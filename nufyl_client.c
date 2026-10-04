/*
 * RFMP C client (non-secured)
 * Only supports openRead: asks for a file name, the server sends back
 * the file contents. No RSA, AES or Caesar in this version.
 *
 * Compile: gcc -Wall -Wextra nufyl_client.c -o nufyl_client
 * Run:     ./nufyl_client [host] [port]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Windows uses winsock, Linux/macOS use the normal socket headers */
#ifdef _WIN32
#include <winsock2.h>
#define close closesocket
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* biggest packet we can receive (64 KB) */
#define BUFFER_SIZE 65536

/* send() might not send everything in one go, so loop until all
   len bytes are sent. Returns 0 if ok, -1 on error. */
int send_all(int sock, char data[], int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(sock, data + sent, len - sent, 0);
        if (n <= 0) {
            return -1;
        }
        sent = sent + n;
    }
    return 0;
}


/* same idea for recv(): keep reading until we have exactly len bytes.
   Returns -1 if the server closes the connection first. */
int recv_exact(int sock, char data[], int len) {
    int got = 0;
    while (got < len) {
        int n = recv(sock, data + got, len - got, 0);
        if (n <= 0) {
            return -1;
        }
        got = got + n;
    }
    return 0;
}

/* Sends one RFMP packet: 4 byte length, then the text (e.g. "CM|openRead|a.txt").
   Same format as the Python server's send_packet(). */
int send_packet(int sock, char payload[]) {
    int len = strlen(payload);
    /* htonl = convert to network byte order (big endian), matches "!I" in Python */
    unsigned int header = htonl(len);
    if (send_all(sock, (char *)&header, 4) < 0) {
        return -1;
    }
    return send_all(sock, payload, len);
}


/* Receives one packet into packet[] and adds '\0' so we can use it as a string.
   Returns the length, or -1 on error. */
int recv_packet(int sock, char packet[], int max_size) {
    unsigned int header;
    int len;

    if (recv_exact(sock, (char *)&header, 4) < 0) {
        return -1;
    }
    /* ntohl = convert the length back from network byte order */
    len = ntohl(header);
    /* don't read more than the buffer can hold (need 1 byte for '\0') */
    if (len < 0 || len >= max_size) {
        return -1;
    }
    if (recv_exact(sock, packet, len) < 0) {
        return -1;
    }
    packet[len] = '\0';
    return len;
}

/* Prints SC or EE replies.
   SC|message -> "SC message"
   EE|code|description -> "EE code description" */
void print_status(char packet[]) {
    int i;

    if (strncmp(packet, "SC|", 3) == 0) {
        printf("SC %s\n", packet + 3);
    } else if (strncmp(packet, "EE|", 3) == 0) {
        /* swap the "|" between code and description for a space */
        for (i = 3; packet[i] != '\0'; i++) {
            if (packet[i] == '|') {
                packet[i] = ' ';
                break;
            }
        }
        printf("EE %s\n", packet + 3);
    } else {
        printf("Unexpected packet: %s\n", packet);
    }
}

int main(int argc, char *argv[]) {
    /* defaults if no host/port are given */
    char *host = "127.0.0.1";
    int port = 5000;
    int sock;
    struct sockaddr_in server;
    char reply[BUFFER_SIZE];
    char line[1024];
    /* room for "CM|openRead|" + the file name */
    char request[1100];
    int i;

#ifdef _WIN32
    /* winsock has to be started before using sockets on Windows */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
#endif

    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }

    /* TCP socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Could not create socket\n");
        return 1;
    }
    /* fill in the server address (IPv4, port in network byte order) */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Could not connect to %s:%d\n", host, port);
        close(sock);
        return 1;
    }

    /* ---------- Setup phase ---------- */
    /* Start packet with 0 at the end = no encryption */
    if (send_packet(sock, "SS|RFMP|v1.0|0") < 0) {
        printf("Failed to send Start packet\n");
        close(sock);
        return 1;
    }

    /* server should answer with just "CC" */
    if (recv_packet(sock, reply, BUFFER_SIZE) < 0) {
        printf("The server disconnected.\n");
        close(sock);
        return 1;
    }
    if (strcmp(reply, "CC") != 0) {
        /* probably an EE packet, show it and quit */
        print_status(reply);
        close(sock);
        return 1;
    }
    printf("Connected (non-secured).\n");

    /* ---------- Operation phase ---------- */
    printf("Type a filename to read it from the server, or exit to quit.\n");
    while (1) {
        printf("rfmp-c> ");
        /* make sure the prompt shows before fgets waits for input */
        fflush(stdout);
        if (fgets(line, sizeof(line), stdin) == NULL) {
            break;
        }

        /* fgets keeps the newline, remove it */
        for (i = 0; line[i] != '\0'; i++) {
            if (line[i] == '\n') {
                line[i] = '\0';
                break;
            }
        }

        if (line[0] == '\0') {
            continue;
        }
        if (strcmp(line, "exit") == 0) {
            break;
        }

        /* build CM|openRead|<file name> */
        strcpy(request, "CM|openRead|");
        strcat(request, line);
        if (send_packet(sock, request) < 0) {
            printf("Failed to send request\n");
            break;
        }

        /* if the file exists the server sends DP|contents first, then SC.
           If not, it sends EE straight away. */
        if (recv_packet(sock, reply, BUFFER_SIZE) < 0) {
            printf("The server disconnected.\n");
            break;
        }
        if (strncmp(reply, "DP|", 3) == 0) {
            printf("--- File contents ---\n%s\n--- End of file ---\n", reply + 3);
            /* read the SC that comes after the DP */
            if (recv_packet(sock, reply, BUFFER_SIZE) < 0) {
                printf("The server disconnected.\n");
                break;
            }
        }
        print_status(reply);
    }

    /* ---------- Closing phase ---------- */
    /* tell the server we're done, then close the socket */
    send_packet(sock, "End");
    close(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
