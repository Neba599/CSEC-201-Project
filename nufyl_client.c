
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#define close closesocket
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define BUFFER_SIZE 65536

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

int send_packet(int sock, char payload[]) {
    int len = strlen(payload);
    unsigned int header = htonl(len);   
    if (send_all(sock, (char *)&header, 4) < 0) {
        return -1;
    }
    return send_all(sock, payload, len);
}


int recv_packet(int sock, char packet[], int max_size) {
    unsigned int header;
    int len;

    if (recv_exact(sock, (char *)&header, 4) < 0) {
        return -1;
    }
    len = ntohl(header);                
    if (len < 0 || len >= max_size) {
        return -1;                    
    }
    if (recv_exact(sock, packet, len) < 0) {
        return -1;
    }
    packet[len] = '\0';           
    return len;
}

void print_status(char packet[]) {
    int i;

    if (strncmp(packet, "SC|", 3) == 0) {
        printf("SC %s\n", packet + 3);
    } else if (strncmp(packet, "EE|", 3) == 0) {
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
    char *host = "127.0.0.1";
    int port = 5000;
    int sock;
    struct sockaddr_in server;
    char reply[BUFFER_SIZE];
    char line[1024];
    char request[1100];
    int i;

#ifdef _WIN32
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

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Could not create socket\n");
        return 1;
    }
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Could not connect to %s:%d\n", host, port);
        close(sock);
        return 1;
    }

    if (send_packet(sock, "SS|RFMP|v1.0|0") < 0) {
        printf("Failed to send Start packet\n");
        close(sock);
        return 1;
    }

    if (recv_packet(sock, reply, BUFFER_SIZE) < 0) {
        printf("The server disconnected.\n");
        close(sock);
        return 1;
    }
    if (strcmp(reply, "CC") != 0) {
        print_status(reply);         
        close(sock);
        return 1;
    }
    printf("Connected (non-secured).\n");

    printf("Type a filename to read it from the server, or exit to quit.\n");
    while (1) {
        printf("rfmp-c> ");
        fflush(stdout);
        if (fgets(line, sizeof(line), stdin) == NULL) {
            break;
        }

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

        strcpy(request, "CM|openRead|");
        strcat(request, line);
        if (send_packet(sock, request) < 0) {
            printf("Failed to send request\n");
            break;
        }

        if (recv_packet(sock, reply, BUFFER_SIZE) < 0) {
            printf("The server disconnected.\n");
            break;
        }
        if (strncmp(reply, "DP|", 3) == 0) {
            printf("--- File contents ---\n%s\n--- End of file ---\n", reply + 3);
            if (recv_packet(sock, reply, BUFFER_SIZE) < 0) {
                printf("The server disconnected.\n");
                break;
            }
        }
        print_status(reply);
    }

    send_packet(sock, "End");
    close(sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
