import socket
import struct
import base64
import os
import sys

# cryptography library: RSA for sending the session key, AES for the file data
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding


# Same packet format as the server: fields joined with "|" and a
# 4 byte length in front, so we know where each packet ends on the TCP stream.
def send_packet(conn, *fields):
    payload = "|".join(fields).encode("utf-8")
    # "!I" = 4 byte unsigned int in network byte order (big endian)
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exact(conn, amount):
    # recv() can return less than we asked for, so keep reading
    # until we have exactly `amount` bytes
    data = b""
    while len(data) < amount:
        chunk = conn.recv(amount - len(data))
        if not chunk:
            # server closed the connection
            return None
        data += chunk
    return data


def recv_packet(conn):
    # read the 4 byte length first, then the packet itself
    header = recv_exact(conn, 4)
    if header is None:
        return None

    length = struct.unpack("!I", header)[0]
    data = recv_exact(conn, length)
    if data is None:
        return None
    # return the fields as a list, e.g. ["SC", "folder created"]
    return data.decode("utf-8").split("|")


def caesar(text, shift):
    # shift letters by `shift` places and wrap around with % 26
    # a negative shift decrypts
    result = ""
    for ch in text:
        if "A" <= ch <= "Z":
            result += chr((ord(ch) - ord("A") + shift) % 26 + ord("A"))
        elif "a" <= ch <= "z":
            result += chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
        else:
            # numbers, spaces and symbols stay the same
            result += ch
    return result


def aes_encrypt(key, plaintext):
    # new random IV every time so the same text never encrypts the same way twice
    iv = os.urandom(16)
    # AES works on 16 byte blocks, PKCS7 pads the text to fit
    padder = aes_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    # send IV + ciphertext together, base64 so it can go inside a text packet
    return base64.b64encode(iv + ciphertext).decode("ascii")


def aes_decrypt(key, encrypted_text):
    raw = base64.b64decode(encrypted_text)
    # needs at least the 16 byte IV + one block, and whole blocks only
    if len(raw) < 32 or len(raw) % 16 != 0:
        raise ValueError("Invalid AES data")

    # first 16 bytes are the IV, the rest is the encrypted data
    iv = raw[:16]
    ciphertext = raw[16:]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # remove the padding added in aes_encrypt
    unpadder = aes_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def print_status(packet):
    # Shows the server's reply. Returns True for SC, False for anything else,
    # so the caller knows if the command worked.
    if packet is None:
        print("The server disconnected.")
        return False

    # SC|message: command worked
    if packet[0] == "SC":
        print("SC", "|".join(packet[1:]))
        return True

    # EE|error code|description: something went wrong on the server
    if packet[0] == "EE":
        code = packet[1] if len(packet) > 1 else "?"
        description = "|".join(packet[2:])
        print("EE", code, description)
        return False

    print("Unexpected packet:", packet)
    return False


def main():
    # optional arguments: python3 nufyl_client.py [host] [port]
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    sock = socket.create_connection((host, port))

    try:
        # ---------- Setup phase ----------
        secure = input("Use encryption? (y/n): ").strip().lower() == "y"
        cipher_name = None
        session_key = None
        my_public_key_text = None

        if secure:
            # anything other than "aes" falls back to Caesar
            choice = input("Cipher (AES/Caesar): ").strip().lower()
            cipher_name = "AES" if choice == "aes" else "Caesar"

            # make the session key. raw_key is the bytes version we encrypt with RSA
            if cipher_name == "AES":
                # 32 random bytes = AES-256 key
                session_key = os.urandom(32)
                raw_key = session_key
            else:
                # Caesar key is just the shift amount
                session_key = 3
                raw_key = str(session_key).encode("utf-8")

            # the client's own RSA key pair. The spec says to send our public
            # key in the EC packet as part of the credentials
            my_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            my_public_key = my_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            # base64 so the PEM newlines don't cause problems in the packet
            my_public_key_text = base64.b64encode(my_public_key).decode("ascii")

        # Start packet: SS|RFMP|v1.0|1 for secured, 0 for not secured
        send_packet(sock, "SS", "RFMP", "v1.0", "1" if secure else "0")
        packet = recv_packet(sock)

        # server rejected the Start packet or hung up
        if packet is None or packet[0] == "EE":
            print_status(packet)
            return

        if not secure:
            # not secured: server sends just CC
            if packet != ["CC"]:
                print("Invalid confirmation packet from server")
                return
        else:
            # secured: server sends CC|server_public_key
            if len(packet) != 2 or packet[0] != "CC":
                print("Invalid secure confirmation packet from server")
                return

            server_public_key = serialization.load_pem_public_key(
                base64.b64decode(packet[1])
            )
            # encrypt the session key with the server's public key,
            # only the server's private key can decrypt it
            encrypted_key = server_public_key.encrypt(
                raw_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # username only fills the credentials field, it is not a password
            username = input("Username: ").strip() or "student"
            credentials = username + ":" + my_public_key_text
            # Encryption packet: EC|algorithm|encrypted session key|username:client_public_key
            send_packet(
                sock,
                "EC",
                cipher_name,
                base64.b64encode(encrypted_key).decode("ascii"),
                credentials,
            )

        # helpers for the DP text field: use the session key if secured,
        # otherwise just pass the text through
        def encrypt(text):
            if not secure:
                return text
            if cipher_name == "AES":
                return aes_encrypt(session_key, text)
            return caesar(text, session_key)

        def decrypt(text):
            if not secure:
                return text
            if cipher_name == "AES":
                return aes_decrypt(session_key, text)
            return caesar(text, -session_key)

        def read_reply(expect_file_data=False):
            # Reads the server's reply to one command.
            # For openRead the server sends DP (file contents) first, then SC.
            packet = recv_packet(sock)
            if packet is None:
                print("The server disconnected.")
                return False

            if packet[0] == "DP":
                # we only expect a DP back from openRead
                if not expect_file_data:
                    print("Unexpected DP packet")
                    return False

                # join back in case the file itself had a "|" in it
                file_data = "|".join(packet[1:])
                print("--- File contents ---")
                print(decrypt(file_data))
                print("--- End of file ---")
                # now read the SC/EE that comes after the DP
                packet = recv_packet(sock)

            return print_status(packet)

        # ---------- Operation phase ----------
        print("Commands: mkdir, cd, rmdir/rd, del, ren, ls, pwd, whoami, hostname, date")
        print("File commands: openRead filename, openWrite filename")
        print("Type exit to close the connection.")

        while True:
            line = input("rfmp> ").strip()

            # ---------- Closing phase ----------
            # send End so the server knows we're done, then close
            if line == "exit":
                send_packet(sock, "End")
                break

            # openRead <file>: CM|openRead|<file>, server replies DP then SC
            if line.startswith("openRead "):
                filename = line.split(" ", 1)[1]
                send_packet(sock, "CM", "openRead", filename)
                read_reply(expect_file_data=True)

            # openWrite <file>: CM|openWrite|<file>, and if the server says
            # SC we send the content in a DP packet (encrypted if secured)
            elif line.startswith("openWrite "):
                filename = line.split(" ", 1)[1]
                send_packet(sock, "CM", "openWrite", filename)

                if read_reply():
                    content = input("content: ")
                    send_packet(sock, "DP", encrypt(content))
                    read_reply()

            # anything else is sent as a prompt command, e.g. CM|prompt|mkdir folder1
            elif line:
                send_packet(sock, "CM", "prompt", line)
                read_reply()

    except (OSError, ValueError) as error:
        print("Connection error:", error)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
