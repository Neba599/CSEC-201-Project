import socket
import struct
import base64
import os
import sys
# Cryptographic primitives for RSA public key encryption and AES symmetric encryption
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding


def send_packet(conn, *fields):
    # Join fields with pipe delimiter and encode to UTF-8 byte stream
    payload = "|".join(fields).encode("utf-8")
    # Send 4-byte big-endian unsigned integer length header followed by binary payload
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exact(conn, amount):
    """Receive exactly the requested number of bytes."""
    data = b""
    # Read network stream until requested byte count is fully collected
    while len(data) < amount:
        chunk = conn.recv(amount - len(data))
        # Return None if the connection drops unexpectedly
        if not chunk:
            return None
        data += chunk
    return data


def recv_packet(conn):
    # Read 4-byte big-endian length header
    header = recv_exact(conn, 4)
    if header is None:
        return None
    # Unpack payload size header integer
    length = struct.unpack("!I", header)[0]
    # Read remaining payload bytes matching decoded length
    data = recv_exact(conn, length)
    if data is None:
        return None
        # Convert payload bytes to UTF-8 string and split into list by pipe separator
    return data.decode("utf-8").split("|")


def caesar(text, shift):
    result = ""
    for ch in text:
        # Shift uppercase alphabetic characters
        if "A" <= ch <= "Z":
            result += chr((ord(ch) - ord("A") + shift) % 26 + ord("A"))
            # Shift lowercase alphabetic characters
        elif "a" <= ch <= "z":
            result += chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
            # Leave special characters/numbers unchanged
        else:
            result += ch
    return result


def aes_encrypt(key, plaintext):
    # Generate random 16-byte initialization vector (IV)
    iv = os.urandom(16)
    # Apply PKCS7 block padding to ensure payload length is a multiple of 128 bits
    padder = aes_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    # Perform AES-CBC encryption using session key and IV
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    # Concatenate IV + ciphertext and convert output to Base64 ASCII string
    return base64.b64encode(iv + ciphertext).decode("ascii")


def aes_decrypt(key, encrypted_text):
    # Decode Base64 string to raw encrypted bytes
    raw = base64.b64decode(encrypted_text)
    # Validate payload minimum size and block alignment
    if len(raw) < 32 or len(raw) % 16 != 0:
        raise ValueError("Invalid AES data")
# Separate initial 16-byte IV from ciphertext body
    iv = raw[:16]
    ciphertext = raw[16:]
    # Perform AES-CBC decryption
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # Strip PKCS7 block padding bytes
    unpadder = aes_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def print_status(packet):
    if packet is None:
        print("The server disconnected.")
        return False
# Handle Status Confirmation packet (SC)
    if packet[0] == "SC":
        print("SC", "|".join(packet[1:]))
        return True
# Handle Error packet (EE)
    if packet[0] == "EE":
        code = packet[1] if len(packet) > 1 else "?"
        description = "|".join(packet[2:])
        print("EE", code, description)
        return False
# Log unhandled packet types
    print("Unexpected packet:", packet)
    return False


def main():
    # Parse target host and port from arguments or default to 127.0.0.1:5000
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
# Establish TCP connection to RFMP server
    sock = socket.create_connection((host, port))

    try:
        # ---------- Setup phase ----------
        secure = input("Use encryption? (y/n): ").strip().lower() == "y"
        cipher_name = None
        session_key = None
        my_public_key_text = None

        if secure:
            choice = input("Cipher (AES/Caesar): ").strip().lower()
            cipher_name = "AES" if choice == "aes" else "Caesar"

            if cipher_name == "AES":
                session_key = os.urandom(32)
                raw_key = session_key
            else:
                session_key = 3
                raw_key = str(session_key).encode("utf-8")

            my_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            my_public_key = my_private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            my_public_key_text = base64.b64encode(my_public_key).decode("ascii")

        send_packet(sock, "SS", "RFMP", "v1.0", "1" if secure else "0")
        packet = recv_packet(sock)

        if packet is None or packet[0] == "EE":
            print_status(packet)
            return

        if not secure:
            if packet != ["CC"]:
                print("Invalid confirmation packet from server")
                return
        else:
            if len(packet) != 2 or packet[0] != "CC":
                print("Invalid secure confirmation packet from server")
                return

            server_public_key = serialization.load_pem_public_key(
                base64.b64decode(packet[1])
            )
            encrypted_key = server_public_key.encrypt(
                raw_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            username = input("Username: ").strip() or "student"
            credentials = username + ":" + my_public_key_text
            send_packet(
                sock,
                "EC",
                cipher_name,
                base64.b64encode(encrypted_key).decode("ascii"),
                credentials,
            )

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
            packet = recv_packet(sock)
            if packet is None:
                print("The server disconnected.")
                return False

            if packet[0] == "DP":
                if not expect_file_data:
                    print("Unexpected DP packet")
                    return False

                file_data = "|".join(packet[1:])
                print("--- File contents ---")
                print(decrypt(file_data))
                print("--- End of file ---")
                packet = recv_packet(sock)

            return print_status(packet)

        print("Commands: mkdir, cd, rmdir/rd, del, ren, ls, pwd, whoami, hostname, date")
        print("File commands: openRead filename, openWrite filename")
        print("Type exit to close the connection.")

        while True:
            line = input("rfmp> ").strip()

            if line == "exit":
                send_packet(sock, "End")
                break

            if line.startswith("openRead "):
                filename = line.split(" ", 1)[1]
                send_packet(sock, "CM", "openRead", filename)
                read_reply(expect_file_data=True)

            elif line.startswith("openWrite "):
                filename = line.split(" ", 1)[1]
                send_packet(sock, "CM", "openWrite", filename)

                if read_reply():
                    content = input("content: ")
                    send_packet(sock, "DP", encrypt(content))
                    read_reply()

            elif line:
                send_packet(sock, "CM", "prompt", line)
                read_reply()

    except (OSError, ValueError) as error:
        print("Connection error:", error)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
