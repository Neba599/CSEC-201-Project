

import socket
import struct
import base64
import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding




def send_packet(conn, *fields):
    payload = "|".join(fields).encode()
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def recv_packet(conn):
    header = conn.recv(4)
    if len(header) < 4:
        return None
    length = struct.unpack("!I", header)[0]
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode().split("|")




def caesar(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            ch = chr((ord(ch) - base + shift) % 26 + base)
        result += ch
    return result


def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    padder = aes_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return base64.b64encode(iv + enc.update(padded) + enc.finalize()).decode()


def aes_decrypt(key, blob_b64):
    raw = base64.b64decode(blob_b64)
    iv, ciphertext = raw[:16], raw[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = aes_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()




host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
sock = socket.create_connection((host, port))

# ---- Setup Phase ----
secure = input("Use encryption? (y/n): ").strip().lower() == "y"
send_packet(sock, "SS", "RFMP", "v1.0", "1" if secure else "0")
packet = recv_packet(sock)                 # (CC) or (CC, server_public_key)

cipher_name = None
session_key = None

if secure:
    cipher_name = "AES" if input("Cipher (AES/Caesar): ").strip().lower() == "aes" else "Caesar"

    # AES key = 32 random bytes; Caesar key = a shift number sent as text
    if cipher_name == "AES":
        session_key = os.urandom(32)
        raw_key = session_key
    else:
        session_key = 3
        raw_key = b"3"

    # Lock the session key with the server's public key so only the server can read it
    server_public_key = serialization.load_pem_public_key(base64.b64decode(packet[1]))
    encrypted_key = server_public_key.encrypt(
        raw_key,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    # Our own public key goes in the same packet, as the spec asks
    my_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    my_pub_pem = my_private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send_packet(sock, "EC", cipher_name, base64.b64encode(encrypted_key).decode(),
                base64.b64encode(my_pub_pem).decode())


def encrypt(text):
    if not secure:
        return text
    return aes_encrypt(session_key, text) if cipher_name == "AES" else caesar(text, session_key)


def decrypt(text):
    if not secure:
        return text
    return aes_decrypt(session_key, text) if cipher_name == "AES" else caesar(text, -session_key)


def read_reply():
    """Print the server's answer. A DP (file data) may come before the SC/EE."""
    packet = recv_packet(sock)
    if packet[0] == "DP":
        print(decrypt(packet[1]))
        packet = recv_packet(sock)
    print(packet[0], "|".join(packet[1:]))


# ---- Operation Phase ----
while True:
    line = input("rfmp> ").strip()

    if line == "exit":
        send_packet(sock, "End")           # ---- Closing Phase ----
        break

    elif line.startswith("openRead "):
        send_packet(sock, "CM", "openRead", line.split(" ", 1)[1])
        read_reply()

    elif line.startswith("openWrite "):
        send_packet(sock, "CM", "openWrite", line.split(" ", 1)[1])
        read_reply()
        send_packet(sock, "DP", encrypt(input("content: ")))
        read_reply()

    elif line:
        send_packet(sock, "CM", "prompt", line)
        read_reply()

sock.close()