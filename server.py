

import socket
import struct
import threading
import subprocess
import base64
import os

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


# ---------- one client connection ----------

def handle_client(conn, addr):
    print(f"[+] {addr} connected")

    # ---- Setup Phase ----
    packet = recv_packet(conn)             # (SS, RFMP, v1.0, 0|1)
    secure = packet[3] == "1"
    cipher_name = None
    session_key = None

    if secure:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        send_packet(conn, "CC", base64.b64encode(pub_pem).decode())

        packet = recv_packet(conn)         # (EC, Algorithm, enc_session_key, credentials)
        cipher_name = packet[1]
        session_key = private_key.decrypt(
            base64.b64decode(packet[2]),
            rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        if cipher_name == "Caesar":
            session_key = int(session_key.decode())
    else:
        send_packet(conn, "CC")

    def decrypt(text):
        if not secure:
            return text
        return aes_decrypt(session_key, text) if cipher_name == "AES" else caesar(text, -session_key)

    def encrypt(text):
        if not secure:
            return text
        return aes_encrypt(session_key, text) if cipher_name == "AES" else caesar(text, session_key)

    # ---- Operation Phase + Closing Phase ----
    pending_write_file = None
    while True:
        packet = recv_packet(conn)
        if packet is None or packet[0] == "End":
            break

        ptype = packet[0]
        try:
            if ptype == "CM":
                cmd_type, arg = packet[1], "|".join(packet[2:])

                if cmd_type == "prompt":
                    result = subprocess.run(arg, shell=True, capture_output=True, text=True, timeout=15)
                    send_packet(conn, "SC", (result.stdout or result.stderr or "OK").strip())

                elif cmd_type == "openRead":
                    if not os.path.isfile(arg):
                        send_packet(conn, "EE", "2", "file not found: " + arg)
                    else:
                        content = open(arg, "r", encoding="utf-8").read()
                        send_packet(conn, "DP", encrypt(content))
                        send_packet(conn, "SC", "openRead complete")

                elif cmd_type == "openWrite":
                    pending_write_file = arg
                    send_packet(conn, "SC", "ready to receive data")

                else:
                    send_packet(conn, "EE", "1", "unknown command: " + cmd_type)

            elif ptype == "DP":
                if pending_write_file is None:
                    send_packet(conn, "EE", "3", "no openWrite pending")
                else:
                    open(pending_write_file, "w", encoding="utf-8").write(decrypt(packet[1]))
                    send_packet(conn, "SC", "file written")
                    pending_write_file = None

            else:
                send_packet(conn, "EE", "1", "unknown packet type: " + ptype)

        except Exception as e:
            send_packet(conn, "EE", "4", str(e))

    conn.close()
    print(f"[-] {addr} disconnected")


def main(host="0.0.0.0", port=5000):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)
    print(f"RFMP server listening on {host}:{port}")

    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    import sys
    h = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    p = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    main(h, p)