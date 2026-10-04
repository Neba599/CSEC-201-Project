import socket
import struct
import threading
import subprocess
import base64
import os
import shlex
import sys

# Cryptographic primitives for asymmetric (RSA) key exchange and symmetric encryption
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding


def send_packet(conn, *fields):
    # Concatenate all packet fields with a pipe delimiter and convert to UTF-8 bytes
    payload = "|".join(fields).encode("utf-8")
    # Pack the payload length into a 4-byte big-endian integer header and transmit complete packet
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exact(conn, amount):
    """Receive exactly the requested number of bytes."""
    data = b""
    # Accumulate data chunks until the exact specified byte count is received
    while len(data) < amount:
        chunk = conn.recv(amount - len(data))
        # Return None if the socket connection was closed prematurely
        if not chunk:
            return None
        data += chunk
    return data


def recv_packet(conn):
    # Read the 4-byte length prefix header
    header = recv_exact(conn, 4)
    if header is None:
        return None
# Unpack the 4-byte big-endian header into an integer payload size
    length = struct.unpack("!I", header)[0]
    # Retrieve the exact payload byte stream
    data = recv_exact(conn, length)
    if data is None:
        return None
    # Decode byte sequence to UTF-8 text and split by pipe delimiter
    return data.decode("utf-8").split("|")


def caesar(text, shift):
    result = ""
    for ch in text:
        # Shift uppercase alphabetic characters within ASCII range
        if "A" <= ch <= "Z":
            result += chr((ord(ch) - ord("A") + shift) % 26 + ord("A"))
            # Shift lowercase alphabetic characters within ASCII range
        elif "a" <= ch <= "z":
            result += chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
            # Preserve non-alphabetic characters without modification
        else:
            result += ch
    return result


def aes_encrypt(key, plaintext):
    # Generate a cryptographically secure random 16-byte initialization vector (IV)
    iv = os.urandom(16)
    # Apply PKCS7 padding to pad plaintext to 128-bit block size boundaries
    padder = aes_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    # Encrypt the padded byte payload using AES-CBC mode
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    # Prepend IV to ciphertext and return Base64 ASCII string
    return base64.b64encode(iv + ciphertext).decode("ascii")


def aes_decrypt(key, encrypted_text):
    # Decode Base64 string to original raw byte sequence
    raw = base64.b64decode(encrypted_text)
    # Validate minimum block length requirements (IV + at least 1 AES block)
    if len(raw) < 32 or len(raw) % 16 != 0:
        raise ValueError("Invalid AES data")
    # Extract IV (first 16 bytes) and ciphertext body
    iv = raw[:16]
    ciphertext = raw[16:]
    # Decrypt byte payload using AES cipher in CBC mode
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove PKCS7 padding bytes from decrypted payload
    unpadder = aes_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def make_path(current_folder, name):
    """Constructs a fully resolved absolute path within the current target folder."""
    return os.path.abspath(os.path.join(current_folder, name))


def run_prompt(command_text, current_folder):
    """Parses and executes a command string within the specified working directory context."""
    # Split input command string using shell parsing rules
    parts = shlex.split(command_text)
    if not parts:
        raise ValueError("Empty command")

    command = parts[0].lower()
    arguments = parts[1:]
    # Directory creation command: mkdir <folder>
    if command == "mkdir" and len(arguments) == 1:
        os.mkdir(make_path(current_folder, arguments[0]))
        return current_folder, "folder created"
    # Working directory navigation command: cd <folder>
    if command == "cd" and len(arguments) == 1:
        new_folder = make_path(current_folder, arguments[0])
        if not os.path.isdir(new_folder):
            raise FileNotFoundError("Folder does not exist")
        return new_folder, "current folder changed"
    # Directory removal command: rmdir/rd <folder>
    if command in ("rmdir", "rd") and len(arguments) == 1:
        folder = make_path(current_folder, arguments[0])
        os.rmdir(folder)
        return current_folder, "folder removed"
    # File deletion command: del <file>
    if command == "del" and len(arguments) == 1:
        os.remove(make_path(current_folder, arguments[0]))
        return current_folder, "file deleted"
    # Rename file or directory command: ren <old> <new>
    if command == "ren" and len(arguments) == 2:
        old_name = make_path(current_folder, arguments[0])
        new_name = make_path(current_folder, arguments[1])
        os.rename(old_name, new_name)
        return current_folder, "file or folder renamed"

    # Five additional prompt commands.
    if command in ("ls", "dir") and len(arguments) == 0:
        names = os.listdir(current_folder)
        return current_folder, "\n".join(names) if names else "(empty folder)"
    # Print working directory command: pwd
    if command == "pwd" and len(arguments) == 0:
        return current_folder, current_folder
    # System command execution: whoami, hostname, date
    if command in ("whoami", "hostname", "date") and len(arguments) == 0:
        system_command = [command]
        # Adjust date command parameters for Windows shell environment
        if os.name == "nt" and command == "date":
            system_command = ["cmd", "/c", "date", "/t"]
    # Run system subprocess and capture stdout/stderr output
        result = subprocess.run(
            system_command,
            cwd=current_folder,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Command failed")
        return current_folder, result.stdout.strip()

    raise ValueError("Unknown command or wrong number of arguments")


def handle_client(conn, addr):
    print(f"[+] {addr} connected")
    current_folder = os.getcwd()

    try:
        # ---------- Setup phase ----------
        packet = recv_packet(conn)
        valid_start = (
            packet is not None
            and len(packet) == 4
            and packet[0] == "SS"
            and packet[1] == "RFMP"
            and packet[2] == "v1.0"
            and packet[3] in ("0", "1")
        )
        # Validate initial protocol parameters
        if not valid_start:
            send_packet(conn, "EE", "1", "invalid Start packet")
            return

        secure = packet[3] == "1"
        cipher_name = None
        session_key = None

        if secure:
            # Generate temporary server RSA 2048-bit key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # Serialize server public key to PEM format
            public_key = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            # Send server public key packet (CC) base64 encoded
            send_packet(conn, "CC", base64.b64encode(public_key).decode("ascii"))

# Receive Encryption packet (EC): algorithm, RSA-encrypted session key, username:client_public_key            packet = recv_packet(conn)
            if packet is None or len(packet) != 4 or packet[0] != "EC":
                send_packet(conn, "EE", "1", "expected Encryption packet")
                return

            cipher_name = packet[1]
            if cipher_name not in ("AES", "Caesar"):
                send_packet(conn, "EE", "4", "invalid encryption algorithm")
                return
    # Extract user credentials and client public key
            username, client_public_key_text = packet[3].split(":", 1)
    # Decrypt symmetrical session key sent by client using server RSA private key
            raw_key = private_key.decrypt(
                base64.b64decode(packet[2]),
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
    # Configure session key variable based on negotiated symmetric cipher
            if cipher_name == "AES":
                session_key = raw_key
            else:
                session_key = int(raw_key.decode("utf-8"))
        else:
            # Send unencrypted session confirmation packet (CC)
            send_packet(conn, "CC")

        def decrypt(text):
            if not secure:
                return text
            if cipher_name == "AES":
                return aes_decrypt(session_key, text)
            return caesar(text, -session_key)

        def encrypt(text):
            if not secure:
                return text
            if cipher_name == "AES":
                return aes_encrypt(session_key, text)
            return caesar(text, session_key)

        pending_write_file = None
        # Main command processing loop
        while True:
            packet = recv_packet(conn)
            if packet is None:
                break
        # Exit connection loop on End packet
            if packet == ["End"]:
                break

            packet_type = packet[0]
        # Command execution packet (CM)
            try:
                if packet_type == "CM":
                    if len(packet) < 3:
                        send_packet(conn, "EE", "1", "invalid Command packet")
                        continue
                    # Reject command if openWrite file upload step is pending data payload
                    if pending_write_file is not None:
                        send_packet(conn, "EE", "1", "send DP to finish openWrite")
                        continue

                    command_type = packet[1]
                    argument = "|".join(packet[2:])
                    # Execute prompt command and return status result
                    if command_type == "prompt":
                        current_folder, result = run_prompt(argument, current_folder)
                        send_packet(conn, "SC", result)
                    # Read file content from filesystem and send encrypted payload to client
                    elif command_type == "openRead":
                        filename = make_path(current_folder, argument)
                        if not os.path.isfile(filename):
                            send_packet(conn, "EE", "3", "file not found: " + argument)
                            continue

                        with open(filename, "r", encoding="utf-8") as file:
                            content = file.read()
                        send_packet(conn, "DP", encrypt(content))
                        send_packet(conn, "SC", "openRead complete")

                    elif command_type == "openWrite":
                        filename = make_path(current_folder, argument)
                        with open(filename, "w", encoding="utf-8"):
                            pass
                        pending_write_file = filename
                        send_packet(conn, "SC", "ready to receive data")

                    else:
                        send_packet(conn, "EE", "2", "unknown command: " + command_type)

                elif packet_type == "DP":
                    if pending_write_file is None:
                        send_packet(conn, "EE", "1", "no openWrite pending")
                        continue

                    file_data = "|".join(packet[1:])
                    content = decrypt(file_data)
                    with open(pending_write_file, "w", encoding="utf-8") as file:
                        file.write(content)

                    pending_write_file = None
                    send_packet(conn, "SC", "file written")

                else:
                    send_packet(conn, "EE", "1", "unknown packet type: " + packet_type)

            except (OSError, PermissionError) as error:
                send_packet(conn, "EE", "3", str(error))
            except (ValueError, UnicodeError) as error:
                send_packet(conn, "EE", "2", str(error))
            except Exception as error:
                send_packet(conn, "EE", "4", str(error))

    except Exception as error:
        try:
            send_packet(conn, "EE", "4", str(error))
        except OSError:
            pass
    finally:
        conn.close()
        print(f"[-] {addr} disconnected")


def main(host="0.0.0.0", port=5000):
    # Create IPv4 TCP socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow socket address reuse on restart
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind socket to interface address and port
    server_sock.bind((host, port))
    # Listen for incoming client connections with a backlog queue of 5
    server_sock.listen(5)
    print(f"RFMP server listening on {host}:{port}")

    try:
        while True:
            conn, addr = server_sock.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("\nServer stopped")
    finally:
        server_sock.close()


if __name__ == "__main__":
    selected_host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    selected_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    main(selected_host, selected_port)
