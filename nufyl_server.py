import socket
import struct
import threading
import subprocess
import base64
import os
import shlex
import sys

# cryptography library: RSA for sending the session key, AES for the file data
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding


# Every RFMP packet is the fields joined with "|", e.g. SS|RFMP|v1.0|1
# TCP is a stream, so we put a 4 byte length in front of each packet
# so the other side knows where the packet ends.
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
            # other side closed the connection
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
    # return the fields as a list, e.g. ["CM", "prompt", "ls"]
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


def make_path(current_folder, name):
    # turn a name the client sent into a full path inside the client's current folder
    return os.path.abspath(os.path.join(current_folder, name))


def run_prompt(command_text, current_folder):
    # Runs one prompt command, e.g. "mkdir folder1".
    # Returns (folder, message). Only cd changes the folder.
    # Errors are raised and turned into EE packets in handle_client.

    # shlex handles quotes, so "my folder" counts as one argument
    parts = shlex.split(command_text)
    if not parts:
        raise ValueError("Empty command")

    command = parts[0].lower()
    arguments = parts[1:]

    # mkdir <folder>
    if command == "mkdir" and len(arguments) == 1:
        os.mkdir(make_path(current_folder, arguments[0]))
        return current_folder, "folder created"

    # cd <folder>: we don't call os.chdir() because that would change the
    # folder for every thread. Each client keeps its own current_folder.
    if command == "cd" and len(arguments) == 1:
        new_folder = make_path(current_folder, arguments[0])
        if not os.path.isdir(new_folder):
            raise FileNotFoundError("Folder does not exist")
        return new_folder, "current folder changed"

    # rmdir / rd <folder> (folder has to be empty)
    if command in ("rmdir", "rd") and len(arguments) == 1:
        folder = make_path(current_folder, arguments[0])
        os.rmdir(folder)
        return current_folder, "folder removed"

    # del <file>
    if command == "del" and len(arguments) == 1:
        os.remove(make_path(current_folder, arguments[0]))
        return current_folder, "file deleted"

    # ren <old name> <new name>, works for files and folders
    if command == "ren" and len(arguments) == 2:
        old_name = make_path(current_folder, arguments[0])
        new_name = make_path(current_folder, arguments[1])
        os.rename(old_name, new_name)
        return current_folder, "file or folder renamed"

    # ---- our 5 extra commands: ls, pwd, whoami, hostname, date ----

    # ls / dir: list what's in the current folder
    if command in ("ls", "dir") and len(arguments) == 0:
        names = os.listdir(current_folder)
        return current_folder, "\n".join(names) if names else "(empty folder)"

    # pwd: show the client's current folder
    if command == "pwd" and len(arguments) == 0:
        return current_folder, current_folder

    # whoami, hostname, date are run as real system commands
    if command in ("whoami", "hostname", "date") and len(arguments) == 0:
        system_command = [command]
        # on Windows "date" asks for a new date, "date /t" just prints it
        if os.name == "nt" and command == "date":
            system_command = ["cmd", "/c", "date", "/t"]

        # capture the output so we can send it back, timeout so it can't hang
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
    # Runs in its own thread for each client: setup, operation, then closing.
    print(f"[+] {addr} connected")
    # each client starts in the folder the server was started from
    current_folder = os.getcwd()

    try:
        # ---------- Setup phase ----------
        # first packet must be the Start packet: SS|RFMP|v1.0|0 or 1
        packet = recv_packet(conn)
        valid_start = (
            packet is not None
            and len(packet) == 4
            and packet[0] == "SS"
            and packet[1] == "RFMP"
            and packet[2] == "v1.0"
            and packet[3] in ("0", "1")
        )
        if not valid_start:
            send_packet(conn, "EE", "1", "invalid Start packet")
            return

        # last field: 1 = secured, 0 = not secured
        secure = packet[3] == "1"
        cipher_name = None
        session_key = None

        if secure:
            # make the server's RSA key pair for this client
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # public key as PEM text so we can send it
            public_key = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            # CC|server_public_key (base64 so the PEM newlines don't cause problems)
            send_packet(conn, "CC", base64.b64encode(public_key).decode("ascii"))

            # Encryption packet: EC|algorithm|encrypted session key|username:client_public_key
            packet = recv_packet(conn)
            if packet is None or len(packet) != 4 or packet[0] != "EC":
                send_packet(conn, "EE", "1", "expected Encryption packet")
                return

            cipher_name = packet[1]
            if cipher_name not in ("AES", "Caesar"):
                send_packet(conn, "EE", "4", "invalid encryption algorithm")
                return

            # credentials field is "username:client_public_key"
            username, client_public_key_text = packet[3].split(":", 1)

            # the client encrypted the session key with our public key,
            # so only our private key can decrypt it
            raw_key = private_key.decrypt(
                base64.b64decode(packet[2]),
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # AES key is 32 raw bytes, Caesar key is the shift number sent as text
            if cipher_name == "AES":
                session_key = raw_key
            else:
                session_key = int(raw_key.decode("utf-8"))

            # tell the client the key exchange worked. If anything above
            # failed, the except at the bottom sends EE 4 instead.
            send_packet(conn, "SC", "secure session ready")
        else:
            # not secured: CC packet with just one field
            send_packet(conn, "CC")

        # helpers for the DP text field: use the session key if secured,
        # otherwise just pass the text through
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

        # ---------- Operation phase ----------
        # file name from the last openWrite, waiting for its DP packet
        pending_write_file = None

        while True:
            packet = recv_packet(conn)
            if packet is None:
                # client disconnected without sending End
                break

            # ---------- Closing phase ----------
            # End packet: client is done, stop and close the connection
            if packet == ["End"]:
                break

            packet_type = packet[0]

            try:
                # Command packet: CM|command_type|arguments
                if packet_type == "CM":
                    if len(packet) < 3:
                        send_packet(conn, "EE", "1", "invalid Command packet")
                        continue

                    # after openWrite the next packet has to be the DP
                    if pending_write_file is not None:
                        send_packet(conn, "EE", "1", "send DP to finish openWrite")
                        continue

                    command_type = packet[1]
                    # join back in case the argument itself had a "|" in it
                    argument = "|".join(packet[2:])

                    # CM|prompt|<command>: run it and send the output in SC
                    if command_type == "prompt":
                        current_folder, result = run_prompt(argument, current_folder)
                        send_packet(conn, "SC", result)

                    # CM|openRead|<file>: send the file in a DP (encrypted if
                    # secured), then SC
                    elif command_type == "openRead":
                        filename = make_path(current_folder, argument)
                        if not os.path.isfile(filename):
                            send_packet(conn, "EE", "3", "file not found: " + argument)
                            continue

                        with open(filename, "r", encoding="utf-8") as file:
                            content = file.read()
                        send_packet(conn, "DP", encrypt(content))
                        send_packet(conn, "SC", "openRead complete")

                    # CM|openWrite|<file>: create the file now and remember it,
                    # the content comes in the next DP packet
                    elif command_type == "openWrite":
                        filename = make_path(current_folder, argument)
                        with open(filename, "w", encoding="utf-8"):
                            pass
                        pending_write_file = filename
                        send_packet(conn, "SC", "ready to receive data")

                    else:
                        send_packet(conn, "EE", "2", "unknown command: " + command_type)

                # Data packet: DP|text, decrypt it and write it to the openWrite file
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

            # turn errors into EE packets instead of crashing the thread
            # 3 = file/folder error, 2 = bad command, 4 = anything else
            except (OSError, PermissionError) as error:
                send_packet(conn, "EE", "3", str(error))
            except (ValueError, UnicodeError) as error:
                send_packet(conn, "EE", "2", str(error))
            except Exception as error:
                send_packet(conn, "EE", "4", str(error))

    except Exception as error:
        # error during setup : try to tell the client
        try:
            send_packet(conn, "EE", "4", str(error))
        except OSError:
            pass
    finally:
        conn.close()
        print(f"[-] {addr} disconnected")


def main(host="0.0.0.0", port=5000):
    # TCP socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # lets us restart the server right away without "address already in use"
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    # up to 5 connections can wait in the queue
    server_sock.listen(5)
    print(f"RFMP server listening on {host}:{port}")

    try:
        while True:
            conn, addr = server_sock.accept()
            # new thread for every client so several clients can connect at
            # the same time. daemon=True so the threads stop when the server stops
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        # Ctrl+C stops the server
        print("\nServer stopped")
    finally:
        server_sock.close()


if __name__ == "__main__":
    # optional arguments: python3 nufyl_server.py [host] [port]
    selected_host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    selected_port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    main(selected_host, selected_port)
