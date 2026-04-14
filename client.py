import ctypes
import socket
import sys
import threading
import base64
import os
from crypto_utils import (
    build_transport_key_record_from_metadata,
    decrypt_transport_message,
    encrypt_transport_message,
    parse_transport_key_metadata,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
BUFFER_SIZE = 4096
USER_STORAGE_DIR = "users"


def parse_args(argv):
    if len(argv) > 3:
        raise ValueError("Usage: python client.py [host] [port]")

    host = argv[1] if len(argv) >= 2 else DEFAULT_HOST

    if len(argv) == 3:
        try:
            port = int(argv[2])
        except ValueError as exc:
            raise ValueError("Le port doit etre un entier.") from exc
    else:
        port = DEFAULT_PORT

    if not 1 <= port <= 65535:
        raise ValueError("Le port doit etre compris entre 1 et 65535.")

    return host, port


def enable_ansi_colors():
    if sys.platform != "win32":
        return

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle in (0, -1):
            return

        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def receive_line(sock, buffer):
    while b"\n" not in buffer:
        data = sock.recv(BUFFER_SIZE)
        if not data:
            return None, buffer
        buffer += data

    raw_line, buffer = buffer.split(b"\n", 1)
    return raw_line.rstrip(b"\r"), buffer


def receive_messages(sock, stop_event, transport_key, initial_buffer=b""):
    buffer = initial_buffer

    try:
        while not stop_event.is_set():
            raw_message, buffer = receive_line(sock, buffer)
            if raw_message is None:
                print("Connexion fermee par le serveur.")
                stop_event.set()
                break

            message = raw_message.decode("utf-8", errors="replace")
            if message.startswith("ENCMSG "):
                try:
                    message = decrypt_transport_message(
                        message[len("ENCMSG "):],
                        transport_key,
                    )
                except ValueError:
                    message = "[client] Impossible de dechiffrer le message."
            print(message, flush=True)
    except OSError:
        if not stop_event.is_set():
            print("Connexion interrompue.")
            stop_event.set()


def read_console_line(prompt):
    print(prompt, end="", flush=True)
    try:
        return sys.stdin.readline()
    except OSError:
        return ""


def get_user_storage_directory(username):
    safe_username = base64.urlsafe_b64encode(username.encode("utf-8")).decode("ascii")
    return os.path.join(USER_STORAGE_DIR, safe_username)


def save_transport_key_record(username, serialized_record):
    user_directory = get_user_storage_directory(username)
    os.makedirs(user_directory, exist_ok=True)
    key_path = os.path.join(user_directory, "key.txt")
    with open(key_path, "w", encoding="utf-8") as key_file:
        key_file.write(serialized_record + "\n")


def negotiate_username(sock):
    buffer = b""

    while True:
        line = read_console_line("Username: ")
        if line == "":
            return None, buffer

        proposed_username = line.rstrip("\r\n")

        try:
            sock.sendall((proposed_username + "\n").encode("utf-8"))
        except OSError:
            print("Impossible d'envoyer le username: connexion fermee.")
            return None, buffer

        raw_response, buffer = receive_line(sock, buffer)
        if raw_response is None:
            print("Connexion fermee par le serveur.")
            return None, buffer

        response = raw_response.decode("utf-8", errors="replace")
        if response == "USERNAME_ACCEPTED":
            return proposed_username.strip(), buffer

        if response.startswith("USERNAME_REJECTED "):
            print(response[len("USERNAME_REJECTED "):])
            continue

        print(f"Reponse inattendue du serveur: {response}")
        return None, buffer


def authenticate_password(sock, buffer):
    raw_mode, buffer = receive_line(sock, buffer)
    if raw_mode is None:
        print("Connexion fermee par le serveur.")
        return False, None, buffer

    auth_mode_response = raw_mode.decode("utf-8", errors="replace")
    if auth_mode_response == "AUTH_MODE LOGIN":
        auth_mode = "LOGIN"
    elif auth_mode_response == "AUTH_MODE REGISTER":
        auth_mode = "REGISTER"
        print("Nouveau compte detecte. Creation du mot de passe.")
    else:
        print(f"Reponse inattendue du serveur: {auth_mode_response}")
        return False, None, buffer

    while True:
        if auth_mode == "LOGIN":
            line = read_console_line("Password: ")
            if line == "":
                return False, None, buffer

            password = line.rstrip("\r\n")

            try:
                sock.sendall((password + "\n").encode("utf-8"))
            except OSError:
                print("Impossible d'envoyer le mot de passe: connexion fermee.")
                return False, None, buffer
        else:
            password_line = read_console_line("New password: ")
            if password_line == "":
                return False, None, buffer

            confirmation_line = read_console_line("Confirm password: ")
            if confirmation_line == "":
                return False, None, buffer

            password = password_line.rstrip("\r\n")
            confirmation = confirmation_line.rstrip("\r\n")

            try:
                sock.sendall((password + "\n").encode("utf-8"))
                sock.sendall((confirmation + "\n").encode("utf-8"))
            except OSError:
                print("Impossible d'envoyer le mot de passe: connexion fermee.")
                return False, None, buffer

        raw_response, buffer = receive_line(sock, buffer)
        if raw_response is None:
            print("Connexion fermee par le serveur.")
            return False, None, buffer

        response = raw_response.decode("utf-8", errors="replace")
        if response == "AUTH_ACCEPTED":
            return True, password, buffer

        if response.startswith("AUTH_INFO "):
            print(response[len("AUTH_INFO "):])
            raw_response, buffer = receive_line(sock, buffer)
            if raw_response is None:
                print("Connexion fermee par le serveur.")
                return False, None, buffer
            response = raw_response.decode("utf-8", errors="replace")
            if response == "AUTH_ACCEPTED":
                return True, password, buffer

        if response.startswith("AUTH_RETRY "):
            print(response[len("AUTH_RETRY "):])
            continue

        print(f"Reponse inattendue du serveur: {response}")
        return False, None, buffer


def ensure_transport_key(sock, buffer, username, password):
    raw_response, buffer = receive_line(sock, buffer)
    if raw_response is None:
        print("Connexion fermee par le serveur.")
        return None, buffer

    response = raw_response.decode("utf-8", errors="replace")
    if not response.startswith("KEY_INFO "):
        print(f"Reponse inattendue du serveur: {response}")
        return None, buffer

    metadata = parse_transport_key_metadata(response[len("KEY_INFO "):])
    record = build_transport_key_record_from_metadata(
        password,
        metadata["algorithm"],
        metadata["cost"],
        metadata["salt"],
    )
    save_transport_key_record(
        username,
        f"{record['algorithm']}:{record['cost']}:{record['salt']}:{record['key']}",
    )
    return base64.b64decode(record["key"].encode("ascii")), buffer


def run_client(host, port):
    try:
        sock = socket.create_connection((host, port))
    except OSError as error:
        print(f"Connexion impossible a {host}:{port} ({error})")
        return

    print(f"Connecte a {host}:{port}")

    username, buffer = negotiate_username(sock)
    if username is None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        return

    authenticated, auth_password, buffer = authenticate_password(sock, buffer)
    if not authenticated:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        return

    transport_key, buffer = ensure_transport_key(
        sock,
        buffer,
        username,
        auth_password,
    )
    if transport_key is None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        return

    print(f"Username accepte: {username}")
    print("Authentification reussie.")
    print("Commandes: /create nom_room [motdepasse], /join nom_room [motdepasse], /room")

    stop_event = threading.Event()

    receiver = threading.Thread(
        target=receive_messages,
        args=(sock, stop_event, transport_key, buffer),
        daemon=True,
    )

    receiver.start()

    try:
        while not stop_event.is_set():
            try:
                line = sys.stdin.readline()
            except OSError:
                stop_event.set()
                break

            if line == "":
                break

            message = line.rstrip("\r\n")
            if not message:
                continue

            try:
                if message.startswith("/"):
                    payload = message
                else:
                    encrypted_message = encrypt_transport_message(message, transport_key)
                    payload = f"ENCMSG {encrypted_message}"

                sock.sendall((payload + "\n").encode("utf-8"))
            except OSError:
                print("Impossible d'envoyer le message: connexion fermee.")
                stop_event.set()
    except KeyboardInterrupt:
        print("\nFermeture du client.")
    finally:
        stop_event.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


def main():
    enable_ansi_colors()

    try:
        host, port = parse_args(sys.argv)
    except ValueError as error:
        print(error)
        sys.exit(1)

    run_client(host, port)


if __name__ == "__main__":
    main()
