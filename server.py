import socket
import sys
import threading
from datetime import datetime
import hashlib


DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
BUFFER_SIZE = 4096
DEFAULT_ROOM = "general"
ANSI_RESET = "\033[0m"
ANSI_COLORS = [
    "\033[31m",
    "\033[32m",
    "\033[33m",
    "\033[34m",
    "\033[35m",
    "\033[36m",
    "\033[91m",
    "\033[92m",
    "\033[94m",
    "\033[95m",
    "\033[96m",
]

clients = {}
rooms = {DEFAULT_ROOM: None}
state_lock = threading.Lock()


def parse_port(argv):
    if len(argv) > 2:
        raise ValueError("Usage: python server.py [port]")

    if len(argv) == 2:
        try:
            port = int(argv[1])
        except ValueError as exc:
            raise ValueError("Le port doit etre un entier.") from exc
    else:
        port = DEFAULT_PORT

    if not 1 <= port <= 65535:
        raise ValueError("Le port doit etre compris entre 1 et 65535.")

    return port


def send_line(client_socket, message):
    client_socket.sendall((message + "\n").encode("utf-8"))


def get_username_color(username):
    digest = hashlib.sha256(username.encode("utf-8")).digest()
    return ANSI_COLORS[digest[0] % len(ANSI_COLORS)]


def build_chat_message(username, message, color_code):
    timestamp = datetime.now().strftime("%H:%M:%S")
    colored_username = f"{color_code}{username}{ANSI_RESET}"
    return f"[{timestamp}] {colored_username}: {message}\n".encode("utf-8")


def remove_client(client_socket):
    with state_lock:
        client_info = clients.pop(client_socket, None)

    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    try:
        client_socket.close()
    except OSError:
        pass

    return client_info


def broadcast_to_room(message, room_name, excluded_socket=None):
    with state_lock:
        recipients = [
            sock
            for sock, info in clients.items()
            if info["username"] is not None
            and info["room"] == room_name
            and sock is not excluded_socket
        ]

    failed_clients = []
    for client_socket in recipients:
        try:
            client_socket.sendall(message)
        except OSError:
            failed_clients.append(client_socket)

    for client_socket in failed_clients:
        remove_client(client_socket)


def receive_line(client_socket, buffer):
    while b"\n" not in buffer:
        data = client_socket.recv(BUFFER_SIZE)
        if not data:
            return None, buffer
        buffer += data

    raw_line, buffer = buffer.split(b"\n", 1)
    return raw_line.rstrip(b"\r"), buffer


def try_register_username(client_socket, username):
    with state_lock:
        if any(
            info["username"] == username
            for info in clients.values()
            if info["username"] is not None
        ):
            return False

        clients[client_socket]["username"] = username
        clients[client_socket]["room"] = DEFAULT_ROOM
        clients[client_socket]["color"] = get_username_color(username)
        return True


def negotiate_username(client_socket):
    buffer = b""

    while True:
        raw_username, buffer = receive_line(client_socket, buffer)
        if raw_username is None:
            return None, buffer

        username = raw_username.decode("utf-8", errors="replace").strip()

        if not username:
            send_line(client_socket, "USERNAME_REJECTED Username vide.")
            continue

        if not try_register_username(client_socket, username):
            send_line(client_socket, "USERNAME_REJECTED Username deja utilise.")
            continue

        send_line(client_socket, "USERNAME_ACCEPTED")
        send_line(client_socket, f"[server] Vous avez rejoint la room {DEFAULT_ROOM}.")
        return username, buffer


def get_current_room(client_socket):
    with state_lock:
        client_info = clients.get(client_socket)
        if client_info is None:
            return None
        return client_info["room"]


def create_room_and_join(client_socket, room_name, password):
    with state_lock:
        if room_name in rooms:
            return False, "[server] Cette room existe deja."

        rooms[room_name] = password
        clients[client_socket]["room"] = room_name

    if password is None:
        return True, f"[server] Room creee et rejointe: {room_name}."

    return True, f"[server] Room protegee creee et rejointe: {room_name}."


def join_room(client_socket, room_name, password):
    with state_lock:
        if room_name not in rooms:
            return False, "[server] Cette room n'existe pas."

        room_password = rooms[room_name]
        if room_password is not None and password != room_password:
            return False, "[server] Mot de passe incorrect."

        clients[client_socket]["room"] = room_name

    return True, f"[server] Vous avez rejoint la room {room_name}."


def process_command(client_socket, message):
    parts = message.split()
    command = parts[0]

    if command == "/create":
        if len(parts) not in {2, 3}:
            return "[server] Usage: /create nom_room [motdepasse]"

        room_name = parts[1].strip()
        if not room_name:
            return "[server] Le nom de room ne peut pas etre vide."

        password = parts[2] if len(parts) == 3 else None
        _, response = create_room_and_join(client_socket, room_name, password)
        return response

    if command == "/join":
        if len(parts) not in {2, 3}:
            return "[server] Usage: /join nom_room [motdepasse]"

        room_name = parts[1].strip()
        if not room_name:
            return "[server] Le nom de room ne peut pas etre vide."

        password = parts[2] if len(parts) == 3 else None
        _, response = join_room(client_socket, room_name, password)
        return response

    if command == "/room":
        if len(parts) != 1:
            return "[server] Usage: /room"

        room_name = get_current_room(client_socket)
        return f"[server] Room courante: {room_name}"

    return "[server] Commande inconnue."


def handle_client(client_socket, client_address):
    print(f"Client connecte: {client_address[0]}:{client_address[1]}")
    username = None
    buffer = b""

    try:
        username, buffer = negotiate_username(client_socket)
        if username is None:
            return

        print(f"Username accepte: {username} ({client_address[0]}:{client_address[1]})")

        while True:
            raw_message, buffer = receive_line(client_socket, buffer)
            if raw_message is None:
                break

            message = raw_message.decode("utf-8", errors="replace").strip()
            if not message:
                continue

            if message.startswith("/"):
                response = process_command(client_socket, message)
                send_line(client_socket, response)
                continue

            room_name = get_current_room(client_socket)
            if room_name is None:
                break

            formatted_message = build_chat_message(
                username,
                message,
                clients[client_socket]["color"],
            )
            broadcast_to_room(
                formatted_message,
                room_name,
                excluded_socket=client_socket,
            )
    except OSError:
        pass
    finally:
        released_info = remove_client(client_socket)
        if released_info is not None and released_info["username"] is not None:
            print(
                f"Client deconnecte: {released_info['username']} "
                f"({client_address[0]}:{client_address[1]})"
            )
        else:
            print(f"Client deconnecte: {client_address[0]}:{client_address[1]}")


def run_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((DEFAULT_HOST, port))
    server_socket.listen()

    print(f"Serveur en ecoute sur le port {port}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            with state_lock:
                clients[client_socket] = {"username": None, "room": None, "color": None}

            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("\nArret du serveur.")
    finally:
        with state_lock:
            open_clients = list(clients.keys())
            clients.clear()

        for client_socket in open_clients:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client_socket.close()
            except OSError:
                pass

        server_socket.close()


def main():
    try:
        port = parse_port(sys.argv)
    except ValueError as error:
        print(error)
        sys.exit(1)

    run_server(port)


if __name__ == "__main__":
    main()
