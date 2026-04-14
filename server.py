import socket
import sys
import threading


DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
BUFFER_SIZE = 4096

clients = {}
clients_lock = threading.Lock()


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


def remove_client(client_socket):
    with clients_lock:
        username = clients.pop(client_socket, None)

    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    try:
        client_socket.close()
    except OSError:
        pass

    return username


def broadcast(message, excluded_socket=None):
    with clients_lock:
        recipients = [
            client_socket
            for client_socket, username in clients.items()
            if username is not None and client_socket is not excluded_socket
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
    with clients_lock:
        if any(current_username == username for current_username in clients.values() if current_username is not None):
            return False

        clients[client_socket] = username
        return True


def negotiate_username(client_socket):
    buffer = b""

    while True:
        raw_username, buffer = receive_line(client_socket, buffer)
        if raw_username is None:
            return None, buffer

        username = raw_username.decode("utf-8", errors="replace").strip()

        if not username:
            client_socket.sendall(b"USERNAME_REJECTED Username vide.\n")
            continue

        if not try_register_username(client_socket, username):
            client_socket.sendall(b"USERNAME_REJECTED Username deja utilise.\n")
            continue

        client_socket.sendall(b"USERNAME_ACCEPTED\n")
        return username, buffer


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
            if message:
                formatted_message = f"{username}: {message}\n".encode("utf-8")
                broadcast(formatted_message, excluded_socket=client_socket)
    except OSError:
        pass
    finally:
        released_username = remove_client(client_socket)
        if released_username is not None:
            print(f"Client deconnecte: {released_username} ({client_address[0]}:{client_address[1]})")
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
            with clients_lock:
                clients[client_socket] = None

            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("\nArret du serveur.")
    finally:
        with clients_lock:
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
