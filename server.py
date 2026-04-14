import socket
import sys
import threading


DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
BUFFER_SIZE = 4096

clients = set()
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
        clients.discard(client_socket)

    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    try:
        client_socket.close()
    except OSError:
        pass


def broadcast(message, excluded_socket=None):
    with clients_lock:
        recipients = [client for client in clients if client is not excluded_socket]

    failed_clients = []
    for client_socket in recipients:
        try:
            client_socket.sendall(message)
        except OSError:
            failed_clients.append(client_socket)

    for client_socket in failed_clients:
        remove_client(client_socket)


def handle_client(client_socket, client_address):
    print(f"Client connecte: {client_address[0]}:{client_address[1]}")
    buffer = b""

    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break

            buffer += data
            while b"\n" in buffer:
                raw_message, buffer = buffer.split(b"\n", 1)
                message = raw_message.rstrip(b"\r")
                if message:
                    broadcast(message + b"\n", excluded_socket=client_socket)
    except OSError:
        pass
    finally:
        remove_client(client_socket)
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
                clients.add(client_socket)

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
            open_clients = list(clients)
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
