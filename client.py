import socket
import sys
import threading


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
BUFFER_SIZE = 4096


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


def receive_line(sock, buffer):
    while b"\n" not in buffer:
        data = sock.recv(BUFFER_SIZE)
        if not data:
            return None, buffer
        buffer += data

    raw_line, buffer = buffer.split(b"\n", 1)
    return raw_line.rstrip(b"\r"), buffer


def receive_messages(sock, stop_event, initial_buffer=b""):
    buffer = initial_buffer

    try:
        while not stop_event.is_set():
            raw_message, buffer = receive_line(sock, buffer)
            if raw_message is None:
                print("Connexion fermee par le serveur.")
                stop_event.set()
                break

            message = raw_message.decode("utf-8", errors="replace")
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

    print(f"Username accepte: {username}")

    stop_event = threading.Event()

    receiver = threading.Thread(
        target=receive_messages,
        args=(sock, stop_event, buffer),
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
                sock.sendall((message + "\n").encode("utf-8"))
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
    try:
        host, port = parse_args(sys.argv)
    except ValueError as error:
        print(error)
        sys.exit(1)

    run_client(host, port)


if __name__ == "__main__":
    main()
