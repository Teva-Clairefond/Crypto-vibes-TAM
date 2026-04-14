import queue
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


def receive_messages(sock, stop_event):
    buffer = b""

    try:
        while not stop_event.is_set():
            data = sock.recv(BUFFER_SIZE)
            if not data:
                print("Connexion fermee par le serveur.")
                stop_event.set()
                break

            buffer += data
            while b"\n" in buffer:
                raw_message, buffer = buffer.split(b"\n", 1)
                message = raw_message.rstrip(b"\r").decode("utf-8", errors="replace")
                print(message, flush=True)
    except OSError:
        if not stop_event.is_set():
            print("Connexion interrompue.")
            stop_event.set()


def read_user_input(input_queue, stop_event):
    while not stop_event.is_set():
        try:
            line = sys.stdin.readline()
        except OSError:
            stop_event.set()
            break

        if line == "":
            stop_event.set()
            break

        input_queue.put(line)


def run_client(host, port):
    try:
        sock = socket.create_connection((host, port))
    except OSError as error:
        print(f"Connexion impossible a {host}:{port} ({error})")
        return

    print(f"Connecte a {host}:{port}")

    stop_event = threading.Event()
    input_queue = queue.Queue()

    receiver = threading.Thread(
        target=receive_messages,
        args=(sock, stop_event),
        daemon=True,
    )
    reader = threading.Thread(
        target=read_user_input,
        args=(input_queue, stop_event),
        daemon=True,
    )

    receiver.start()
    reader.start()

    try:
        while not stop_event.is_set():
            try:
                line = input_queue.get(timeout=0.1)
            except queue.Empty:
                continue

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
