import ctypes
import socket
import sys
import threading
import base64
import binascii
import hashlib
import hmac
import os
from crypto_utils import (
    decrypt_transport_message,
    encrypt_transport_message,
)
from asymmetric_utils import (
    decrypt_with_private_key,
    encrypt_with_public_key,
    generate_rsa_private_key,
    load_private_key,
    private_key_to_pem,
    public_key_to_pem,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
BUFFER_SIZE = 4096
USER_STORAGE_DIR = "users"
IDENTITY_KEY_BASENAME = "identity"
PEERS_DIRNAME = "peers"
PAIR_SESSION_KEY_BYTES = 16


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


def send_secure_line(sock, transport_key, message):
    payload = encrypt_transport_message(message, transport_key)
    sock.sendall((f"ENCMSG {payload}\n").encode("utf-8"))


def receive_secure_line(sock, buffer, transport_key):
    raw_message, buffer = receive_line(sock, buffer)
    if raw_message is None:
        print("Connexion fermee par le serveur.")
        return None, buffer

    message = raw_message.decode("utf-8", errors="replace")
    if not message.startswith("ENCMSG "):
        print(f"Reponse inattendue du serveur: {message}")
        return None, buffer

    try:
        return decrypt_transport_message(
            message[len("ENCMSG "):],
            transport_key,
        ), buffer
    except (ValueError, binascii.Error, UnicodeDecodeError):
        print("Impossible de dechiffrer une reponse du serveur.")
        return None, buffer


def parse_scrypt_cost(cost):
    values = {}
    for item in cost.split(","):
        key, raw_value = item.split("=", 1)
        values[key] = int(raw_value)
    return values["n"], values["r"], values["p"]


def read_console_line(prompt):
    print(prompt, end="", flush=True)
    try:
        return sys.stdin.readline()
    except OSError:
        return ""


def encode_username_component(username):
    return base64.urlsafe_b64encode(username.encode("utf-8")).decode("ascii")


def decode_username_component(encoded_username):
    return base64.urlsafe_b64decode(encoded_username.encode("ascii")).decode("utf-8")


def get_user_storage_directory(username):
    return os.path.join(USER_STORAGE_DIR, encode_username_component(username))


def get_peer_keys_directory(username):
    return os.path.join(get_user_storage_directory(username), PEERS_DIRNAME)


def load_known_public_keys(username):
    peer_directory = get_peer_keys_directory(username)
    known_public_keys = {}
    if not os.path.isdir(peer_directory):
        return known_public_keys

    for entry in os.listdir(peer_directory):
        if not entry.endswith(".pub"):
            continue

        encoded_username = entry[:-4]
        try:
            peer_username = decode_username_component(encoded_username)
            with open(os.path.join(peer_directory, entry), "r", encoding="utf-8") as public_key_file:
                known_public_keys[peer_username] = public_key_file.read()
        except (OSError, ValueError, binascii.Error, UnicodeDecodeError):
            continue

    return known_public_keys


def upsert_known_public_key(owner_username, known_public_keys, peer_username, public_key_pem):
    if peer_username == owner_username:
        return

    peer_directory = get_peer_keys_directory(owner_username)
    os.makedirs(peer_directory, exist_ok=True)
    peer_filename = f"{encode_username_component(peer_username)}.pub"
    peer_path = os.path.join(peer_directory, peer_filename)

    with open(peer_path, "w", encoding="utf-8") as public_key_file:
        public_key_file.write(public_key_pem)

    known_public_keys[peer_username] = public_key_pem


def decode_pubdir_payload(payload):
    encoded_username, encoded_public_key = payload.split(" ", 1)
    peer_username = decode_username_component(encoded_username)
    public_key_pem = base64.b64decode(
        encoded_public_key.encode("ascii"),
        validate=True,
    ).decode("utf-8")
    return peer_username, public_key_pem


def handle_protocol_message(
    username,
    message,
    known_public_keys,
    active_public_keys,
    pair_session_keys,
    pending_directory,
):
    if message == "PUBDIR_BEGIN":
        pending_directory.clear()
        return True

    if message == "PUBDIR_END":
        previous_active_keys = dict(active_public_keys)
        active_public_keys.clear()
        for peer_username, public_key_pem in pending_directory.items():
            active_public_keys[peer_username] = public_key_pem
            upsert_known_public_key(username, known_public_keys, peer_username, public_key_pem)

        for peer_username in set(previous_active_keys) | set(active_public_keys):
            if previous_active_keys.get(peer_username) != active_public_keys.get(peer_username):
                pair_session_keys.pop(peer_username, None)

        pending_directory.clear()
        return True

    if message.startswith("PUBDIR_ENTRY "):
        peer_username, public_key_pem = decode_pubdir_payload(message[len("PUBDIR_ENTRY "):])
        pending_directory[peer_username] = public_key_pem
        return True

    if message.startswith("PUBDIR_ADD "):
        peer_username, public_key_pem = decode_pubdir_payload(message[len("PUBDIR_ADD "):])
        if active_public_keys.get(peer_username) != public_key_pem:
            pair_session_keys.pop(peer_username, None)
        active_public_keys[peer_username] = public_key_pem
        upsert_known_public_key(username, known_public_keys, peer_username, public_key_pem)
        return True

    if message.startswith("PUBDIR_REMOVE "):
        peer_username = decode_username_component(message[len("PUBDIR_REMOVE "):])
        active_public_keys.pop(peer_username, None)
        pair_session_keys.pop(peer_username, None)
        return True

    return False


def handle_private_protocol_message(
    message,
    private_key_pem,
    pair_session_keys,
):
    if message.startswith("E2EE_KEY_FROM "):
        encoded_username, encrypted_key_b64 = message[len("E2EE_KEY_FROM "):].split(" ", 1)
        peer_username = decode_username_component(encoded_username)
        encrypted_key = base64.b64decode(encrypted_key_b64.encode("ascii"), validate=True)
        pair_session_keys[peer_username] = decrypt_with_private_key(private_key_pem, encrypted_key)
        return True, None

    if message.startswith("E2EE_MSG_FROM "):
        encoded_username, encrypted_payload = message[len("E2EE_MSG_FROM "):].split(" ", 1)
        peer_username = decode_username_component(encoded_username)
        pair_session_key = pair_session_keys.get(peer_username)
        if pair_session_key is None:
            return True, f"[client] Cle de session privee absente pour {peer_username}."

        try:
            plaintext = decrypt_transport_message(encrypted_payload, pair_session_key)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return True, f"[client] Message prive illisible de {peer_username}."

        return True, f"[private] {peer_username}: {plaintext}"

    return False, None


def receive_messages(
    sock,
    stop_event,
    transport_key,
    username,
    private_key_pem,
    known_public_keys,
    active_public_keys,
    known_keys_lock,
    pair_session_keys,
    pair_keys_lock,
    initial_buffer=b"",
):
    buffer = initial_buffer
    pending_directory = {}

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
                except (ValueError, binascii.Error, UnicodeDecodeError):
                    message = "[client] Impossible de dechiffrer le message."

            try:
                with known_keys_lock, pair_keys_lock:
                    if handle_protocol_message(
                        username,
                        message,
                        known_public_keys,
                        active_public_keys,
                        pair_session_keys,
                        pending_directory,
                    ):
                        continue
            except (ValueError, binascii.Error, UnicodeDecodeError):
                message = "[client] Annuaire de cles publiques invalide."

            try:
                with pair_keys_lock:
                    handled, rendered_message = handle_private_protocol_message(
                        message,
                        private_key_pem,
                        pair_session_keys,
                    )
                if handled:
                    if rendered_message is not None:
                        print(rendered_message, flush=True)
                    continue
            except (ValueError, binascii.Error, UnicodeDecodeError):
                message = "[client] Message prive invalide."

            print(message, flush=True)
    except OSError:
        if not stop_event.is_set():
            print("Connexion interrompue.")
            stop_event.set()


def ensure_identity_key_pair(username):
    user_directory = get_user_storage_directory(username)
    os.makedirs(user_directory, exist_ok=True)
    private_key_path = os.path.join(user_directory, f"{IDENTITY_KEY_BASENAME}.priv")
    public_key_path = os.path.join(user_directory, f"{IDENTITY_KEY_BASENAME}.pub")

    if os.path.exists(private_key_path):
        try:
            with open(private_key_path, "rb") as private_key_file:
                private_key_pem = private_key_file.read()
            private_key = load_private_key(private_key_pem)
            public_key_pem = public_key_to_pem(private_key.public_key())

            with open(public_key_path, "wb") as public_key_file:
                public_key_file.write(public_key_pem)

            return private_key_pem, public_key_pem
        except (OSError, ValueError, TypeError):
            pass

    private_key = generate_rsa_private_key()
    private_key_pem = private_key_to_pem(private_key)
    public_key_pem = public_key_to_pem(private_key.public_key())

    with open(private_key_path, "wb") as private_key_file:
        private_key_file.write(private_key_pem)

    with open(public_key_path, "wb") as public_key_file:
        public_key_file.write(public_key_pem)

    return private_key_pem, public_key_pem


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


def negotiate_key_exchange_mode(sock, buffer):
    raw_mode, buffer = receive_line(sock, buffer)
    if raw_mode is None:
        print("Connexion fermee par le serveur.")
        return None, None, buffer

    response = raw_mode.decode("utf-8", errors="replace")
    if response == "KEYX_MODE REGISTER":
        return {"auth_mode": "REGISTER", "nonce": None, "verifier_key": None}, None, buffer

    if not response.startswith("KEYX_MODE LOGIN "):
        print(f"Reponse inattendue du serveur: {response}")
        return None, None, buffer

    password_line = read_console_line("Password: ")
    if password_line == "":
        return None, None, buffer

    password = password_line.rstrip("\r\n")
    parts = response.split()
    try:
        if len(parts) == 4 and parts[2] == "legacy_md5":
            nonce = base64.b64decode(parts[3].encode("ascii"), validate=True)
            verifier_key = hashlib.md5(password.encode("utf-8")).digest()
        elif len(parts) == 6 and parts[2] == "scrypt":
            _, _, _, cost, salt_b64, nonce_b64 = parts
            nonce = base64.b64decode(nonce_b64.encode("ascii"), validate=True)
            salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
            n_value, r_value, p_value = parse_scrypt_cost(cost)
            verifier_key = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=n_value,
                r=r_value,
                p=p_value,
            )
        else:
            print(f"Reponse inattendue du serveur: {response}")
            return None, None, buffer
    except (ValueError, binascii.Error):
        print("Reponse de negotiation de cle invalide.")
        return None, None, buffer

    return {
        "auth_mode": "LOGIN",
        "nonce": nonce,
        "verifier_key": verifier_key,
    }, password, buffer


def authenticate_password(sock, buffer, transport_key, initial_password=None):
    auth_mode_response, buffer = receive_secure_line(sock, buffer, transport_key)
    if auth_mode_response is None:
        return False, None, buffer

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
            if initial_password is None:
                line = read_console_line("Password: ")
                if line == "":
                    return False, None, buffer
                password = line.rstrip("\r\n")
            else:
                password = initial_password
                initial_password = None

            try:
                send_secure_line(sock, transport_key, password)
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
                send_secure_line(sock, transport_key, password)
                send_secure_line(sock, transport_key, confirmation)
            except OSError:
                print("Impossible d'envoyer le mot de passe: connexion fermee.")
                return False, None, buffer

        response, buffer = receive_secure_line(sock, buffer, transport_key)
        if response is None:
            return False, None, buffer

        if response == "AUTH_ACCEPTED":
            return True, password, buffer

        if response.startswith("AUTH_INFO "):
            print(response[len("AUTH_INFO "):])
            response, buffer = receive_secure_line(sock, buffer, transport_key)
            if response is None:
                return False, None, buffer
            if response == "AUTH_ACCEPTED":
                return True, password, buffer

        if response.startswith("AUTH_RETRY "):
            print(response[len("AUTH_RETRY "):])
            continue

        print(f"Reponse inattendue du serveur: {response}")
        return False, None, buffer


def establish_session_key(sock, buffer, public_key_pem, private_key_pem, proof_context=None):
    try:
        public_key_b64 = base64.b64encode(public_key_pem).decode("ascii")
        if proof_context is None or proof_context["verifier_key"] is None:
            sock.sendall((f"KEYX_PUB {public_key_b64}\n").encode("utf-8"))
        else:
            proof = hmac.digest(
                proof_context["verifier_key"],
                public_key_pem + proof_context["nonce"],
                hashlib.sha256,
            )
            proof_b64 = base64.b64encode(proof).decode("ascii")
            sock.sendall((f"KEYX_PUB {public_key_b64} {proof_b64}\n").encode("utf-8"))
    except OSError:
        print("Impossible d'envoyer la cle publique.")
        return None, buffer

    raw_response, buffer = receive_line(sock, buffer)
    if raw_response is None:
        print("Connexion fermee par le serveur.")
        return None, buffer

    response = raw_response.decode("utf-8", errors="replace")
    if response.startswith("KEYX_REJECTED "):
        print(response[len("KEYX_REJECTED "):])
        return "retry", None, buffer

    if not response.startswith("SESSION_KEY "):
        print(f"Reponse inattendue du serveur: {response}")
        return "failed", None, buffer

    try:
        encrypted_session_key = base64.b64decode(
            response[len("SESSION_KEY "):].encode("ascii"),
            validate=True,
        )
        return "ok", decrypt_with_private_key(private_key_pem, encrypted_session_key), buffer
    except (ValueError, binascii.Error, UnicodeEncodeError):
        print("Impossible de dechiffrer la cle de session.")
        return "failed", None, buffer


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

    private_key_pem, public_key_pem = ensure_identity_key_pair(username)
    while True:
        key_exchange_context, login_password, buffer = negotiate_key_exchange_mode(sock, buffer)
        if key_exchange_context is None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
            return

        key_status, transport_key, buffer = establish_session_key(
            sock,
            buffer,
            public_key_pem,
            private_key_pem,
            key_exchange_context,
        )
        if key_status == "retry":
            continue
        if key_status != "ok":
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
            return
        break

    authenticated, _, buffer = authenticate_password(
        sock,
        buffer,
        transport_key,
        initial_password=login_password,
    )
    if not authenticated:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
        return

    print(f"Username accepte: {username}")
    print("Authentification reussie.")
    print("Commandes: /create nom_room [motdepasse], /join nom_room [motdepasse], /room, /pubkey username, /dm username message")

    stop_event = threading.Event()
    known_public_keys = load_known_public_keys(username)
    active_public_keys = {}
    known_keys_lock = threading.Lock()
    pair_session_keys = {}
    pair_keys_lock = threading.Lock()

    receiver = threading.Thread(
        target=receive_messages,
        args=(
            sock,
            stop_event,
            transport_key,
            username,
            private_key_pem,
            known_public_keys,
            active_public_keys,
            known_keys_lock,
            pair_session_keys,
            pair_keys_lock,
            buffer,
        ),
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

            if message == "/pubkey" or message.startswith("/pubkey "):
                peer_username = message[len("/pubkey"):].strip()
                if not peer_username:
                    print("Usage: /pubkey username")
                    continue

                with known_keys_lock:
                    public_key_pem = known_public_keys.get(peer_username)

                if public_key_pem is None:
                    print(f"[client] Cle publique inconnue pour {peer_username}.")
                else:
                    print(public_key_pem, flush=True)
                continue

            if message.startswith("/dm "):
                parts = message.split(" ", 2)
                if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
                    print("Usage: /dm username message")
                    continue

                peer_username = parts[1].strip()
                private_message = parts[2].strip()

                with known_keys_lock:
                    peer_public_key = known_public_keys.get(peer_username)

                if peer_public_key is None:
                    print(f"[client] Cle publique inconnue pour {peer_username}.")
                    continue

                with pair_keys_lock:
                    pair_session_key = pair_session_keys.get(peer_username)
                    encrypted_pair_key = None
                    if pair_session_key is None:
                        pair_session_key = os.urandom(PAIR_SESSION_KEY_BYTES)
                        encrypted_pair_key = base64.b64encode(
                            encrypt_with_public_key(
                                peer_public_key.encode("utf-8"),
                                pair_session_key,
                            )
                        ).decode("ascii")
                        pair_session_keys[peer_username] = pair_session_key

                    encrypted_private_message = encrypt_transport_message(
                        private_message,
                        pair_session_key,
                    )

                encoded_peer_username = encode_username_component(peer_username)

                try:
                    if encrypted_pair_key is not None:
                        send_secure_line(
                            sock,
                            transport_key,
                            f"E2EE_KEY {encoded_peer_username} {encrypted_pair_key}",
                        )

                    send_secure_line(
                        sock,
                        transport_key,
                        f"E2EE_MSG {encoded_peer_username} {encrypted_private_message}",
                    )
                except OSError:
                    print("Impossible d'envoyer le message: connexion fermee.")
                    stop_event.set()
                continue

            try:
                send_secure_line(sock, transport_key, message)
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
