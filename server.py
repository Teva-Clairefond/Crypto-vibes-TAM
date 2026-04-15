import socket
import sys
import threading
from datetime import datetime
import hashlib
import json
import base64
import binascii
import hmac
import math
import os
from crypto_utils import (
    decrypt_transport_message,
    encrypt_transport_message,
)
from asymmetric_utils import (
    encrypt_with_public_key,
)


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
LOG_FILENAME_FORMAT = "log_%Y-%m-%d_%H-%M-%S.txt"
PROTECTED_ROOM_MARKER = "[PROTEGEE]"
PASSWORD_STORE_FILE = "this_is_safe.txt"
PASSWORD_RULES_FILE = "password_rules.json"
DEFAULT_PASSWORD_RULES = {
    "min_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
}
PASSWORD_HASH_ALGORITHM = "scrypt"
PASSWORD_HASH_COST = "n=16384,r=8,p=1"
PASSWORD_HASH_N = 16384
PASSWORD_HASH_R = 8
PASSWORD_HASH_P = 1
PASSWORD_SALT_BYTES = 16

clients = {}
rooms = {DEFAULT_ROOM: None}
state_lock = threading.Lock()
log_lock = threading.Lock()
auth_lock = threading.Lock()
log_file = None
log_filename = None
client_threads = []
password_store = {}
password_rules = {}


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


def initialize_log_file():
    global log_file
    global log_filename

    base_filename = datetime.now().strftime(LOG_FILENAME_FORMAT)
    candidate = base_filename
    suffix = 1

    while True:
        try:
            log_file = open(candidate, "x", encoding="utf-8")
            log_filename = candidate
            return log_filename
        except FileExistsError:
            stem, extension = base_filename.rsplit(".", 1)
            candidate = f"{stem}-{suffix}.{extension}"
            suffix += 1


def close_log_file():
    global log_file

    with log_lock:
        if log_file is None:
            return

        log_file.flush()
        log_file.close()
        log_file = None


def write_log(event, **fields):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parts = [f"[{timestamp}]", event]

    for key, value in fields.items():
        if value is not None:
            parts.append(f"{key}={json.dumps(value, ensure_ascii=False)}")

    line = " ".join(parts)

    with log_lock:
        if log_file is None:
            return

        log_file.write(line + "\n")
        log_file.flush()


def format_client_address(client_address):
    return f"{client_address[0]}:{client_address[1]}"


def send_line(client_socket, message):
    client_socket.sendall((message + "\n").encode("utf-8"))


def send_secure_line(client_socket, session_key, message):
    payload = encrypt_transport_message(message, session_key)
    send_line(client_socket, f"ENCMSG {payload}")


def get_username_color(username):
    digest = hashlib.sha256(username.encode("utf-8")).digest()
    return ANSI_COLORS[digest[0] % len(ANSI_COLORS)]


def ensure_password_rules_file():
    if os.path.exists(PASSWORD_RULES_FILE):
        return

    with open(PASSWORD_RULES_FILE, "w", encoding="utf-8") as rules_file:
        json.dump(DEFAULT_PASSWORD_RULES, rules_file, indent=2)


def load_password_rules():
    ensure_password_rules_file()

    with open(PASSWORD_RULES_FILE, "r", encoding="utf-8") as rules_file:
        loaded_rules = json.load(rules_file)

    min_length = loaded_rules.get("min_length", DEFAULT_PASSWORD_RULES["min_length"])
    if not isinstance(min_length, int) or isinstance(min_length, bool) or min_length <= 0:
        raise ValueError("password_rules.json: min_length doit etre un entier strictement positif.")

    validated_rules = {"min_length": min_length}
    for key in ("require_uppercase", "require_lowercase", "require_digit"):
        value = loaded_rules.get(key, DEFAULT_PASSWORD_RULES[key])
        if not isinstance(value, bool):
            raise ValueError(f"password_rules.json: {key} doit etre un booleen JSON.")
        validated_rules[key] = value

    return validated_rules


def ensure_password_store_file():
    if os.path.exists(PASSWORD_STORE_FILE):
        return

    with open(PASSWORD_STORE_FILE, "w", encoding="utf-8"):
        pass


def load_password_store():
    ensure_password_store_file()
    loaded_store = {}

    with open(PASSWORD_STORE_FILE, "r", encoding="utf-8") as store_file:
        for line in store_file:
            line = line.strip()
            if not line:
                continue

            if line.count(":") < 4:
                username, stored_hash = line.rsplit(":", 1)
                loaded_store[username] = {
                    "format": "legacy_md5",
                    "hash": stored_hash,
                }
                continue

            parts = line.rsplit(":", 4)
            if len(parts) == 5:
                username, algorithm, cost, salt_b64, digest_b64 = parts
                loaded_store[username] = {
                    "format": "modern",
                    "algorithm": algorithm,
                    "cost": cost,
                    "salt": salt_b64,
                    "digest": digest_b64,
                }

    return loaded_store


def save_password_store():
    temp_path = f"{PASSWORD_STORE_FILE}.tmp"

    with open(temp_path, "w", encoding="utf-8") as store_file:
        for username in sorted(password_store):
            record = password_store[username]
            if record["format"] == "legacy_md5":
                store_file.write(f"{username}:{record['hash']}\n")
                continue

            store_file.write(
                f"{username}:{record['algorithm']}:{record['cost']}:"
                f"{record['salt']}:{record['digest']}\n"
            )

    os.replace(temp_path, PASSWORD_STORE_FILE)


def hash_password_md5_base64(password):
    digest = hashlib.md5(password.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def build_scrypt_password_record(password):
    salt = os.urandom(PASSWORD_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=PASSWORD_HASH_N,
        r=PASSWORD_HASH_R,
        p=PASSWORD_HASH_P,
    )
    return {
        "format": "modern",
        "algorithm": PASSWORD_HASH_ALGORITHM,
        "cost": PASSWORD_HASH_COST,
        "salt": base64.b64encode(salt).decode("ascii"),
        "digest": base64.b64encode(digest).decode("ascii"),
    }


def verify_legacy_password(password, stored_hash):
    candidate_hash = hash_password_md5_base64(password)
    return hmac.compare_digest(
        candidate_hash.encode("ascii"),
        stored_hash.encode("ascii"),
    )


def parse_scrypt_cost(cost):
    values = {}
    for item in cost.split(","):
        key, raw_value = item.split("=", 1)
        values[key] = int(raw_value)
    return values["n"], values["r"], values["p"]


def verify_password_constant_time(password, stored_record):
    if stored_record["format"] == "legacy_md5":
        return verify_legacy_password(password, stored_record["hash"])

    if stored_record["algorithm"] != PASSWORD_HASH_ALGORITHM:
        return False

    n_value, r_value, p_value = parse_scrypt_cost(stored_record["cost"])
    salt = base64.b64decode(stored_record["salt"].encode("ascii"))
    expected_digest = base64.b64decode(stored_record["digest"].encode("ascii"))
    candidate_digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n_value,
        r=r_value,
        p=p_value,
    )
    return hmac.compare_digest(candidate_digest, expected_digest)


def validate_password_rules(password):
    errors = []

    if len(password) < password_rules["min_length"]:
        errors.append(
            f"Le mot de passe doit contenir au moins {password_rules['min_length']} caracteres."
        )

    if password_rules["require_uppercase"] and not any(char.isupper() for char in password):
        errors.append("Le mot de passe doit contenir au moins une majuscule.")

    if password_rules["require_lowercase"] and not any(char.islower() for char in password):
        errors.append("Le mot de passe doit contenir au moins une minuscule.")

    if password_rules["require_digit"] and not any(char.isdigit() for char in password):
        errors.append("Le mot de passe doit contenir au moins un chiffre.")

    return errors


def estimate_password_entropy(password):
    charset_size = 0
    if any(char.islower() for char in password):
        charset_size += 26
    if any(char.isupper() for char in password):
        charset_size += 26
    if any(char.isdigit() for char in password):
        charset_size += 10
    if any(not char.isalnum() for char in password):
        charset_size += 32

    if charset_size == 0:
        return 0.0

    return len(password) * math.log2(charset_size)


def describe_password_strength(password):
    entropy = estimate_password_entropy(password)
    if entropy < 40:
        label = "faible"
    elif entropy < 60:
        label = "moyenne"
    else:
        label = "forte"

    return f"{label} ({entropy:.1f} bits)"


def get_auth_mode(username):
    with auth_lock:
        if username in password_store:
            return "LOGIN"
        return "REGISTER"


def build_chat_message(username, message, color_code):
    timestamp = datetime.now().strftime("%H:%M:%S")
    colored_username = f"{color_code}{username}{ANSI_RESET}"
    return f"[{timestamp}] {colored_username}: {message}"


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


def get_client_snapshot(client_socket):
    with state_lock:
        client_info = clients.get(client_socket)
        if client_info is None:
            return None

        return client_info.copy()


def is_room_protected(room_name):
    with state_lock:
        if room_name not in rooms:
            return False

        return rooms[room_name] is not None


def format_room_display(room_name):
    if is_room_protected(room_name):
        return f"{room_name} {PROTECTED_ROOM_MARKER}"

    return room_name


def broadcast_to_room(message, room_name, excluded_socket=None):
    with state_lock:
        recipients = [
            sock
            for sock, info in clients.items()
            if info["username"] is not None
            and info["authenticated"]
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


def broadcast_encrypted_message_to_room(message, room_name, excluded_socket=None):
    with state_lock:
        recipients = [
            (sock, info["session_key"])
            for sock, info in clients.items()
            if info["username"] is not None
            and info["authenticated"]
            and info["room"] == room_name
            and info["session_key"] is not None
            and sock is not excluded_socket
        ]

    failed_clients = []
    for recipient_socket, recipient_session_key in recipients:
        try:
            payload = encrypt_transport_message(
                message,
                recipient_session_key,
            )
            send_line(recipient_socket, f"ENCMSG {payload}")
        except (OSError, ValueError):
            failed_clients.append(recipient_socket)

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


def receive_secure_line(client_socket, buffer, session_key):
    raw_line, buffer = receive_line(client_socket, buffer)
    if raw_line is None:
        return None, buffer

    message = raw_line.decode("utf-8", errors="replace")
    if not message.startswith("ENCMSG "):
        raise ValueError("Message non chiffre.")

    return decrypt_transport_message(message[len("ENCMSG "):], session_key), buffer


def try_register_username(client_socket, username):
    with state_lock:
        if any(
            info["username"] == username
            for info in clients.values()
            if info["username"] is not None
        ):
            return False

        clients[client_socket]["username"] = username
        clients[client_socket]["room"] = None
        clients[client_socket]["color"] = get_username_color(username)
        clients[client_socket]["authenticated"] = False
        return True


def mark_client_authenticated(client_socket):
    with state_lock:
        client_info = clients.get(client_socket)
        if client_info is None:
            return None

        client_info["authenticated"] = True
        client_info["room"] = DEFAULT_ROOM
        return client_info.copy()


def negotiate_username(client_socket):
    buffer = b""

    while True:
        raw_username, buffer = receive_line(client_socket, buffer)
        if raw_username is None:
            return None, buffer

        username = raw_username.decode("utf-8", errors="replace").strip()
        client_info = get_client_snapshot(client_socket)
        client_address = None if client_info is None else client_info["address"]

        if not username:
            write_log("USERNAME_REJECTED_EMPTY", client=client_address)
            send_line(client_socket, "USERNAME_REJECTED Username vide.")
            continue

        if not try_register_username(client_socket, username):
            write_log(
                "USERNAME_REJECTED_DUPLICATE",
                client=client_address,
                username=username,
            )
            send_line(client_socket, "USERNAME_REJECTED Username deja utilise.")
            continue

        send_line(client_socket, "USERNAME_ACCEPTED")
        write_log(
            "USERNAME_ACCEPTED",
            client=client_address,
            username=username,
        )
        return username, buffer


def authenticate_known_user(client_socket, buffer, session_key):
    while True:
        try:
            password, buffer = receive_secure_line(client_socket, buffer, session_key)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            send_secure_line(client_socket, session_key, "[server] Message chiffre invalide.")
            continue

        if password is None:
            return False, None, buffer

        password = password.strip()
        client_info = get_client_snapshot(client_socket)
        client_address = None if client_info is None else client_info["address"]
        username = None if client_info is None else client_info["username"]

        with auth_lock:
            stored_record = password_store.get(username)

        if stored_record is None:
            send_secure_line(client_socket, session_key, "AUTH_RETRY Compte introuvable.")
            return False, None, buffer

        if not verify_password_constant_time(password, stored_record):
            write_log(
                "AUTH_REJECTED",
                client=client_address,
                username=username,
            )
            send_secure_line(client_socket, session_key, "AUTH_RETRY Mot de passe incorrect.")
            continue

        if stored_record["format"] == "legacy_md5":
            with auth_lock:
                password_store[username] = build_scrypt_password_record(password)
                save_password_store()
            send_secure_line(
                client_socket,
                session_key,
                "AUTH_INFO Mot de passe migre vers un hash moderne.",
            )
            write_log(
                "PASSWORD_MIGRATED",
                client=client_address,
                username=username,
                algorithm=PASSWORD_HASH_ALGORITHM,
                cost=PASSWORD_HASH_COST,
            )

        authenticated_info = mark_client_authenticated(client_socket)
        if authenticated_info is None:
            return False, None, buffer

        send_secure_line(client_socket, session_key, "AUTH_ACCEPTED")
        write_log(
            "AUTH_ACCEPTED",
            client=authenticated_info["address"],
            username=authenticated_info["username"],
            room=authenticated_info["room"],
        )
        return True, password, buffer


def register_new_user(client_socket, buffer, session_key):
    while True:
        try:
            password, buffer = receive_secure_line(client_socket, buffer, session_key)
            if password is None:
                return False, None, buffer

            confirmation, buffer = receive_secure_line(client_socket, buffer, session_key)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            send_secure_line(client_socket, session_key, "[server] Message chiffre invalide.")
            continue

        if confirmation is None:
            return False, None, buffer

        password = password.strip()
        confirmation = confirmation.strip()
        client_info = get_client_snapshot(client_socket)
        client_address = None if client_info is None else client_info["address"]
        username = None if client_info is None else client_info["username"]

        if password != confirmation:
            write_log(
                "ACCOUNT_REJECTED_CONFIRMATION",
                client=client_address,
                username=username,
            )
            send_secure_line(
                client_socket,
                session_key,
                "AUTH_RETRY Les mots de passe ne correspondent pas.",
            )
            continue

        rule_errors = validate_password_rules(password)
        if rule_errors:
            write_log(
                "ACCOUNT_REJECTED_RULES",
                client=client_address,
                username=username,
            )
            send_secure_line(client_socket, session_key, f"AUTH_RETRY {' '.join(rule_errors)}")
            continue

        stored_record = build_scrypt_password_record(password)
        with auth_lock:
            password_store[username] = stored_record
            save_password_store()

        authenticated_info = mark_client_authenticated(client_socket)
        if authenticated_info is None:
            return False, None, buffer

        password_strength = describe_password_strength(password)
        send_secure_line(
            client_socket,
            session_key,
            f"AUTH_INFO Force du mot de passe: {password_strength}.",
        )
        send_secure_line(client_socket, session_key, "AUTH_ACCEPTED")
        write_log(
            "ACCOUNT_CREATED",
            client=authenticated_info["address"],
            username=authenticated_info["username"],
            algorithm=PASSWORD_HASH_ALGORITHM,
            cost=PASSWORD_HASH_COST,
        )
        write_log(
            "AUTH_ACCEPTED",
            client=authenticated_info["address"],
            username=authenticated_info["username"],
            room=authenticated_info["room"],
        )
        return True, password, buffer


def authenticate_client(client_socket, buffer, session_key):
    client_info = get_client_snapshot(client_socket)
    if client_info is None:
        return False, None, buffer

    auth_mode = get_auth_mode(client_info["username"])
    send_secure_line(client_socket, session_key, f"AUTH_MODE {auth_mode}")

    if auth_mode == "LOGIN":
        return authenticate_known_user(client_socket, buffer, session_key)

    return register_new_user(client_socket, buffer, session_key)


def prepare_key_exchange(client_socket):
    client_info = get_client_snapshot(client_socket)
    if client_info is None:
        return None, None, None

    auth_mode = get_auth_mode(client_info["username"])
    if auth_mode == "REGISTER":
        send_line(client_socket, "KEYX_MODE REGISTER")
        return auth_mode, None, None

    with auth_lock:
        stored_record = password_store.get(client_info["username"])

    if stored_record is None:
        return None, None, None

    nonce = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    if stored_record["format"] == "legacy_md5":
        send_line(client_socket, f"KEYX_MODE LOGIN legacy_md5 {nonce_b64}")
    else:
        send_line(
            client_socket,
            "KEYX_MODE LOGIN "
            f"{stored_record['algorithm']} {stored_record['cost']} {stored_record['salt']} {nonce_b64}",
        )

    return auth_mode, stored_record, nonce


def key_exchange_verifier(stored_record):
    if stored_record["format"] == "legacy_md5":
        return base64.b64decode(stored_record["hash"].encode("ascii"))

    if stored_record["algorithm"] != PASSWORD_HASH_ALGORITHM:
        raise ValueError("Unsupported password algorithm.")

    return base64.b64decode(stored_record["digest"].encode("ascii"))


def establish_session_key(client_socket, buffer, stored_record=None, nonce=None):
    client_info = get_client_snapshot(client_socket)
    if client_info is None:
        return "failed", None, buffer

    raw_public_key, buffer = receive_line(client_socket, buffer)
    if raw_public_key is None:
        return "failed", None, buffer

    message = raw_public_key.decode("utf-8", errors="replace")
    if not message.startswith("KEYX_PUB "):
        send_line(client_socket, "[server] Cle publique attendue.")
        return "failed", None, buffer

    try:
        payload = message[len("KEYX_PUB "):]
        if stored_record is not None:
            public_key_b64, proof_b64 = payload.split(" ", 1)
            received_proof = base64.b64decode(proof_b64.encode("ascii"), validate=True)
        else:
            public_key_b64 = payload
            received_proof = None

        public_key_pem = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
        if stored_record is not None:
            expected_proof = hmac.digest(
                key_exchange_verifier(stored_record),
                public_key_pem + nonce,
                hashlib.sha256,
            )
            if not hmac.compare_digest(received_proof, expected_proof):
                write_log(
                    "AUTH_REJECTED",
                    client=client_info["address"],
                    username=client_info["username"],
                )
                send_line(client_socket, "KEYX_REJECTED Mot de passe incorrect.")
                return "retry", None, buffer

        session_key = os.urandom(16)
        encrypted_session_key = encrypt_with_public_key(public_key_pem, session_key)
    except (ValueError, binascii.Error, UnicodeEncodeError):
        send_line(client_socket, "[server] Cle publique invalide.")
        return "failed", None, buffer

    with state_lock:
        if client_socket not in clients:
            return "failed", None, buffer

        clients[client_socket]["session_key"] = session_key
        clients[client_socket]["public_key"] = public_key_pem.decode("utf-8")

    send_line(
        client_socket,
        f"SESSION_KEY {base64.b64encode(encrypted_session_key).decode('ascii')}",
    )
    write_log(
        "SESSION_KEY_ESTABLISHED",
        client=client_info["address"],
        username=client_info["username"],
    )
    return "ok", session_key, buffer


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

        client_info = clients[client_socket]
        previous_room = client_info["room"]
        username = client_info["username"]
        client_address = client_info["address"]
        rooms[room_name] = password
        client_info["room"] = room_name

    write_log(
        "ROOM_CREATED",
        client=client_address,
        username=username,
        room=room_name,
        protected="yes" if password is not None else "no",
    )
    write_log(
        "ROOM_CHANGED",
        client=client_address,
        username=username,
        from_room=previous_room,
        to_room=room_name,
    )

    if password is None:
        return True, f"[server] Room creee et rejointe: {format_room_display(room_name)}."

    return True, f"[server] Room protegee creee et rejointe: {format_room_display(room_name)}."


def join_room(client_socket, room_name, password):
    with state_lock:
        client_info = clients[client_socket]
        previous_room = client_info["room"]
        username = client_info["username"]
        client_address = client_info["address"]

        if room_name not in rooms:
            return False, "[server] Cette room n'existe pas."

        room_password = rooms[room_name]
        if room_password is not None and password != room_password:
            write_log(
                "ROOM_JOIN_REJECTED_BAD_PASSWORD",
                client=client_address,
                username=username,
                room=room_name,
            )
            return False, "[server] Mot de passe incorrect."

        client_info["room"] = room_name

    if previous_room != room_name:
        write_log(
            "ROOM_CHANGED",
            client=client_address,
            username=username,
            from_room=previous_room,
            to_room=room_name,
        )

    return True, f"[server] Vous avez rejoint la room {format_room_display(room_name)}."


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
        return f"[server] Room courante: {format_room_display(room_name)}"

    return "[server] Commande inconnue."


def handle_client(client_socket, client_address):
    print(f"Client connecte: {client_address[0]}:{client_address[1]}")
    write_log("CLIENT_CONNECTED", client=format_client_address(client_address))
    username = None
    buffer = b""
    session_key = None

    try:
        username, buffer = negotiate_username(client_socket)
        if username is None:
            return

        while True:
            key_exchange_mode, stored_record, key_exchange_nonce = prepare_key_exchange(client_socket)
            if key_exchange_mode is None:
                return

            key_status, session_key, buffer = establish_session_key(
                client_socket,
                buffer,
                stored_record,
                key_exchange_nonce,
            )
            if key_status == "retry":
                continue
            if key_status != "ok":
                return
            break

        authenticated, _, buffer = authenticate_client(client_socket, buffer, session_key)
        if not authenticated:
            return

        send_secure_line(client_socket, session_key, f"[server] Vous avez rejoint la room {DEFAULT_ROOM}.")

        print(f"Username accepte: {username} ({client_address[0]}:{client_address[1]})")

        while True:
            try:
                message, buffer = receive_secure_line(client_socket, buffer, session_key)
            except (ValueError, binascii.Error, UnicodeDecodeError):
                send_secure_line(client_socket, session_key, "[server] Message chiffre invalide.")
                continue

            if message is None:
                break

            message = message.strip()
            if not message:
                continue

            if message.startswith("/"):
                response = process_command(client_socket, message)
                send_secure_line(client_socket, session_key, response)
                continue

            room_name = get_current_room(client_socket)
            if room_name is None:
                break

            client_info = get_client_snapshot(client_socket)
            if client_info is None:
                break

            formatted_message = build_chat_message(
                username,
                message,
                client_info["color"],
            )
            broadcast_encrypted_message_to_room(
                formatted_message,
                room_name,
                excluded_socket=client_socket,
            )
    except OSError:
        pass
    finally:
        released_info = remove_client(client_socket)
        if released_info is not None and released_info["username"] is not None:
            write_log(
                "CLIENT_DISCONNECTED",
                client=released_info["address"],
                username=released_info["username"],
                room=released_info["room"],
            )
            print(
                f"Client deconnecte: {released_info['username']} "
                f"({client_address[0]}:{client_address[1]})"
            )
        else:
            write_log(
                "CLIENT_DISCONNECTED",
                client=format_client_address(client_address),
            )
            print(f"Client deconnecte: {client_address[0]}:{client_address[1]}")


def run_server(port):
    global password_rules
    global password_store

    server_socket = None
    server_started = False
    password_rules = load_password_rules()
    password_store = load_password_store()
    initialize_log_file()
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((DEFAULT_HOST, port))
        server_socket.listen()

        server_started = True
        write_log("SERVER_STARTED", port=port, log_file=log_filename)
        print(f"Serveur en ecoute sur le port {port}")

        try:
            while True:
                client_socket, client_address = server_socket.accept()
                with state_lock:
                    clients[client_socket] = {
                        "username": None,
                        "room": None,
                        "color": None,
                        "authenticated": False,
                        "session_key": None,
                        "public_key": None,
                        "address": format_client_address(client_address),
                    }

                thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address),
                    daemon=True,
                )
                thread.start()
                with state_lock:
                    client_threads.append(thread)
        except KeyboardInterrupt:
            print("\nArret du serveur.")
    finally:
        with state_lock:
            open_clients = list(clients.keys())
            clients.clear()
            threads_to_join = list(client_threads)
            client_threads.clear()

        for client_socket in open_clients:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client_socket.close()
            except OSError:
                pass

        if server_socket is not None:
            server_socket.close()

        for thread in threads_to_join:
            thread.join()

        if server_started:
            write_log("SERVER_STOPPED")

        close_log_file()


def main():
    try:
        port = parse_port(sys.argv)
    except ValueError as error:
        print(error)
        sys.exit(1)

    run_server(port)


if __name__ == "__main__":
    main()
