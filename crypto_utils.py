import base64
import binascii
import hashlib
import os
import struct


KDF_ALGORITHM = "pbkdf2_sha256"
KDF_ITERATIONS = 200000
TRANSPORT_KEY_BYTES = 16
TRANSPORT_SALT_BYTES = 16
TEA_BLOCK_SIZE = 8
TEA_DELTA = 0x9E3779B9
TEA_ROUNDS = 32


def derive_transport_key(secret, salt, iterations=KDF_ITERATIONS):
    return hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt,
        iterations,
        TRANSPORT_KEY_BYTES,
    )


def build_transport_key_record(secret):
    salt = os.urandom(TRANSPORT_SALT_BYTES)
    key = derive_transport_key(secret, salt)
    return {
        "algorithm": KDF_ALGORITHM,
        "cost": str(KDF_ITERATIONS),
        "salt": base64.b64encode(salt).decode("ascii"),
        "key": base64.b64encode(key).decode("ascii"),
    }


def build_transport_key_record_from_metadata(secret, algorithm, cost, salt_b64):
    if algorithm != KDF_ALGORITHM:
        raise ValueError("Unsupported key derivation algorithm.")

    iterations = int(cost)
    salt = base64.b64decode(salt_b64.encode("ascii"))
    key = derive_transport_key(secret, salt, iterations)
    return {
        "algorithm": algorithm,
        "cost": str(iterations),
        "salt": salt_b64,
        "key": base64.b64encode(key).decode("ascii"),
    }


def serialize_transport_key_record(record):
    return (
        f"{record['algorithm']}:{record['cost']}:"
        f"{record['salt']}:{record['key']}"
    )


def serialize_transport_key_metadata(record):
    return f"{record['algorithm']}:{record['cost']}:{record['salt']}"


def parse_transport_key_record(serialized_record):
    algorithm, cost, salt_b64, key_b64 = serialized_record.split(":", 3)
    return {
        "algorithm": algorithm,
        "cost": cost,
        "salt": salt_b64,
        "key": key_b64,
    }


def parse_transport_key_metadata(serialized_record):
    algorithm, cost, salt_b64 = serialized_record.split(":", 2)
    return {
        "algorithm": algorithm,
        "cost": cost,
        "salt": salt_b64,
    }


def transport_key_bytes(record):
    return base64.b64decode(record["key"].encode("ascii"))


def _pkcs7_pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)


def _pkcs7_unpad(data, block_size):
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")

    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length.")

    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes.")

    return data[:-padding_length]


def _tea_encrypt_block(block, key):
    v0, v1 = struct.unpack(">2I", block)
    k0, k1, k2, k3 = struct.unpack(">4I", key)
    total = 0

    for _ in range(TEA_ROUNDS):
        total = (total + TEA_DELTA) & 0xFFFFFFFF
        v0 = (
            v0
            + (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))
        ) & 0xFFFFFFFF
        v1 = (
            v1
            + (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))
        ) & 0xFFFFFFFF

    return struct.pack(">2I", v0, v1)


def _tea_decrypt_block(block, key):
    v0, v1 = struct.unpack(">2I", block)
    k0, k1, k2, k3 = struct.unpack(">4I", key)
    total = (TEA_DELTA * TEA_ROUNDS) & 0xFFFFFFFF

    for _ in range(TEA_ROUNDS):
        v1 = (
            v1
            - (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))
        ) & 0xFFFFFFFF
        v0 = (
            v0
            - (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))
        ) & 0xFFFFFFFF
        total = (total - TEA_DELTA) & 0xFFFFFFFF

    return struct.pack(">2I", v0, v1)


def encrypt_transport_message(message, key):
    plaintext = _pkcs7_pad(message.encode("utf-8"), TEA_BLOCK_SIZE)
    iv = os.urandom(TEA_BLOCK_SIZE)
    previous = iv
    ciphertext = bytearray()

    for start in range(0, len(plaintext), TEA_BLOCK_SIZE):
        block = plaintext[start:start + TEA_BLOCK_SIZE]
        xored = bytes(left ^ right for left, right in zip(block, previous))
        encrypted = _tea_encrypt_block(xored, key)
        ciphertext.extend(encrypted)
        previous = encrypted

    return (
        f"{base64.b64encode(iv).decode('ascii')}:"
        f"{base64.b64encode(bytes(ciphertext)).decode('ascii')}"
    )


def decrypt_transport_message(payload, key):
    iv_b64, ciphertext_b64 = payload.split(":", 1)
    try:
        iv = base64.b64decode(iv_b64.encode("ascii"), validate=True)
        ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("Invalid encrypted message encoding.") from exc

    if len(iv) != TEA_BLOCK_SIZE or len(ciphertext) % TEA_BLOCK_SIZE != 0:
        raise ValueError("Invalid encrypted message format.")

    previous = iv
    plaintext = bytearray()

    for start in range(0, len(ciphertext), TEA_BLOCK_SIZE):
        block = ciphertext[start:start + TEA_BLOCK_SIZE]
        decrypted = _tea_decrypt_block(block, key)
        plaintext.extend(
            left ^ right for left, right in zip(decrypted, previous)
        )
        previous = block

    unpadded = _pkcs7_unpad(bytes(plaintext), TEA_BLOCK_SIZE)
    return unpadded.decode("utf-8")
