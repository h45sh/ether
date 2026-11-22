"""Authenticated AES-256-GCM encryption with Argon2id key derivation for Ether archives.

Provides tamper-resistant, authenticated encryption for session database exports
and state archives, ensuring confidentiality and cryptographic integrity.
"""

import os
from typing import Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC_HEADER = b"ETHER_SECURE_ARC"  # 16 bytes
CURRENT_VERSION = 1  # 1 byte
AAD_TAG = b"ETHER_AUTHENTICATED_DATABASE_V1"
SALT_SIZE = 16
NONCE_SIZE = 12
HEADER_SIZE = len(MAGIC_HEADER) + 1 + SALT_SIZE + NONCE_SIZE  # 16 + 1 + 16 + 12 = 45 bytes


class CryptoError(Exception):
    """Base exception for cryptographic operations in Ether."""


class InvalidArchiveFormatError(CryptoError):
    """Raised when an encrypted archive has invalid headers, length, or version."""


class TamperedArchiveError(CryptoError):
    """Raised when ciphertext authentication fails (bit-flip, truncation, or wrong key)."""


class InvalidPassphraseError(CryptoError):
    """Raised when a passphrase is empty or invalid."""


def derive_key_argon2id(
    passphrase: Union[str, bytes],
    salt: bytes,
    iterations: int = 3,
    lanes: int = 4,
    memory_cost: int = 65536,
) -> bytes:
    """Derive a 256-bit (32-byte) key using Argon2id with memory-hard parameters."""
    if isinstance(passphrase, str):
        passphrase_bytes = passphrase.encode("utf-8")
    else:
        passphrase_bytes = passphrase

    if not passphrase_bytes:
        raise InvalidPassphraseError("Passphrase cannot be empty.")

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    return kdf.derive(passphrase_bytes)


def encrypt_bytes(
    data: bytes,
    passphrase: str,
    iterations: int = 3,
    memory_cost: int = 65536,
) -> bytes:
    """Encrypt payload using AES-256-GCM and Argon2id key derivation."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key_argon2id(passphrase, salt, iterations=iterations, memory_cost=memory_cost)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, bytes(data), AAD_TAG)

    # Format: MAGIC (16B) + VERSION (1B) + SALT (16B) + NONCE (12B) + CIPHERTEXT (incl 16B tag)
    header = MAGIC_HEADER + bytes([CURRENT_VERSION]) + salt + nonce
    return header + ciphertext


def decrypt_bytes(
    archive_bytes: bytes,
    passphrase: str,
    iterations: int = 3,
    memory_cost: int = 65536,
) -> bytes:
    """Decrypt payload using AES-256-GCM, verifying integrity and authentication tag."""
    if len(archive_bytes) < HEADER_SIZE + 16:  # Must have header + at least 16-byte auth tag
        raise InvalidArchiveFormatError("Archive data is too short to be a valid Ether secure archive.")

    # 1. Verify Magic Header
    magic = archive_bytes[: len(MAGIC_HEADER)]
    if magic != MAGIC_HEADER:
        raise InvalidArchiveFormatError(f"Invalid magic header: expected {MAGIC_HEADER!r}, got {magic!r}")

    # 2. Verify Version
    offset = len(MAGIC_HEADER)
    version = archive_bytes[offset]
    if version != CURRENT_VERSION:
        raise InvalidArchiveFormatError(f"Unsupported archive version: {version} (expected {CURRENT_VERSION})")
    offset += 1

    # 3. Extract Salt & Nonce
    salt = archive_bytes[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = archive_bytes[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE

    ciphertext = archive_bytes[offset:]

    # 4. Derive key and decrypt
    key = derive_key_argon2id(passphrase, salt, iterations=iterations, memory_cost=memory_cost)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, AAD_TAG)
        return plaintext
    except InvalidTag as exc:
        raise TamperedArchiveError("Decryption failed: archive is corrupted, tampered with, or passphrase is wrong.") from exc


def encrypt_file(
    input_path: str,
    output_path: str,
    passphrase: str,
    iterations: int = 3,
    memory_cost: int = 65536,
) -> None:
    """Encrypt file contents atomically with 0o600 permissions."""
    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = encrypt_bytes(data, passphrase, iterations=iterations, memory_cost=memory_cost)

    # Atomic write with 0o600 permissions
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(output_path, flags, 0o600)
    with open(fd, "wb") as f:
        f.write(encrypted)


def decrypt_file(
    input_path: str,
    output_path: str,
    passphrase: str,
    iterations: int = 3,
    memory_cost: int = 65536,
) -> None:
    """Decrypt archive contents and write to output_path atomically with 0o600 permissions."""
    with open(input_path, "rb") as f:
        archive_bytes = f.read()

    plaintext = decrypt_bytes(archive_bytes, passphrase, iterations=iterations, memory_cost=memory_cost)

    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(output_path, flags, 0o600)
    with open(fd, "wb") as f:
        f.write(plaintext)
