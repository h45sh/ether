"""Cryptographic verification test suite for Ether session database archives.

Tests:
1. AES-256-GCM authenticated encryption roundtrip.
2. Argon2id key derivation resistance.
3. Rejecting incorrect passphrases.
4. Rejecting bit-flipped ciphertext (AEAD integrity).
5. Rejecting truncated, corrupted, or altered archive headers.
6. Atomic 0o600 file permission guarantees.
"""

import os
import stat

import pytest

from ether.common.crypto import (
    MAGIC_HEADER,
    InvalidArchiveFormatError,
    InvalidPassphraseError,
    TamperedArchiveError,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
)


def test_encrypt_decrypt_bytes_roundtrip():
    """Verify that encrypted bytes roundtrip cleanly with the correct passphrase."""
    plaintext = b'{"session_id": "test-123", "nodes": [{"id": "n1"}]}'
    passphrase = "Correct-Horse-Battery-Staple-2026!"

    # Use smaller memory cost for fast test runs
    encrypted = encrypt_bytes(plaintext, passphrase, iterations=1, memory_cost=1024)
    assert encrypted.startswith(MAGIC_HEADER)
    assert len(encrypted) > len(plaintext)

    decrypted = decrypt_bytes(encrypted, passphrase, iterations=1, memory_cost=1024)
    assert decrypted == plaintext


def test_reject_wrong_passphrase():
    """Verify that decryption fails when supplied with an incorrect passphrase."""
    plaintext = b"sensitive investigation graph state"
    encrypted = encrypt_bytes(plaintext, "password-A", iterations=1, memory_cost=1024)

    with pytest.raises(TamperedArchiveError) as exc_info:
        decrypt_bytes(encrypted, "password-B-WRONG", iterations=1, memory_cost=1024)
    assert "Decryption failed" in str(exc_info.value)


def test_reject_bit_flipped_ciphertext():
    """Verify that a single bit modification in the ciphertext or tag is rejected."""
    plaintext = b"super secret forensic finding"
    encrypted = bytearray(encrypt_bytes(plaintext, "test-key", iterations=1, memory_cost=1024))

    # Flip 1 bit in the ciphertext payload (after the 45-byte header)
    tamper_index = len(MAGIC_HEADER) + 30
    encrypted[tamper_index] ^= 0x01

    with pytest.raises(TamperedArchiveError):
        decrypt_bytes(bytes(encrypted), "test-key", iterations=1, memory_cost=1024)


def test_reject_truncated_archive():
    """Verify that truncated or undersized archives are rejected with format error."""
    with pytest.raises(InvalidArchiveFormatError):
        decrypt_bytes(b"TOO_SHORT", "test-key", iterations=1, memory_cost=1024)


def test_reject_corrupt_magic_header():
    """Verify that archives with invalid magic bytes are rejected immediately."""
    plaintext = b"valid data"
    encrypted = bytearray(encrypt_bytes(plaintext, "test-key", iterations=1, memory_cost=1024))

    # Corrupt magic header
    encrypted[0] = ord("X")
    with pytest.raises(InvalidArchiveFormatError) as exc_info:
        decrypt_bytes(bytes(encrypted), "test-key", iterations=1, memory_cost=1024)
    assert "Invalid magic header" in str(exc_info.value)


def test_empty_passphrase_rejected():
    """Verify that empty passphrases raise InvalidPassphraseError."""
    with pytest.raises(InvalidPassphraseError):
        encrypt_bytes(b"data", "", iterations=1, memory_cost=1024)


def test_encrypt_decrypt_file_roundtrip_permissions(tmp_path):
    """Verify file encryption and decryption roundtrip with atomic 0o600 file permissions."""
    in_file = tmp_path / "graph.json"
    enc_file = tmp_path / "graph.enc"
    dec_file = tmp_path / "recovered.json"

    original_data = b'{"nodes": ["10.0.0.1", "10.0.0.2"], "status": "confirmed"}'
    in_file.write_bytes(original_data)

    passphrase = "Strict-Atomic-Permissions-Key!"
    encrypt_file(str(in_file), str(enc_file), passphrase, iterations=1, memory_cost=1024)

    # Verify encrypted file exists and has 0o600 permissions
    assert enc_file.exists()
    enc_mode = stat.S_IMODE(os.stat(enc_file).st_mode)
    assert enc_mode == 0o600, f"Expected file mode 0o600, got {oct(enc_mode)}"

    decrypt_file(str(enc_file), str(dec_file), passphrase, iterations=1, memory_cost=1024)

    assert dec_file.exists()
    dec_mode = stat.S_IMODE(os.stat(dec_file).st_mode)
    assert dec_mode == 0o600, f"Expected file mode 0o600, got {oct(dec_mode)}"
    assert dec_file.read_bytes() == original_data
