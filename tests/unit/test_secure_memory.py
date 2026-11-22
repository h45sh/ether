"""Unit tests for zero-leakage in-memory credential and buffer scrubbing."""

import gc

import pytest

from ether.common.secure_memory import SecureBuffer, wipe_buffer, wipe_credentials


def test_wipe_buffer_zeroes_memory():
    """Verify that wipe_buffer uses ctypes.memset to zero bytearray memory."""
    buf = bytearray(b"SENSITIVE_SECRET_TOKEN_999")
    assert any(b != 0 for b in buf)

    wipe_buffer(buf)

    assert len(buf) == 26
    assert all(b == 0 for b in buf)


def test_secure_buffer_lifecycle_and_explicit_wipe():
    """Verify SecureBuffer access, explicit wiping, and error upon wiped access."""
    sec = SecureBuffer("api_key_xyz_12345")
    assert sec.is_wiped is False
    assert len(sec) == 17
    assert sec.get_string() == "api_key_xyz_12345"

    sec.wipe()
    assert sec.is_wiped is True
    assert repr(sec) == "<SecureBuffer: [WIPED]>"

    with pytest.raises(ValueError, match="already been wiped"):
        sec.get_bytes()

    with pytest.raises(ValueError, match="already been wiped"):
        sec.get_string()


def test_secure_buffer_context_manager_auto_wipe():
    """Verify that SecureBuffer zeroes memory immediately upon exiting context."""
    with SecureBuffer(b"ephemeral_private_key_material") as sec:
        assert sec.is_wiped is False
        assert sec.get_bytes() == b"ephemeral_private_key_material"

    assert sec.is_wiped is True


def test_secure_buffer_destructor_auto_wipe():
    """Verify that garbage collection triggers finalizer memory wipe."""
    sec = SecureBuffer(b"to_be_garbage_collected")
    ref = sec._buf

    del sec
    gc.collect()

    # The underlying bytearray buffer must be zeroed
    assert all(b == 0 for b in ref)


def test_wipe_credentials_dict_and_list():
    """Verify recursive scanning and in-place wiping of sensitive keys."""
    sec_key = SecureBuffer("sensitive_secret_value")

    payload = {
        "target": "10.0.0.1",
        "params": {
            "password": "ClearTextPassword123",
            "api_key": bytearray(b"RAW_API_KEY_BYTES"),
            "token": sec_key,
            "nested": {
                "private_key": "-----BEGIN RSA PRIVATE KEY-----",
                "normal_field": "safe_value",
            },
        },
        "credentials": [
            bytearray(b"admin_hash_here"),
            {"secret": "hidden_secret"},
        ],
    }

    wipe_credentials(payload)

    # Immutable sensitive strings replaced with [WIPED]
    assert payload["params"]["password"] == "[WIPED]"
    assert payload["params"]["nested"]["private_key"] == "[WIPED]"
    assert payload["params"]["nested"]["normal_field"] == "safe_value"
    assert payload["credentials"][1]["secret"] == "[WIPED]"

    # Mutable buffers zeroed in place
    assert all(b == 0 for b in payload["params"]["api_key"])
    assert sec_key.is_wiped is True
    assert all(b == 0 for b in payload["credentials"][0])
