from __future__ import annotations

import os

import pytest

from docseal.crypto import decrypt_bytes, encrypt_bytes
from docseal.errors import DecryptionError


@pytest.fixture()
def sample_bytes() -> bytes:
    return b"\x89PNG\r\n\x1a\n" + os.urandom(1024)


def test_roundtrip(sample_bytes: bytes) -> None:
    encrypted = encrypt_bytes(sample_bytes, "password123", ".png")
    decrypted, ext = decrypt_bytes(encrypted, "password123")
    assert decrypted == sample_bytes
    assert ext == ".png"


def test_wrong_password_fails(sample_bytes: bytes) -> None:
    encrypted = encrypt_bytes(sample_bytes, "password123", ".png")
    with pytest.raises(DecryptionError):
        decrypt_bytes(encrypted, "wrong")


def test_tamper_detection_fails(sample_bytes: bytes) -> None:
    encrypted = encrypt_bytes(sample_bytes, "password123", ".png")
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_bytes(bytes(tampered), "password123")


def test_header_tamper_fails(sample_bytes: bytes) -> None:
    encrypted = encrypt_bytes(sample_bytes, "password123", ".png")
    tampered = bytearray(encrypted)
    tampered[4] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt_bytes(bytes(tampered), "password123")
