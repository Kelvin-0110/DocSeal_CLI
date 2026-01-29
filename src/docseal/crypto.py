from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Tuple
import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import DecryptionError, FileTooLargeError, InvalidFormatError
from .format import (
    Header,
    KDF_ARGON2ID,
    KDF_SCRYPT,
    ALG_AES256_GCM,
    ALG_CHACHA20_POLY1305,
    ALG_XCHACHA20_POLY1305,
    decode_header,
)

try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305  # type: ignore

    HAS_XCHACHA = True
except Exception:
    XChaCha20Poly1305 = None
    HAS_XCHACHA = False

try:
    from argon2.low_level import Type as Argon2Type
    from argon2.low_level import hash_secret_raw as argon2_hash_secret_raw

    HAS_ARGON2 = True
except Exception:
    Argon2Type = None
    argon2_hash_secret_raw = None
    HAS_ARGON2 = False

MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB
KEY_LEN = 32
SALT_LEN = 16
MIN_SALT_LEN = 8
MAX_SALT_LEN = 64

ARGON2_MAX_TIME = 10
ARGON2_MAX_MEMORY_KIB = 1024 * 1024  # 1GB
ARGON2_MAX_PARALLELISM = 8

SCRYPT_MIN_N = 2**14
SCRYPT_MAX_N = 2**20
SCRYPT_MAX_R = 16
SCRYPT_MAX_P = 4


@dataclass(frozen=True)
class KdfConfig:
    kdf_id: int
    params: bytes


@dataclass(frozen=True)
class AeadConfig:
    alg_id: int
    nonce_len: int


def _select_aead() -> AeadConfig:
    if HAS_XCHACHA and XChaCha20Poly1305 is not None:
        return AeadConfig(alg_id=ALG_XCHACHA20_POLY1305, nonce_len=24)
    if ChaCha20Poly1305 is not None:
        return AeadConfig(alg_id=ALG_CHACHA20_POLY1305, nonce_len=12)
    return AeadConfig(alg_id=ALG_AES256_GCM, nonce_len=12)


def _select_kdf() -> Tuple[int, bytes]:
    if HAS_ARGON2 and argon2_hash_secret_raw is not None:
        # time_cost=3, memory_cost=64MB, parallelism=2
        return KDF_ARGON2ID, struct.pack(">III", 3, 65536, 2)
    # Scrypt params: N=2**15, r=8, p=1
    return KDF_SCRYPT, struct.pack(">III", 2**15, 8, 1)

def _resolve_aead(choice: Optional[str]) -> AeadConfig:
    if choice in (None, "auto"):
        return _select_aead()
    if choice == "xchacha20-poly1305":
        if not (HAS_XCHACHA and XChaCha20Poly1305 is not None):
            raise InvalidFormatError("XChaCha20-Poly1305 not available")
        return AeadConfig(alg_id=ALG_XCHACHA20_POLY1305, nonce_len=24)
    if choice == "chacha20-poly1305":
        return AeadConfig(alg_id=ALG_CHACHA20_POLY1305, nonce_len=12)
    if choice == "aes-256-gcm":
        return AeadConfig(alg_id=ALG_AES256_GCM, nonce_len=12)
    raise InvalidFormatError("Unknown algorithm selection")


def _resolve_kdf(choice: Optional[str]) -> Tuple[int, bytes]:
    if choice in (None, "auto"):
        return _select_kdf()
    if choice == "argon2id":
        if not (HAS_ARGON2 and argon2_hash_secret_raw is not None):
            raise InvalidFormatError("Argon2id not available")
        return KDF_ARGON2ID, struct.pack(">III", 3, 65536, 2)
    if choice == "scrypt":
        return KDF_SCRYPT, struct.pack(">III", 2**15, 8, 1)
    raise InvalidFormatError("Unknown KDF selection")


def _derive_key(password: str, salt: bytes, kdf_id: int, kdf_params: bytes) -> bytes:
    password_bytes = password.encode("utf-8")

    if kdf_id == KDF_ARGON2ID:
        if not (HAS_ARGON2 and argon2_hash_secret_raw is not None):
            raise InvalidFormatError("Argon2id not available")
        if len(kdf_params) != 12:
            raise InvalidFormatError("Invalid Argon2id params")
        time_cost, memory_cost, parallelism = struct.unpack(">III", kdf_params)
        if (
            time_cost < 1
            or time_cost > ARGON2_MAX_TIME
            or memory_cost < 8 * 1024
            or memory_cost > ARGON2_MAX_MEMORY_KIB
            or parallelism < 1
            or parallelism > ARGON2_MAX_PARALLELISM
        ):
            raise InvalidFormatError("Argon2id params out of range")
        return argon2_hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=KEY_LEN,
            type=Argon2Type.ID,
        )

    if kdf_id == KDF_SCRYPT:
        if len(kdf_params) != 12:
            raise InvalidFormatError("Invalid Scrypt params")
        n, r, p = struct.unpack(">III", kdf_params)
        if n < SCRYPT_MIN_N or n > SCRYPT_MAX_N or (n & (n - 1)) != 0:
            raise InvalidFormatError("Scrypt N out of range")
        if r < 1 or r > SCRYPT_MAX_R or p < 1 or p > SCRYPT_MAX_P:
            raise InvalidFormatError("Scrypt r/p out of range")
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
        return kdf.derive(password_bytes)

    raise InvalidFormatError("Unknown KDF")


def _aead_encrypt(alg_id: int, key: bytes, nonce: bytes, data: bytes, aad: Optional[bytes]) -> bytes:
    if alg_id == ALG_XCHACHA20_POLY1305 and HAS_XCHACHA and XChaCha20Poly1305 is not None:
        return XChaCha20Poly1305(key).encrypt(nonce, data, aad)
    if alg_id == ALG_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key).encrypt(nonce, data, aad)
    if alg_id == ALG_AES256_GCM:
        return AESGCM(key).encrypt(nonce, data, aad)
    raise InvalidFormatError("Unknown algorithm")


def _aead_decrypt(alg_id: int, key: bytes, nonce: bytes, data: bytes, aad: Optional[bytes]) -> bytes:
    if alg_id == ALG_XCHACHA20_POLY1305 and HAS_XCHACHA and XChaCha20Poly1305 is not None:
        return XChaCha20Poly1305(key).decrypt(nonce, data, aad)
    if alg_id == ALG_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key).decrypt(nonce, data, aad)
    if alg_id == ALG_AES256_GCM:
        return AESGCM(key).decrypt(nonce, data, aad)
    raise InvalidFormatError("Unknown algorithm")

def _expected_nonce_len(alg_id: int) -> int:
    if alg_id == ALG_XCHACHA20_POLY1305:
        return 24
    return 12


def _validate_extension(ext: str) -> None:
    if "\x00" in ext:
        raise InvalidFormatError("Invalid extension")
    if os.path.sep in ext:
        raise InvalidFormatError("Invalid extension")
    if os.path.altsep and os.path.altsep in ext:
        raise InvalidFormatError("Invalid extension")
    if ":" in ext:
        raise InvalidFormatError("Invalid extension")
    if ext and not ext.startswith("."):
        raise InvalidFormatError("Invalid extension")
    if len(ext) > 32:
        raise InvalidFormatError("Extension too long")


def encrypt_bytes(
    data: bytes,
    password: str,
    orig_ext: str,
    alg_choice: Optional[str] = None,
    kdf_choice: Optional[str] = None,
) -> bytes:
    if len(data) > MAX_FILE_SIZE:
        raise FileTooLargeError("File exceeds size limit")

    aead = _resolve_aead(alg_choice)
    kdf_id, kdf_params = _resolve_kdf(kdf_choice)
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(aead.nonce_len)

    key = _derive_key(password, salt, kdf_id, kdf_params)
    safe_ext = orig_ext or ""
    _validate_extension(safe_ext)

    header = Header(
        version=1,
        alg_id=aead.alg_id,
        kdf_id=kdf_id,
        kdf_params=kdf_params,
        salt=salt,
        nonce=nonce,
        orig_ext=safe_ext,
    )
    header_bytes = header.encode()
    ciphertext = _aead_encrypt(aead.alg_id, key, nonce, data, header_bytes)
    return header_bytes + ciphertext


def decrypt_bytes(data: bytes, password: str) -> Tuple[bytes, str]:
    header, offset = decode_header(data)
    if len(header.salt) < MIN_SALT_LEN or len(header.salt) > MAX_SALT_LEN:
        raise InvalidFormatError("Invalid salt length")
    if len(header.nonce) != _expected_nonce_len(header.alg_id):
        raise InvalidFormatError("Invalid nonce length")
    _validate_extension(header.orig_ext)
    ciphertext = data[offset:]
    key = _derive_key(password, header.salt, header.kdf_id, header.kdf_params)
    try:
        plaintext = _aead_decrypt(header.alg_id, key, header.nonce, ciphertext, data[:offset])
    except Exception as exc:
        raise DecryptionError("Decryption failed") from exc
    return plaintext, header.orig_ext


def encrypt_file(
    path: str,
    out_path: str,
    password: str,
    allow_large: bool,
    alg_choice: Optional[str] = None,
    kdf_choice: Optional[str] = None,
) -> None:
    size = os.path.getsize(path)
    if size > MAX_FILE_SIZE and not allow_large:
        raise FileTooLargeError("File exceeds size limit; use --allow-large")

    with open(path, "rb") as f:
        data = f.read()

    ext = os.path.splitext(path)[1]
    payload = encrypt_bytes(data, password, ext, alg_choice=alg_choice, kdf_choice=kdf_choice)
    with open(out_path, "wb") as f:
        f.write(payload)


def decrypt_file(path: str, out_path: str, password: str, allow_large: bool) -> None:
    size = os.path.getsize(path)
    if size > MAX_FILE_SIZE and not allow_large:
        raise FileTooLargeError("File exceeds size limit; use --allow-large")

    with open(path, "rb") as f:
        data = f.read()

    plaintext, _ext = decrypt_bytes(data, password)
    with open(out_path, "wb") as f:
        f.write(plaintext)
