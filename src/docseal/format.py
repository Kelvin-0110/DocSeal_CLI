from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple
import struct

from .errors import InvalidFormatError

MAGIC = b"IMGE"
VERSION = 1

ALG_XCHACHA20_POLY1305 = 1
ALG_CHACHA20_POLY1305 = 2
ALG_AES256_GCM = 3

KDF_ARGON2ID = 1
KDF_SCRYPT = 2


@dataclass(frozen=True)
class KdfParams:
    params: bytes


@dataclass(frozen=True)
class Header:
    version: int
    alg_id: int
    kdf_id: int
    kdf_params: bytes
    salt: bytes
    nonce: bytes
    orig_ext: str

    def encode(self) -> bytes:
        ext_bytes = self.orig_ext.encode("utf-8")
        if len(ext_bytes) > 255:
            raise InvalidFormatError("Original extension too long")
        if len(self.salt) > 255 or len(self.nonce) > 255:
            raise InvalidFormatError("Salt or nonce too long")

        parts = [
            MAGIC,
            struct.pack(">BBBBH", self.version, self.alg_id, self.kdf_id, 0, len(self.kdf_params)),
            self.kdf_params,
            struct.pack(">B", len(self.salt)),
            self.salt,
            struct.pack(">B", len(self.nonce)),
            self.nonce,
            struct.pack(">B", len(ext_bytes)),
            ext_bytes,
        ]
        return b"".join(parts)


def decode_header(data: bytes) -> Tuple[Header, int]:
    if len(data) < 4 + 1 + 1 + 1 + 1 + 2:
        raise InvalidFormatError("File too short")
    if data[:4] != MAGIC:
        raise InvalidFormatError("Bad magic bytes")

    offset = 4
    try:
        version, alg_id, kdf_id, _reserved, kdf_params_len = struct.unpack_from(">BBBBH", data, offset
        )
    except struct.error as exc:
        raise InvalidFormatError("Invalid header") from exc

    offset += 6
    if version != VERSION:
        raise InvalidFormatError("Unsupported version")

    end = offset + kdf_params_len
    if end > len(data):
        raise InvalidFormatError("Truncated KDF params")
    kdf_params = data[offset:end]
    offset = end

    if offset + 1 > len(data):
        raise InvalidFormatError("Truncated salt length")
    salt_len = data[offset]
    offset += 1
    end = offset + salt_len
    if end > len(data):
        raise InvalidFormatError("Truncated salt")
    salt = data[offset:end]
    offset = end

    if offset + 1 > len(data):
        raise InvalidFormatError("Truncated nonce length")
    nonce_len = data[offset]
    offset += 1
    end = offset + nonce_len
    if end > len(data):
        raise InvalidFormatError("Truncated nonce")
    nonce = data[offset:end]
    offset = end

    if offset + 1 > len(data):
        raise InvalidFormatError("Truncated extension length")
    ext_len = data[offset]
    offset += 1
    end = offset + ext_len
    if end > len(data):
        raise InvalidFormatError("Truncated extension")
    ext_bytes = data[offset:end]
    offset = end

    try:
        orig_ext = ext_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidFormatError("Invalid extension encoding") from exc

    header = Header(
        version=version,
        alg_id=alg_id,
        kdf_id=kdf_id,
        kdf_params=kdf_params,
        salt=salt,
        nonce=nonce,
        orig_ext=orig_ext,
    )
    return header, offset