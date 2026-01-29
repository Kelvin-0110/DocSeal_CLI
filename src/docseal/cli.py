from __future__ import annotations

import argparse
import os
import sys
from getpass import getpass

from .crypto import decrypt_file, encrypt_file
from .errors import DecryptionError, FileTooLargeError, ImageEncryptorError, InvalidFormatError, UnsafeOperationError
from .format import decode_header


def _read_password(args: argparse.Namespace) -> str:
    if args.password and args.password_file:
        raise UnsafeOperationError("Use either --password or --password-file, not both")

    if args.password:
        print("Warning: --password is insecure; prefer the prompt.", file=sys.stderr)
        return args.password

    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as f:
            pwd = f.read().strip("\r\n")
        if not pwd:
            raise UnsafeOperationError("Password file is empty")
        return pwd

    return getpass("Password: ")


def _resolve_output(input_path: str, out: str | None, default_ext: str) -> str:
    if out is None:
        base = os.path.basename(input_path)
        return os.path.join(os.path.dirname(input_path), base + default_ext)

    if os.path.isdir(out):
        base = os.path.basename(input_path)
        return os.path.join(out, base + default_ext)

    return out


def _ensure_safe_output(path: str, force: bool) -> None:
    if os.path.exists(path) and not force:
        raise UnsafeOperationError("Output exists; use --force to overwrite")


def _ensure_file(path: str) -> None:
    if not os.path.isfile(path):
        raise UnsafeOperationError("Input must be a file")


def _maybe_delete_original(path: str, delete_original: bool, confirmed: bool) -> None:
    if not delete_original:
        return
    if not confirmed:
        raise UnsafeOperationError("Refusing to delete original without --i-understand")
    os.remove(path)


def _encrypt(args: argparse.Namespace) -> int:
    _ensure_file(args.input)
    password = _read_password(args)
    out_path = _resolve_output(args.input, args.out, ".imgenc")
    _ensure_safe_output(out_path, args.force)

    encrypt_file(
        args.input,
        out_path,
        password,
        args.allow_large,
        alg_choice=args.algo,
        kdf_choice=args.kdf,
    )
    _maybe_delete_original(args.input, args.delete_original, args.i_understand)
    print("Encrypted successfully")
    return 0


def _decrypt(args: argparse.Namespace) -> int:
    _ensure_file(args.input)
    password = _read_password(args)

    with open(args.input, "rb") as f:
        header_bytes = f.read(4096)
    header, _offset = decode_header(header_bytes)
    ext = header.orig_ext

    if args.out is None:
        base = os.path.basename(args.input)
        if base.endswith(".imgenc"):
            base = base[: -len(".imgenc")]
        out_path = os.path.join(os.path.dirname(args.input), base + ext)
    elif os.path.isdir(args.out):
        base = os.path.basename(args.input)
        if base.endswith(".imgenc"):
            base = base[: -len(".imgenc")]
        out_path = os.path.join(args.out, base + ext)
    else:
        out_path = args.out

    _ensure_safe_output(out_path, args.force)
    decrypt_file(args.input, out_path, password, args.allow_large)

    _maybe_delete_original(args.input, args.delete_original, args.i_understand)
    print("Decrypted successfully")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="docseal")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("input", help="Input file path")
        p.add_argument("--out", help="Output file path or directory")
        p.add_argument("--force", action="store_true", help="Overwrite output if exists")
        p.add_argument("--allow-large", action="store_true", help="Allow files >200MB")
        p.add_argument("--password", help="Password (insecure, discouraged)")
        p.add_argument("--password-file", help="Read password from a file")
        p.add_argument("--keep-original", action="store_true", default=True, help="Keep original (default)")
        p.add_argument("--delete-original", action="store_true", help="Delete original after success")
        p.add_argument("--i-understand", action="store_true", help="Confirm original deletion")
        p.add_argument("--debug", action="store_true", help="Show stack traces")

    enc = sub.add_parser("encrypt", help="Encrypt an image file")
    add_common(enc)
    enc.add_argument(
        "--algo",
        choices=["auto", "xchacha20-poly1305", "chacha20-poly1305", "aes-256-gcm"],
        default="auto",
        help="Select AEAD algorithm (default: auto)",
    )
    enc.add_argument(
        "--kdf",
        choices=["auto", "argon2id", "scrypt"],
        default="auto",
        help="Select KDF (default: auto)",
    )

    dec = sub.add_parser("decrypt", help="Decrypt an image file")
    add_common(dec)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "encrypt":
            return _encrypt(args)
        if args.command == "decrypt":
            return _decrypt(args)
        raise UnsafeOperationError("Unknown command")
    except (ImageEncryptorError, InvalidFormatError, FileTooLargeError, DecryptionError, UnsafeOperationError) as exc:
        if getattr(args, "debug", False):
            raise
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        if getattr(args, "debug", False):
            raise
        print("Unexpected error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
