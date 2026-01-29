# DocSeal CLI

CLI-only file encryptor/decryptor for personal privacy use. Works on any file as raw bytes (no parsing). Uses modern authenticated encryption (AEAD) and a password-based KDF. Local-only, no network access, no telemetry, no logging.

## Why it is secure (design summary)
- **Confidentiality + integrity**: AEAD provides encryption and tamper detection in one step.
- **Strong key derivation**: Per-file random salt plus Argon2id (preferred) or Scrypt (fallback).
- **Fresh nonces**: A new random nonce is generated for every encryption.
- **Authenticated metadata**: The header (algo/KDF/nonce/salt/extension) is authenticated as AEAD AAD.

## Security model (what this protects)
- Confidentiality + integrity of image files when stored or shared.
- Tamper detection: wrong passwords or modified ciphertext fail safely.

## Threat model (what this does NOT protect)
- Compromised OS, malware, keyloggers, or leaked passwords.
- Weak passwords or reuse across services.
- Forensic recovery after deletion (no secure erase).
- Huge files beyond the configured limit unless explicitly allowed.

## Crypto design
- AEAD: XChaCha20-Poly1305 if available, else ChaCha20-Poly1305, else AES-256-GCM.
- KDF: Argon2id if available, else Scrypt.
- Per-file random salt and nonce.
- Header includes magic bytes, version, algorithm id, KDF id + params, salt, nonce, original extension, and ciphertext+tag.

## Crypto details
- AEAD selection: XChaCha20-Poly1305 (24-byte nonce) → ChaCha20-Poly1305 (12-byte nonce) → AES-256-GCM (12-byte nonce).
- KDF selection: Argon2id → Scrypt (fallback).
- Argon2id params (current): time_cost=3, memory_cost=65536 KiB (64 MiB), parallelism=2.
- Scrypt params (current): N=2**15, r=8, p=1.
- Key length: 32 bytes (256-bit).
- Salt length: 16 bytes (per file).
- Header is authenticated as AEAD AAD, so header tampering fails decryption.
You can override the default selections at encrypt time with `--algo` and `--kdf`.

## File size limit
Default max file size is 200MB to avoid excessive memory use. If you need larger files, pass `--allow-large` and understand the risks.

## Supported image formats
Any image format works (PNG, JPEG/JPG, GIF, BMP, TIFF, WEBP, etc.) because the tool encrypts raw bytes and does not parse the image. The original file extension is restored on decrypt.

## Installation

### 1) Create a virtual environment
```
python -m venv .venv
```

### 2) Activate the environment
PowerShell may block activation scripts. Use one of these:

**Option A (no policy change, recommended):**
```
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m pip install -e .
```

**Option B (current user only):**
```
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\.venv\Scripts\activate
```

**Option C (temporary, this session only):**
```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\activate
```

### 3) Install dependencies and the CLI
```
pip install -r requirements.txt
pip install -e .
```

## Run

### CLI entry point
```
docseal --help
```

### Run without installing the entry point
```
python -m docseal.cli --help
```

### Encrypt
```
docseal encrypt path\\to\\photo.jpg
```

### Decrypt
```
docseal decrypt path\\to\\photo.jpg.imgenc
```

## Help (all CLI parameters)
General:
- `-h`, `--help`: show help and exit

Commands:
- `encrypt <input>`: encrypt an image file
- `decrypt <input>`: decrypt an encrypted file

Common options (apply to both commands):
- `--out <path>`: output file path or output directory
- `--force`: overwrite output if it already exists
- `--allow-large`: allow files larger than 200MB
- `--password <text>`: provide password directly (discouraged)
- `--password-file <path>`: read password from a file (first line)
- `--keep-original`: keep original after success (default)
- `--delete-original`: delete original after success
- `--i-understand`: confirmation required with `--delete-original`
- `--debug`: show stack traces on errors

Encrypt-only options:
- `--algo {auto,xchacha20-poly1305,chacha20-poly1305,aes-256-gcm}`: choose AEAD algorithm
- `--kdf {auto,argon2id,scrypt}`: choose KDF

### Output control
- `--out` can be a file path or a directory.
- Existing outputs are never overwritten unless `--force` is set.

### Password handling
- Recommended: prompt via secure input (default).
- `--password` accepts a literal password (discouraged; warns).
- `--password-file` reads a password from a file (risks: backups, history, permissions).

### Deleting originals
- Default keeps originals.
- To delete after successful encrypt/decrypt: `--delete-original --i-understand`.

## Shell tab completion
Shells do not provide option completion by default. This repo includes completion scripts:

- Bash: `completions/docseal.bash`
- Zsh: `completions/docseal.zsh`
- PowerShell: `completions/docseal.ps1`

### Enable on Bash (Kali)
```
source completions/docseal.bash
```
To make it permanent, add that line to `~/.bashrc`.

### Enable on Zsh
```
fpath=(./completions $fpath)
autoload -U compinit && compinit
```

### Enable on PowerShell
```
. .\completions\docseal.ps1
```
To make it permanent, add the line to your PowerShell profile.

## Best practices
- Use long, unique passwords or passphrases.
- Store encrypted files on an encrypted disk when possible.
- Keep your OS updated and avoid untrusted software.

## Exit codes
- `0` success
- `1` expected error (bad input, wrong password, tampered data)
- `2` unexpected error (only with `--debug` for traces)

