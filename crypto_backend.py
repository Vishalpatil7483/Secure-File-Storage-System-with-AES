"""
crypto_backend.py

Hybrid file encryption for large files:
- Generate a random file_key (32 bytes).
- Encrypt file contents using AES-CTR (streaming-friendly) with file_key.
- Compute HMAC-SHA256 over metadata + ciphertext for integrity.
- Wrap (encrypt) file_key with a key-encryption-key (KEK) derived from password using PBKDF2.
- Store metadata JSON wrapper with base64 fields and chunking info.

Format:
{
  "version": "SFV1",
  "filename": "original.name",
  "filesize": 12345,
  "salt": "<b64>",                # for PBKDF2
  "kdf_iters": 300_000,
  "wrapped_key": "<b64>",        # AES-GCM encrypted file_key (with nonce included)
  "cipher_iv": "<b64>",          # AES-CTR IV used for stream encryption
  "hmac": "<b64>",               # HMAC-SHA256 over (metadata + ciphertext)
  "chunk_size": 65536,
  "ciphertext": "<b64>"          # the full ciphertext as a binary blob (streamed in writing)
}

Notes:
- This stores the full ciphertext inline for simplicity. For huge files you can store ciphertext separately.
- Password is never stored.
"""

import os
import json
import base64
import time
from typing import Tuple
from hashlib import sha256

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Config
KDF_ITERS = 300_000
SALT_SIZE = 16
FILE_KEY_SIZE = 32          # 256-bit file key
WRAP_NONCE_SIZE = 12        # AES-GCM nonce
CTR_IV_SIZE = 16            # 128-bit IV for AES-CTR (unique)
CHUNK_SIZE = 64 * 1024      # 64 KB chunks


def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode("utf-8")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def derive_kek(password: str, salt: bytes, iterations: int = KDF_ITERS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def wrap_file_key(file_key: bytes, kek: bytes) -> Tuple[bytes, bytes]:
    """Encrypt file_key with KEK using AES-GCM. Returns (nonce, ct)."""
    aesgcm = AESGCM(kek)
    nonce = os.urandom(WRAP_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, file_key, None)
    return nonce, ct


def unwrap_file_key(nonce: bytes, ct: bytes, kek: bytes) -> bytes:
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ct, None)


def stream_encrypt_file(in_path: str, out_path: str, password: str, chunk_size: int = CHUNK_SIZE):
    """
    Encrypts file at in_path and writes JSON wrapper (including ciphertext) to out_path.
    For simplicity we put ciphertext into the JSON file as base64; for very large files,
    store ciphertext externally and reference it from metadata.
    """
    if not os.path.isfile(in_path):
        raise FileNotFoundError("Input file not found")

    salt = os.urandom(SALT_SIZE)
    kek = derive_kek(password, salt)
    file_key = os.urandom(FILE_KEY_SIZE)

    # Wrap file_key with KEK (AES-GCM)
    wrap_nonce, wrapped_key = wrap_file_key(file_key, kek)

    # Prepare AES-CTR cipher for streaming encryption
    iv = os.urandom(CTR_IV_SIZE)
    cipher = Cipher(algorithms.AES(file_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # HMAC to authenticate metadata + ciphertext
    h = hmac.HMAC(file_key, hashes.SHA256(), backend=default_backend())

    # Stream encrypt
    ciphertext_parts = []
    total_read = 0
    sz = os.path.getsize(in_path)
    with open(in_path, "rb") as fin:
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            total_read += len(chunk)
            ct_chunk = encryptor.update(chunk)
            ciphertext_parts.append(ct_chunk)
            h.update(ct_chunk)

    # finalize (no finalize tag for CTR)
    final = encryptor.finalize()
    if final:
        ciphertext_parts.append(final)
        h.update(final)

    # compute hmac
    digest = h.finalize()

    # Build metadata
    md = {
        "version": "SFV1",
        "filename": os.path.basename(in_path),
        "filesize": sz,
        "timestamp": int(time.time()),
        "salt": _b64(salt),
        "kdf_iters": KDF_ITERS,
        "wrapped_key": _b64(wrapped_key),
        "wrap_nonce": _b64(wrap_nonce),
        "cipher_iv": _b64(iv),
        "hmac": _b64(digest),
        "chunk_size": chunk_size,
    }

    # Concatenate ciphertext and base64 encode
    ciphertext = b"".join(ciphertext_parts)
    md["ciphertext"] = _b64(ciphertext)

    # Write JSON wrapper
    with open(out_path, "w") as fw:
        json.dump(md, fw)

    return out_path


def stream_decrypt_file(enc_path: str, out_path: str, password: str, chunk_size: int = CHUNK_SIZE):
    """
    Decrypt JSON wrapper file and write plaintext to out_path.
    Verifies HMAC before writing data to disk.
    """
    if not os.path.isfile(enc_path):
        raise FileNotFoundError("Encrypted file not found")

    with open(enc_path, "r") as fr:
        md = json.load(fr)

    if md.get("version") != "SFV1":
        raise ValueError("Unsupported format")

    salt = _unb64(md["salt"])
    wrapped_key = _unb64(md["wrapped_key"])
    wrap_nonce = _unb64(md["wrap_nonce"])
    iv = _unb64(md["cipher_iv"])
    expected_hmac = _unb64(md["hmac"])
    ciphertext = _unb64(md["ciphertext"])
    filesize = md.get("filesize", None)

    kek = derive_kek(password, salt)
    file_key = unwrap_file_key(wrap_nonce, wrapped_key, kek)

    # Verify HMAC
    h = hmac.HMAC(file_key, hashes.SHA256(), backend=default_backend())
    # For streaming, update in chunks
    for i in range(0, len(ciphertext), chunk_size):
        h.update(ciphertext[i:i+chunk_size])
    try:
        h.verify(expected_hmac)
    except Exception as e:
        raise ValueError("Integrity check failed - wrong password or file tampered") from e

    # Decrypt via AES-CTR
    cipher = Cipher(algorithms.AES(file_key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    with open(out_path, "wb") as fw:
        for i in range(0, len(ciphertext), chunk_size):
            ct_chunk = ciphertext[i:i+chunk_size]
            pt = decryptor.update(ct_chunk)
            fw.write(pt)
        final = decryptor.finalize()
        if final:
            fw.write(final)

    return out_path
