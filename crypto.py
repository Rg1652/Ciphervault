"""
CipherVault Core Cryptographic Engine
Supports AES-256-GCM and ChaCha20-Poly1305 with Argon2id and PBKDF2-SHA256.
Provides chunked AEAD streaming to handle files of any size with minimal RAM.
"""

import os
import struct
import json
import time
import hashlib
from typing import Callable, Optional, Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants
MAGIC_HEADER = b"CVLT"
CURRENT_VERSION = 1

CIPHER_AES_256_GCM = 1
CIPHER_CHACHA20_POLY1305 = 2

KDF_ARGON2ID = 1
KDF_PBKDF2_SHA256 = 2

CHUNK_SIZE = 1024 * 1024  # 1 MB chunk size
SALT_SIZE = 16
NONCE_SIZE = 12

CIPHER_NAMES = {
    CIPHER_AES_256_GCM: "AES-256-GCM (NIST Authenticated)",
    CIPHER_CHACHA20_POLY1305: "ChaCha20-Poly1305 (RFC 8439)",
}

KDF_NAMES = {
    KDF_ARGON2ID: "Argon2id (Memory-Hard, PHC Winner)",
    KDF_PBKDF2_SHA256: "PBKDF2-HMAC-SHA256 (600,000 rounds)",
}


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class AuthenticationError(CryptoError):
    """Raised when password/keyfile is incorrect or data was tampered with."""
    pass


class FileFormatError(CryptoError):
    """Raised when the file is not a valid CipherVault encrypted file."""
    pass


def derive_nonce(base_nonce: bytes, index: int) -> bytes:
    """
    Derive a deterministic 96-bit nonce from base_nonce and an incrementing chunk index.
    base_nonce is 12 bytes; we use first 4 bytes as prefix, and last 8 bytes as big-endian counter.
    """
    base_counter = struct.unpack(">Q", base_nonce[4:])[0]
    counter = (base_counter + index) & 0xFFFFFFFFFFFFFFFF
    return base_nonce[:4] + struct.pack(">Q", counter)


def derive_key(
    password: str,
    salt: bytes,
    kdf_id: int = KDF_ARGON2ID,
    keyfile_bytes: Optional[bytes] = None
) -> bytes:
    """
    Derive a 256-bit symmetric key from password and optional keyfile bytes.
    """
    secret = password.encode("utf-8")
    if keyfile_bytes:
        # Mix in SHA-256 of the keyfile bytes
        keyfile_digest = hashlib.sha256(keyfile_bytes).digest()
        secret = secret + keyfile_digest

    if kdf_id == KDF_ARGON2ID:
        # Argon2id with 64 MB memory cost, 3 iterations, 4 lanes
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536
        )
        return kdf.derive(secret)
    elif kdf_id == KDF_PBKDF2_SHA256:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000
        )
        return kdf.derive(secret)
    else:
        raise ValueError(f"Unknown KDF ID: {kdf_id}")


def encrypt_file(
    source_path: str,
    output_path: str,
    password: str,
    cipher_id: int = CIPHER_AES_256_GCM,
    kdf_id: int = KDF_ARGON2ID,
    keyfile_bytes: Optional[bytes] = None,
    progress_callback: Optional[Callable[[int, int, float], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None
) -> Dict[str, Any]:
    """
    Encrypt a file using chunked AEAD with authenticated metadata.
    Returns metadata dict on success.
    """
    if not os.path.isfile(source_path):
        raise FileNotFoundError(f"Source file not found: {source_path}")

    file_size = os.path.getsize(source_path)
    original_filename = os.path.basename(source_path)

    salt = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt, kdf_id, keyfile_bytes)

    cipher_cls = AESGCM if cipher_id == CIPHER_AES_256_GCM else ChaCha20Poly1305
    cipher = cipher_cls(key)

    metadata = {
        "filename": original_filename,
        "size": file_size,
        "created": int(time.time()),
        "has_keyfile": keyfile_bytes is not None,
        "cipher": CIPHER_NAMES.get(cipher_id, "Unknown"),
        "kdf": KDF_NAMES.get(kdf_id, "Unknown"),
    }
    metadata_bytes = json.dumps(metadata).encode("utf-8")

    # Encrypt metadata in Chunk 0
    meta_nonce = derive_nonce(base_nonce, 0)
    enc_metadata = cipher.encrypt(meta_nonce, metadata_bytes, b"CVLT_META_V1")

    # Output file handling
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    temp_output = output_path + ".cvtmp"

    start_time = time.time()
    last_time = start_time
    last_processed = 0

    try:
        with open(source_path, "rb") as fin, open(temp_output, "wb") as fout:
            # Write Header
            fout.write(MAGIC_HEADER)
            fout.write(struct.pack(">BBB", CURRENT_VERSION, cipher_id, kdf_id))
            fout.write(salt)
            fout.write(base_nonce)
            fout.write(struct.pack(">I", len(enc_metadata)))
            fout.write(enc_metadata)

            chunk_idx = 1
            processed_bytes = 0

            # Special case for 0-byte file
            if file_size == 0:
                nonce = derive_nonce(base_nonce, 1)
                aad = b"CVLT_CHUNK_" + struct.pack(">Q", 1) + b"\x01"
                enc_chunk = cipher.encrypt(nonce, b"", aad)
                fout.write(struct.pack(">I", len(enc_chunk)))
                fout.write(enc_chunk)
                if progress_callback:
                    progress_callback(0, 0, 0.0)
            else:
                while True:
                    if cancel_check and cancel_check():
                        raise InterruptedError("Encryption cancelled by user.")

                    chunk_data = fin.read(CHUNK_SIZE)
                    if not chunk_data:
                        break

                    # Check if next byte exists to determine if this is the last chunk
                    next_peek = fin.read(1)
                    is_final = False
                    if not next_peek:
                        is_final = True
                    else:
                        fin.seek(-1, os.SEEK_CUR)

                    nonce = derive_nonce(base_nonce, chunk_idx)
                    aad = b"CVLT_CHUNK_" + struct.pack(">Q", chunk_idx) + (b"\x01" if is_final else b"\x00")
                    enc_chunk = cipher.encrypt(nonce, chunk_data, aad)

                    fout.write(struct.pack(">I", len(enc_chunk)))
                    fout.write(enc_chunk)

                    processed_bytes += len(chunk_data)

                    now = time.time()
                    elapsed = now - last_time
                    if elapsed >= 0.1 or is_final:
                        speed = (processed_bytes - last_processed) / (elapsed * 1024 * 1024) if elapsed > 0 else 0.0
                        if progress_callback:
                            progress_callback(processed_bytes, file_size, speed)
                        last_time = now
                        last_processed = processed_bytes

                    chunk_idx += 1
                    if is_final:
                        break

        # Atomically move temp output to final destination
        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(temp_output, output_path)

        total_elapsed = time.time() - start_time
        metadata["encrypted_size"] = os.path.getsize(output_path)
        metadata["elapsed_seconds"] = total_elapsed
        return metadata

    except Exception:
        if os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except OSError:
                pass
        raise


def decrypt_file(
    source_path: str,
    output_dir: str,
    password: str,
    keyfile_bytes: Optional[bytes] = None,
    progress_callback: Optional[Callable[[int, int, float], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Decrypt a CipherVault file.
    Restores original filename inside output_dir.
    Returns (restored_file_path, metadata_dict).
    """
    if not os.path.isfile(source_path):
        raise FileNotFoundError(f"Encrypted file not found: {source_path}")

    with open(source_path, "rb") as fin:
        magic = fin.read(4)
        if magic != MAGIC_HEADER:
            raise FileFormatError("Not a valid CipherVault encrypted file (invalid header).")

        version_data = fin.read(3)
        if len(version_data) < 3:
            raise FileFormatError("File header is truncated.")
        version, cipher_id, kdf_id = struct.unpack(">BBB", version_data)

        if version != CURRENT_VERSION:
            raise FileFormatError(f"Unsupported file version: {version}")
        if cipher_id not in (CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305):
            raise FileFormatError(f"Unsupported cipher ID: {cipher_id}")
        if kdf_id not in (KDF_ARGON2ID, KDF_PBKDF2_SHA256):
            raise FileFormatError(f"Unsupported KDF ID: {kdf_id}")

        salt = fin.read(SALT_SIZE)
        base_nonce = fin.read(NONCE_SIZE)
        if len(salt) < SALT_SIZE or len(base_nonce) < NONCE_SIZE:
            raise FileFormatError("Corrupted file header parameters.")

        meta_len_bytes = fin.read(4)
        if len(meta_len_bytes) < 4:
            raise FileFormatError("Truncated metadata size.")
        meta_len = struct.unpack(">I", meta_len_bytes)[0]

        enc_meta = fin.read(meta_len)
        if len(enc_meta) < meta_len:
            raise FileFormatError("Truncated encrypted metadata.")

        # Derive key
        key = derive_key(password, salt, kdf_id, keyfile_bytes)
        cipher_cls = AESGCM if cipher_id == CIPHER_AES_256_GCM else ChaCha20Poly1305
        cipher = cipher_cls(key)

        # Attempt metadata decryption
        meta_nonce = derive_nonce(base_nonce, 0)
        try:
            meta_bytes = cipher.decrypt(meta_nonce, enc_meta, b"CVLT_META_V1")
        except Exception:
            raise AuthenticationError(
                "Authentication failed: Incorrect password, missing/invalid keyfile, or file has been tampered with."
            )

        try:
            metadata = json.loads(meta_bytes.decode("utf-8"))
        except Exception:
            raise FileFormatError("Corrupted metadata payload.")

        raw_filename = metadata.get("filename", "decrypted_file")
        # Sanitize against path traversal attacks
        safe_filename = os.path.basename(raw_filename.replace("\\", "/"))
        if not safe_filename:
            safe_filename = "decrypted_file"

        original_size = metadata.get("size", 0)

        os.makedirs(output_dir, exist_ok=True)
        final_output_path = os.path.join(output_dir, safe_filename)

        # Handle filename collisions cleanly if needed
        base_name, ext = os.path.splitext(safe_filename)
        counter = 1
        while os.path.exists(final_output_path) and os.path.abspath(final_output_path) != os.path.abspath(source_path):
            final_output_path = os.path.join(output_dir, f"{base_name} ({counter}){ext}")
            counter += 1

        temp_output = final_output_path + ".cvtmp"
        start_time = time.time()
        last_time = start_time
        last_processed = 0

        try:
            with open(temp_output, "wb") as fout:
                chunk_idx = 1
                processed_bytes = 0
                observed_final = False

                while True:
                    if cancel_check and cancel_check():
                        raise InterruptedError("Decryption cancelled by user.")

                    len_bytes = fin.read(4)
                    if not len_bytes:
                        if not observed_final and original_size > 0:
                            raise AuthenticationError("File was prematurely truncated (missing final authentication block).")
                        break

                    chunk_len = struct.unpack(">I", len_bytes)[0]
                    enc_chunk = fin.read(chunk_len)
                    if len(enc_chunk) < chunk_len:
                        raise AuthenticationError("Truncated data block encountered.")

                    nonce = derive_nonce(base_nonce, chunk_idx)
                    dec_data = None

                    # Try intermediate then final chunk AAD
                    for is_final in (False, True):
                        aad = b"CVLT_CHUNK_" + struct.pack(">Q", chunk_idx) + (b"\x01" if is_final else b"\x00")
                        try:
                            dec_data = cipher.decrypt(nonce, enc_chunk, aad)
                            if is_final:
                                observed_final = True
                            break
                        except Exception:
                            continue

                    if dec_data is None:
                        raise AuthenticationError(
                            f"Block {chunk_idx} authentication failed: Data was modified, corrupted, or tampered."
                        )

                    fout.write(dec_data)
                    processed_bytes += len(dec_data)

                    now = time.time()
                    elapsed = now - last_time
                    if elapsed >= 0.1:
                        speed = (processed_bytes - last_processed) / (elapsed * 1024 * 1024) if elapsed > 0 else 0.0
                        if progress_callback:
                            progress_callback(processed_bytes, original_size, speed)
                        last_time = now
                        last_processed = processed_bytes

                    chunk_idx += 1
                    if observed_final:
                        # Ensure no extraneous junk data trailing after the final block
                        extra = fin.read(1)
                        if extra:
                            raise AuthenticationError("Extraneous unauthenticated bytes detected at end of file.")
                        break

            if os.path.exists(final_output_path):
                os.remove(final_output_path)
            os.rename(temp_output, final_output_path)

            total_elapsed = time.time() - start_time
            metadata["restored_path"] = final_output_path
            metadata["elapsed_seconds"] = total_elapsed
            return final_output_path, metadata

        except Exception:
            if os.path.exists(temp_output):
                try:
                    os.remove(temp_output)
                except OSError:
                    pass
            raise
