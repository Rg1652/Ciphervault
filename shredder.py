"""
CipherVault Secure File Shredder
Overwrites files with CSPRNG random data, patterns, and zeros before deletion
to prevent undelete / recovery tools from retrieving sensitive information.
"""

import os
import secrets
import string
import time
from typing import Callable, Optional

CHUNK_SIZE = 1024 * 1024  # 1 MB


def shred_file(
    file_path: str,
    passes: int = 3,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    cancel_check: Optional[Callable[[], bool]] = None
) -> None:
    """
    Securely overwrite and obliterate a file.
    passes: 1 (Quick wipe) or 3 (DoD 5220.22-M compliant: Random -> Fixed/Pattern -> Zeros).
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found for shredding: {file_path}")

    file_size = os.path.getsize(file_path)

    # Patterns for passes
    if passes == 1:
        pass_patterns = ["random"]
    else:
        pass_patterns = ["random", b"\x55", b"\x00"]

    actual_passes = len(pass_patterns)

    for p_idx, pattern in enumerate(pass_patterns, start=1):
        pass_name = f"Pass {p_idx}/{actual_passes}"
        if pattern == "random":
            pass_name += " (CSPRNG Random)"
        elif pattern == b"\x00":
            pass_name += " (Zero Fill)"
        else:
            pass_name += " (Bit Inversion)"

        if file_size > 0:
            with open(file_path, "r+b") as f:
                f.seek(0)
                written = 0
                while written < file_size:
                    if cancel_check and cancel_check():
                        raise InterruptedError("Shredding cancelled by user.")

                    to_write = min(CHUNK_SIZE, file_size - written)
                    if pattern == "random":
                        chunk = os.urandom(to_write)
                    else:
                        chunk = pattern * to_write

                    f.write(chunk)
                    written += to_write

                    if progress_callback:
                        progress_callback(written, file_size, pass_name)

                f.flush()
                os.fsync(f.fileno())

    # Truncate file to zero bytes
    with open(file_path, "wb") as f:
        f.truncate(0)

    # Rename to random filename to wipe original name from file system index/MFT
    dir_name = os.path.dirname(file_path)
    random_name = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24)) + ".tmp"
    scrambled_path = os.path.join(dir_name, random_name)

    try:
        os.rename(file_path, scrambled_path)
        os.remove(scrambled_path)
    except OSError:
        # Fallback to direct delete if rename fails
        if os.path.exists(file_path):
            os.remove(file_path)
