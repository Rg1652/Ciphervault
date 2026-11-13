# CipherVault - Military-Grade File Encrypter & Decrypter

**CipherVault** is an advanced, high-security, but simple and sleek file encryption and decryption desktop application for Windows.

Packaged as a standalone single **`.exe`** file, CipherVault requires no installation or external runtimes.

---

## Key Features

### 1. Advanced Cryptography

- **Authenticated Encryption (AEAD)**:
  - **AES-256-GCM** (NIST Recommended, 256-bit key with 128-bit authentication tag)
  - **ChaCha20-Poly1305** (RFC 8439 high-performance stream cipher)
- **State-of-the-Art Key Derivation**:
  - **Argon2id** (Memory-hard PHC winner, resistant to GPU/ASIC brute-force attacks)
  - **PBKDF2-HMAC-SHA256** (600,000 rounds for maximum compatibility)
- **Chunked AEAD Streaming (1 MB Blocks)**:
  - Supports files of any size (from a few bytes to 100+ GB) with constant, minimal memory usage (~20 MB RAM).
  - Every block is cryptographically bound to its chunk index and completion flag, preventing chunk reordering, bit-flipping, or truncation attacks.
- **Immediate Authentication Check**:
  - Wrong password or corrupted files are caught immediately within milliseconds, before writing any bad data to disk.
- **Two-Factor Protection (Password + Physical Keyfile)**:
  - Combine your master password with a physical cryptographic keyfile (`.key`) for true multi-factor encryption.

### 2. Sleek, Modern User Interface

- **Dark Obsidian Aesthetics**: Clean, high-contrast dark theme with electric cyan and royal azure accents.
- **Windows Explorer Drag & Drop**: Drag and drop any files or folders directly into the app window.
- **Live Password Strength Evaluator**: Real-time Shannon entropy calculation (bits), cracking time estimation, and visual strength bar.
- **Dynamic Progress & Transfer Speed**: Shows transfer throughput (MB/s), percentage, and bytes processed in real-time.

### 3. Integrated Security Tools

- **Key Studio**:
  - Cryptographically secure password generator (Token, Diceware Passphrase, and 256-bit Hex modes).
  - Physical 512-bit keyfile generator (`.key`).
  - Interactive password testing lab.
- **Secure File Shredder**:
  - Multi-pass file obliteration compliant with **DoD 5220.22-M** (CSPRNG Random -> Bit Inversion -> Zero Fill).
  - Overwrites data, flushes hardware buffers, scrambles file names, and permanently unlinks files to prevent data recovery by forensics tools.
- **Comprehensive Activity & Audit Log**:
  - Real-time timestamps, encryption speeds, file sizes, and verification logs.

---

## How to Run

Simply double-click:

```
CipherVault.exe
```

No Python, dependencies, or installers are required.

---

## 🔒 Encrypted File Format (`.cvault`)

```
+-----------------------------------------------------------+
| Magic Bytes: 'CVLT' (4 bytes)                             |
| Version: 0x01 (1 byte)                                    |
| Cipher Suite ID: 1=AES-256-GCM, 2=ChaCha20-Poly1305       |
| KDF Suite ID: 1=Argon2id, 2=PBKDF2-SHA256                 |
| KDF Salt: 16 bytes CSPRNG                                 |
| Base Nonce: 12 bytes CSPRNG                               |
+-----------------------------------------------------------+
| Encrypted Metadata Chunk (JSON: filename, size, keyfile)   |
+-----------------------------------------------------------+
| Chunk 1: [4-byte len] + [1MB Ciphertext + 16-byte Tag]    |
| Chunk 2: [4-byte len] + [1MB Ciphertext + 16-byte Tag]    |
| ...                                                       |
| Chunk N (Final): [4-byte len] + [Ciphertext + Tag]        |
+-----------------------------------------------------------+
```
