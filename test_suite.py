"""
CipherVault Comprehensive Test Suite
Validates cryptography, key derivation, streaming, shredding, and edge cases.
"""

import os
import unittest
import tempfile
import shutil
from core.crypto import (
    encrypt_file, decrypt_file, CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305,
    KDF_ARGON2ID, KDF_PBKDF2_SHA256, AuthenticationError, FileFormatError
)
from core.shredder import shred_file
from core.keys import (
    generate_complex_password, generate_passphrase, generate_hex_key,
    generate_keyfile, evaluate_password_strength
)

class TestCipherVault(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.password = "demo_test_suite_key_2026_only!"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_aes_gcm_argon2id(self):
        """Test standard AES-256-GCM with Argon2id."""
        src = os.path.join(self.test_dir, "sample.txt")
        enc = os.path.join(self.test_dir, "sample.txt.cvault")
        out_dir = os.path.join(self.test_dir, "restored")

        data = b"Automated test suite payload data block.\n" * 1000
        with open(src, "wb") as f:
            f.write(data)

        meta = encrypt_file(src, enc, self.password, cipher_id=CIPHER_AES_256_GCM, kdf_id=KDF_ARGON2ID)
        self.assertEqual(meta["filename"], "sample.txt")

        restored_path, dec_meta = decrypt_file(enc, out_dir, self.password)
        with open(restored_path, "rb") as f:
            restored_data = f.read()

        self.assertEqual(data, restored_data)

    def test_chacha20_pbkdf2(self):
        """Test ChaCha20-Poly1305 with PBKDF2-SHA256."""
        src = os.path.join(self.test_dir, "chacha.bin")
        enc = os.path.join(self.test_dir, "chacha.cvault")
        out_dir = os.path.join(self.test_dir, "restored_chacha")

        data = os.urandom(250000)  # 250 KB random binary
        with open(src, "wb") as f:
            f.write(data)

        encrypt_file(src, enc, self.password, cipher_id=CIPHER_CHACHA20_POLY1305, kdf_id=KDF_PBKDF2_SHA256)
        restored_path, _ = decrypt_file(enc, out_dir, self.password)

        with open(restored_path, "rb") as f:
            restored_data = f.read()

        self.assertEqual(data, restored_data)

    def test_two_factor_keyfile(self):
        """Test Two-Factor (Password + Keyfile) encryption."""
        src = os.path.join(self.test_dir, "test_document.bin")
        enc = os.path.join(self.test_dir, "test_document.bin.cvault")
        kf_path = os.path.join(self.test_dir, "test_keyfile.key")
        out_dir = os.path.join(self.test_dir, "restored_kf")

        data = b"Test payload data protected by password and physical keyfile"
        with open(src, "wb") as f:
            f.write(data)

        generate_keyfile(kf_path)
        with open(kf_path, "rb") as f:
            kf_bytes = f.read()

        encrypt_file(src, enc, self.password, keyfile_bytes=kf_bytes)

        # Decrypting without keyfile must fail
        with self.assertRaises(AuthenticationError):
            decrypt_file(enc, out_dir, self.password, keyfile_bytes=None)

        # Decrypting with wrong keyfile must fail
        wrong_kf_bytes = b"wrong keyfile data"
        with self.assertRaises(AuthenticationError):
            decrypt_file(enc, out_dir, self.password, keyfile_bytes=wrong_kf_bytes)

        # Decrypting with correct keyfile succeeds
        restored_path, _ = decrypt_file(enc, out_dir, self.password, keyfile_bytes=kf_bytes)
        with open(restored_path, "rb") as f:
            self.assertEqual(data, f.read())

    def test_wrong_password(self):
        """Test wrong password causes immediate authentication failure."""
        src = os.path.join(self.test_dir, "test_file.txt")
        enc = os.path.join(self.test_dir, "test_file.txt.cvault")
        out_dir = os.path.join(self.test_dir, "restored")

        with open(src, "wb") as f:
            f.write(b"Unit test payload data.")

        encrypt_file(src, enc, "TestDemoPass_Alpha!")

        with self.assertRaises(AuthenticationError):
            decrypt_file(enc, out_dir, "TestDemoPass_Beta!")

    def test_tamper_detection(self):
        """Test that altering a single byte in ciphertext fails authentication."""
        src = os.path.join(self.test_dir, "tamper_test.txt")
        enc = os.path.join(self.test_dir, "tamper_test.txt.cvault")
        out_dir = os.path.join(self.test_dir, "restored")

        with open(src, "wb") as f:
            f.write(b"Data before tampering." * 100)

        encrypt_file(src, enc, self.password)

        # Read encrypted file, flip 1 byte in the body, and rewrite
        with open(enc, "r+b") as f:
            f.seek(-10, os.SEEK_END)
            val = f.read(1)
            f.seek(-10, os.SEEK_END)
            f.write(bytes([val[0] ^ 0xFF]))

        with self.assertRaises(AuthenticationError):
            decrypt_file(enc, out_dir, self.password)

    def test_zero_byte_file(self):
        """Test empty 0-byte file edge case."""
        src = os.path.join(self.test_dir, "empty.txt")
        enc = os.path.join(self.test_dir, "empty.txt.cvault")
        out_dir = os.path.join(self.test_dir, "restored")

        with open(src, "wb") as f:
            pass

        encrypt_file(src, enc, self.password)
        restored_path, _ = decrypt_file(enc, out_dir, self.password)

        self.assertTrue(os.path.exists(restored_path))
        self.assertEqual(os.path.getsize(restored_path), 0)

    def test_multi_chunk_file(self):
        """Test multi-megabyte file spanning multiple 1MB chunks."""
        src = os.path.join(self.test_dir, "large.bin")
        enc = os.path.join(self.test_dir, "large.cvault")
        out_dir = os.path.join(self.test_dir, "restored")

        # 3.5 MB
        data = b"0123456789ABCDEF" * (220 * 1024)
        with open(src, "wb") as f:
            f.write(data)

        encrypt_file(src, enc, self.password)
        restored_path, _ = decrypt_file(enc, out_dir, self.password)

        with open(restored_path, "rb") as f:
            restored = f.read()

        self.assertEqual(len(data), len(restored))
        self.assertEqual(data, restored)

    def test_shredder(self):
        """Test secure file shredder obliteration."""
        src = os.path.join(self.test_dir, "to_shred.txt")
        with open(src, "wb") as f:
            f.write(b"Automated dummy sample data block for shredder test." * 500)

        self.assertTrue(os.path.exists(src))
        shred_file(src, passes=3)
        self.assertFalse(os.path.exists(src))

    def test_keys_and_strength(self):
        """Test password generator and strength evaluator."""
        pwd = generate_complex_password(32)
        self.assertEqual(len(pwd), 32)

        passphrase = generate_passphrase(5)
        words = passphrase.split("-")
        self.assertEqual(len(words), 5)

        stats = evaluate_password_strength("weak")
        self.assertEqual(stats["label"], "Very Weak")

        stats_strong = evaluate_password_strength(pwd)
        self.assertIn(stats_strong["label"], ("Strong", "Military-Grade"))

if __name__ == "__main__":
    unittest.main()
