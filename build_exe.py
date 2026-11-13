"""
CipherVault Standalone Executable Builder
Compiles the application into a single self-contained Windows .exe using PyInstaller.
"""

import os
import sys
import shutil
import subprocess

def build():
    print("==================================================")
    print("      CipherVault Windows Executable Builder      ")
    print("==================================================")

    # 1. Ensure icons exist
    if not os.path.exists("assets/icon.ico"):
        print("[1/4] Generating application icons...")
        import generate_icon
        generate_icon.create_cipher_icon()
    else:
        print("[1/4] Application icons verified.")

    # 2. Prepare PyInstaller command
    print("[2/4] Configuring PyInstaller build parameters...")
    ico_path = os.path.join("assets", "icon.ico")
    assets_data = "assets;assets"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=CipherVault",
        "--onefile",
        "--windowed",
        f"--icon={ico_path}",
        f"--add-data={assets_data}",
        "--collect-all=customtkinter",
        "--hidden-import=cryptography",
        "--hidden-import=cryptography.hazmat.primitives.ciphers.aead",
        "--hidden-import=cryptography.hazmat.primitives.kdf.argon2",
        "--hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2",
        "--clean",
        "--noconfirm",
        "app.py"
    ]

    # 3. Execute build
    print("[3/4] Compiling CipherVault.exe (this may take ~30-60 seconds)...")
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"ERROR: Build failed with exit code {res.returncode}")
        sys.exit(res.returncode)

    # 4. Copy to root directory for easy access
    dist_exe = os.path.join("dist", "CipherVault.exe")
    root_exe = os.path.join(os.getcwd(), "CipherVault.exe")
    if os.path.exists(dist_exe):
        shutil.copy2(dist_exe, root_exe)
        size_mb = os.path.getsize(root_exe) / (1024 * 1024)
        print("==================================================")
        print(f"BUILD SUCCESSFUL!")
        print(f"Standalone Executable: {root_exe}")
        print(f"Size: {size_mb:.2f} MB")
        print("==================================================")
    else:
        print("ERROR: dist/CipherVault.exe was not found after build.")
        sys.exit(1)

if __name__ == "__main__":
    build()
