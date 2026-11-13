"""
CipherVault - Advanced File Encrypter and Decrypter
Main Application Entry Point
"""

import os
import sys
import ctypes
import customtkinter as ctk

# Enable High-DPI Awareness on Windows
if sys.platform == "win32":
    try:
        # Per-Monitor (V2) DPI awareness
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            # Fallback to system DPI awareness
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

from ui.main_window import CipherVaultApp


def main():
    # Set Theme & Appearance
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")

    app = CipherVaultApp()

    # Apply application icon
    if getattr(sys, "frozen", False):
        base_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    ico_path = os.path.join(base_dir, "assets", "icon.ico")
    if os.path.exists(ico_path):
        try:
            app.iconbitmap(ico_path)
        except Exception:
            pass

    # Windows 10/11 Dark Title Bar styling
    if sys.platform == "win32":
        try:
            hwnd = app.winfo_id()
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            rendering_policy = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(rendering_policy),
                ctypes.sizeof(rendering_policy)
            )
        except Exception:
            pass

    app.mainloop()


if __name__ == "__main__":
    main()
