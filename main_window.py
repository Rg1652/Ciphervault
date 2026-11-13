"""
CipherVault Main Application Window
Modern, sleek, and intuitive UI for file encryption, decryption, password generation, and file shredding.
"""

import os
import sys
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from typing import List, Optional, Dict, Any

from ui.theme import Theme
from ui.widgets import (
    PasswordStrengthWidget, FileItemCard, DropZoneWidget, format_bytes
)
from core.crypto import (
    encrypt_file, decrypt_file, CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305,
    KDF_ARGON2ID, KDF_PBKDF2_SHA256, AuthenticationError, FileFormatError
)
from core.shredder import shred_file
from core.keys import (
    generate_complex_password, generate_passphrase, generate_hex_key,
    generate_keyfile, evaluate_password_strength
)
from core.native_dnd import WindowsDragDropHandler


class CipherVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Configuration
        self.title("CipherVault - Advanced File Encrypter & Decrypter")
        self.geometry("980x740")
        self.minsize(860, 640)
        self.configure(fg_color=Theme.BG_ROOT)

        # State Variables
        self.encrypt_files: List[str] = []
        self.decrypt_files: List[str] = []
        self.shred_files: List[str] = []

        self.encrypt_keyfile: Optional[str] = None
        self.decrypt_keyfile: Optional[str] = None

        self.cancel_event = threading.Event()
        self.is_processing = False

        # Build UI
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        # Set up native Windows Drag & Drop
        self.dnd_handler = None
        self.after(200, self._init_drag_drop)

    def _init_drag_drop(self):
        """Initialize native Windows Explorer drag & drop."""
        try:
            hwnd = self.winfo_id()
            self.dnd_handler = WindowsDragDropHandler(hwnd, self._on_files_dropped)
        except Exception as e:
            self._log(f"Drag and drop initialization note: {e}")

    def _on_files_dropped(self, paths: List[str]):
        """Handle files dropped from Windows File Explorer."""
        if not paths:
            return

        current_tab = self.tabview.get()

        # Filter valid files/folders
        valid_files = []
        for p in paths:
            if os.path.isfile(p):
                valid_files.append(p)
            elif os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for f in files:
                        valid_files.append(os.path.join(root, f))

        if not valid_files:
            return

        if current_tab == "🔒 Encrypt":
            self._add_encrypt_files(valid_files)
        elif current_tab == "🔓 Decrypt":
            self._add_decrypt_files(valid_files)
        elif current_tab == "🛡️ File Shredder":
            self._add_shred_files(valid_files)
        else:
            # Check file extensions to intelligently route
            has_cvault = any(f.endswith(".cvault") for f in valid_files)
            if has_cvault:
                self.tabview.set("🔓 Decrypt")
                self._add_decrypt_files(valid_files)
            else:
                self.tabview.set("🔒 Encrypt")
                self._add_encrypt_files(valid_files)

    # ==========================================================
    # UI HEADER
    # ==========================================================
    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color=Theme.BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        left_frame = ctk.CTkFrame(header, fg_color="transparent")
        left_frame.pack(side="left", padx=20, pady=10)

        logo_label = ctk.CTkLabel(
            left_frame,
            text="🛡️",
            font=(Theme.FONT_FAMILY, 24),
            width=36
        )
        logo_label.pack(side="left", padx=(0, 10))

        title_box = ctk.CTkFrame(left_frame, fg_color="transparent")
        title_box.pack(side="left")

        app_title = ctk.CTkLabel(
            title_box,
            text="CIPHERVAULT",
            font=Theme.FONT_HERO,
            text_color=Theme.ACCENT_CYAN,
            anchor="w"
        )
        app_title.pack(anchor="w")

        app_subtitle = ctk.CTkLabel(
            title_box,
            text="Military-Grade Authenticated File Encryption & Decryption",
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="w"
        )
        app_subtitle.pack(anchor="w")

        right_frame = ctk.CTkFrame(header, fg_color="transparent")
        right_frame.pack(side="right", padx=20, pady=10)

        badge = ctk.CTkLabel(
            right_frame,
            text="AES-256-GCM  •  Argon2id",
            font=Theme.FONT_CODE_BOLD,
            fg_color=Theme.BG_INPUT,
            text_color=Theme.ACCENT_CYAN,
            corner_radius=6,
            padx=12,
            pady=4
        )
        badge.pack(side="right")

    # ==========================================================
    # TABVIEW
    # ==========================================================
    def _build_tabs(self):
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=Theme.BG_ROOT,
            segmented_button_fg_color=Theme.BG_CARD,
            segmented_button_selected_color=Theme.ACCENT_BLUE,
            segmented_button_selected_hover_color="#2563EB",
            segmented_button_unselected_color=Theme.BG_CARD,
            segmented_button_unselected_hover_color=Theme.BG_HOVER,
            text_color=Theme.TEXT_MAIN
        )
        self.tabview.pack(fill="both", expand=True, padx=16, pady=(10, 4))

        self.tab_encrypt = self.tabview.add("🔒 Encrypt")
        self.tab_decrypt = self.tabview.add("🔓 Decrypt")
        self.tab_keys = self.tabview.add("🔑 Key Studio")
        self.tab_shred = self.tabview.add("🛡️ File Shredder")
        self.tab_logs = self.tabview.add("📋 Activity Log")

        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_key_studio_tab()
        self._build_shredder_tab()
        self._build_logs_tab()

    # ==========================================================
    # TAB 1: ENCRYPT
    # ==========================================================
    def _build_encrypt_tab(self):
        tab = self.tab_encrypt
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # Top: Dropzone
        self.enc_dropzone = DropZoneWidget(
            tab,
            on_browse_files=self._browse_encrypt_files,
            on_browse_folder=self._browse_encrypt_folder,
            hint_text="Drag & drop files to ENCRYPT here, or browse"
        )
        self.enc_dropzone.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 8))

        # Middle: Selected Files List
        files_container = ctk.CTkFrame(tab, fg_color=Theme.BG_CARD, corner_radius=10)
        files_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=4)
        files_container.columnconfigure(0, weight=1)
        files_container.rowconfigure(1, weight=1)

        header_bar = ctk.CTkFrame(files_container, fg_color="transparent")
        header_bar.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 6))
        header_bar.columnconfigure(0, weight=1)

        self.enc_count_label = ctk.CTkLabel(
            header_bar,
            text="Selected Files (0 files • 0 B)",
            font=Theme.FONT_TITLE,
            text_color=Theme.TEXT_MAIN
        )
        self.enc_count_label.grid(row=0, column=0, sticky="w")

        btn_clear = ctk.CTkButton(
            header_bar,
            text="Clear All",
            font=Theme.FONT_SMALL,
            width=70,
            height=24,
            fg_color="transparent",
            hover_color=Theme.BG_HOVER,
            text_color=Theme.TEXT_MUTED,
            command=self._clear_encrypt_files
        )
        btn_clear.grid(row=0, column=1, sticky="e")

        self.enc_files_scroll = ctk.CTkScrollableFrame(
            files_container,
            fg_color="transparent"
        )
        self.enc_files_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Bottom: Credentials & Advanced Options Card
        options_card = ctk.CTkFrame(tab, fg_color=Theme.BG_CARD, corner_radius=10)
        options_card.grid(row=2, column=0, sticky="ew", padx=10, pady=(6, 6))
        options_card.columnconfigure(0, weight=1)

        # Password Entry Row
        pwd_frame = ctk.CTkFrame(options_card, fg_color="transparent")
        pwd_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))
        pwd_frame.columnconfigure(1, weight=1)

        ctk.CTkLabel(
            pwd_frame,
            text="Password:",
            font=Theme.FONT_BODY_BOLD,
            text_color=Theme.TEXT_MAIN,
            width=80,
            anchor="w"
        ).grid(row=0, column=0, sticky="w")

        self.enc_pwd_entry = ctk.CTkEntry(
            pwd_frame,
            font=Theme.FONT_BODY,
            fg_color=Theme.BG_INPUT,
            border_color=Theme.BORDER_SUBTLE,
            show="•",
            placeholder_text="Enter strong master encryption password..."
        )
        self.enc_pwd_entry.grid(row=0, column=1, sticky="ew", padx=(4, 8))
        self.enc_pwd_entry.bind("<KeyRelease>", self._on_enc_pwd_change)

        self.enc_pwd_show_btn = ctk.CTkButton(
            pwd_frame,
            text="👁️",
            width=36,
            height=32,
            fg_color=Theme.BG_INPUT,
            hover_color=Theme.BG_HOVER,
            command=self._toggle_enc_pwd_visibility
        )
        self.enc_pwd_show_btn.grid(row=0, column=2, padx=(0, 6))

        btn_gen = ctk.CTkButton(
            pwd_frame,
            text="🎲 Generate",
            font=Theme.FONT_BODY_BOLD,
            fg_color=Theme.BG_CARD_ALT,
            hover_color=Theme.BG_HOVER,
            border_width=1,
            border_color=Theme.BORDER_SUBTLE,
            text_color=Theme.ACCENT_CYAN,
            width=100,
            height=32,
            command=self._generate_and_fill_enc_password
        )
        btn_gen.grid(row=0, column=3)

        # Strength Meter
        self.enc_strength_widget = PasswordStrengthWidget(options_card)
        self.enc_strength_widget.grid(row=1, column=0, sticky="ew", padx=14, pady=(2, 8))

        # Advanced options frame
        adv_frame = ctk.CTkFrame(options_card, fg_color=Theme.BG_CARD_ALT, corner_radius=8)
        adv_frame.grid(row=2, column=0, sticky="ew", padx=14, pady=(4, 12))
        adv_frame.columnconfigure((0, 1, 2, 3), weight=1)

        # Cipher selection
        ctk.CTkLabel(adv_frame, text="Cipher:", font=Theme.FONT_SMALL, text_color=Theme.TEXT_MUTED).grid(row=0, column=0, sticky="w", padx=10, pady=(6, 2))
        self.enc_cipher_menu = ctk.CTkOptionMenu(
            adv_frame,
            values=["AES-256-GCM (NIST)", "ChaCha20-Poly1305"],
            fg_color=Theme.BG_INPUT,
            button_color=Theme.BG_HOVER,
            text_color=Theme.TEXT_MAIN,
            height=28
        )
        self.enc_cipher_menu.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))

        # KDF selection
        ctk.CTkLabel(adv_frame, text="Key Derivation:", font=Theme.FONT_SMALL, text_color=Theme.TEXT_MUTED).grid(row=0, column=1, sticky="w", padx=10, pady=(6, 2))
        self.enc_kdf_menu = ctk.CTkOptionMenu(
            adv_frame,
            values=["Argon2id (Memory-Hard)", "PBKDF2-SHA256 (600k)"],
            fg_color=Theme.BG_INPUT,
            button_color=Theme.BG_HOVER,
            text_color=Theme.TEXT_MAIN,
            height=28
        )
        self.enc_kdf_menu.grid(row=1, column=1, sticky="ew", padx=10, pady=(0, 8))

        # Keyfile toggle & browse
        ctk.CTkLabel(adv_frame, text="Two-Factor Keyfile:", font=Theme.FONT_SMALL, text_color=Theme.TEXT_MUTED).grid(row=0, column=2, sticky="w", padx=10, pady=(6, 2))
        keyfile_box = ctk.CTkFrame(adv_frame, fg_color="transparent")
        keyfile_box.grid(row=1, column=2, sticky="ew", padx=10, pady=(0, 8))
        keyfile_box.columnconfigure(0, weight=1)

        self.enc_keyfile_label = ctk.CTkLabel(
            keyfile_box,
            text="None (Optional)",
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="w"
        )
        self.enc_keyfile_label.grid(row=0, column=0, sticky="ew")

        self.enc_keyfile_btn = ctk.CTkButton(
            keyfile_box,
            text="Browse",
            font=Theme.FONT_SMALL,
            width=60,
            height=26,
            fg_color=Theme.BG_INPUT,
            hover_color=Theme.BG_HOVER,
            command=self._browse_enc_keyfile
        )
        self.enc_keyfile_btn.grid(row=0, column=1, padx=(4, 0))

        # Secure Shred Original Checkbox
        self.enc_shred_var = ctk.BooleanVar(value=False)
        self.enc_shred_cb = ctk.CTkCheckBox(
            adv_frame,
            text="Shred original file after encryption",
            variable=self.enc_shred_var,
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MAIN,
            fg_color=Theme.ACCENT_ROSE,
            hover_color="#BE123C"
        )
        self.enc_shred_cb.grid(row=1, column=3, sticky="w", padx=10, pady=(0, 8))

        # Encrypt Action Button
        self.btn_encrypt_action = ctk.CTkButton(
            tab,
            text="🔒 ENCRYPT FILES",
            font=Theme.FONT_SECTION,
            fg_color=Theme.ACCENT_BLUE,
            hover_color="#2563EB",
            text_color="#FFFFFF",
            corner_radius=10,
            height=46,
            command=self._start_encryption
        )
        self.btn_encrypt_action.grid(row=3, column=0, sticky="ew", padx=10, pady=(4, 10))

    # ==========================================================
    # TAB 2: DECRYPT
    # ==========================================================
    def _build_decrypt_tab(self):
        tab = self.tab_decrypt
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # Top: Dropzone
        self.dec_dropzone = DropZoneWidget(
            tab,
            on_browse_files=self._browse_decrypt_files,
            on_browse_folder=self._browse_decrypt_folder,
            hint_text="Drag & drop .cvault encrypted files here to DECRYPT"
        )
        self.dec_dropzone.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 8))

        # Middle: Selected Files List
        files_container = ctk.CTkFrame(tab, fg_color=Theme.BG_CARD, corner_radius=10)
        files_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=4)
        files_container.columnconfigure(0, weight=1)
        files_container.rowconfigure(1, weight=1)

        header_bar = ctk.CTkFrame(files_container, fg_color="transparent")
        header_bar.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 6))
        header_bar.columnconfigure(0, weight=1)

        self.dec_count_label = ctk.CTkLabel(
            header_bar,
            text="Encrypted Files to Restore (0 files)",
            font=Theme.FONT_TITLE,
            text_color=Theme.TEXT_MAIN
        )
        self.dec_count_label.grid(row=0, column=0, sticky="w")

        btn_clear = ctk.CTkButton(
            header_bar,
            text="Clear All",
            font=Theme.FONT_SMALL,
            width=70,
            height=24,
            fg_color="transparent",
            hover_color=Theme.BG_HOVER,
            text_color=Theme.TEXT_MUTED,
            command=self._clear_decrypt_files
        )
        btn_clear.grid(row=0, column=1, sticky="e")

        self.dec_files_scroll = ctk.CTkScrollableFrame(
            files_container,
            fg_color="transparent"
        )
        self.dec_files_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Bottom: Credentials & Destination Options Card
        options_card = ctk.CTkFrame(tab, fg_color=Theme.BG_CARD, corner_radius=10)
        options_card.grid(row=2, column=0, sticky="ew", padx=10, pady=(6, 6))
        options_card.columnconfigure(0, weight=1)

        # Password Entry Row
        pwd_frame = ctk.CTkFrame(options_card, fg_color="transparent")
        pwd_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 8))
        pwd_frame.columnconfigure(1, weight=1)

        ctk.CTkLabel(
            pwd_frame,
            text="Password:",
            font=Theme.FONT_BODY_BOLD,
            text_color=Theme.TEXT_MAIN,
            width=80,
            anchor="w"
        ).grid(row=0, column=0, sticky="w")

        self.dec_pwd_entry = ctk.CTkEntry(
            pwd_frame,
            font=Theme.FONT_BODY,
            fg_color=Theme.BG_INPUT,
            border_color=Theme.BORDER_SUBTLE,
            show="•",
            placeholder_text="Enter password to unlock and authenticate files..."
        )
        self.dec_pwd_entry.grid(row=0, column=1, sticky="ew", padx=(4, 8))

        self.dec_pwd_show_btn = ctk.CTkButton(
            pwd_frame,
            text="👁️",
            width=36,
            height=32,
            fg_color=Theme.BG_INPUT,
            hover_color=Theme.BG_HOVER,
            command=self._toggle_dec_pwd_visibility
        )
        self.dec_pwd_show_btn.grid(row=0, column=2)

        # Destination & Keyfile Row
        dest_frame = ctk.CTkFrame(options_card, fg_color=Theme.BG_CARD_ALT, corner_radius=8)
        dest_frame.grid(row=1, column=0, sticky="ew", padx=14, pady=(4, 12))
        dest_frame.columnconfigure(1, weight=1)

        # Output folder
        ctk.CTkLabel(dest_frame, text="Output Directory:", font=Theme.FONT_BODY_BOLD, text_color=Theme.TEXT_MAIN).grid(row=0, column=0, sticky="w", padx=12, pady=10)

        self.dec_dest_var = ctk.StringVar(value="(Same directory as source files)")
        self.dec_dest_label = ctk.CTkLabel(
            dest_frame,
            textvariable=self.dec_dest_var,
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_CYAN,
            anchor="w"
        )
        self.dec_dest_label.grid(row=0, column=1, sticky="ew", padx=8)

        self.btn_dec_dest = ctk.CTkButton(
            dest_frame,
            text="Change...",
            font=Theme.FONT_SMALL,
            width=80,
            height=28,
            fg_color=Theme.BG_INPUT,
            hover_color=Theme.BG_HOVER,
            command=self._browse_decrypt_destination
        )
        self.btn_dec_dest.grid(row=0, column=2, padx=(4, 12))

        # Keyfile row
        keyfile_row = ctk.CTkFrame(dest_frame, fg_color="transparent")
        keyfile_row.grid(row=1, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 10))
        keyfile_row.columnconfigure(1, weight=1)

        ctk.CTkLabel(keyfile_row, text="Keyfile (if required):", font=Theme.FONT_SMALL, text_color=Theme.TEXT_MUTED).grid(row=0, column=0, sticky="w")
        self.dec_keyfile_label = ctk.CTkLabel(
            keyfile_row,
            text="None selected",
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="w"
        )
        self.dec_keyfile_label.grid(row=0, column=1, sticky="ew", padx=8)

        self.btn_dec_keyfile = ctk.CTkButton(
            keyfile_row,
            text="Select Keyfile",
            font=Theme.FONT_SMALL,
            width=100,
            height=26,
            fg_color=Theme.BG_INPUT,
            hover_color=Theme.BG_HOVER,
            command=self._browse_dec_keyfile
        )
        self.btn_dec_keyfile.grid(row=0, column=2)

        # Decrypt Action Button
        self.btn_decrypt_action = ctk.CTkButton(
            tab,
            text="🔓 DECRYPT FILES",
            font=Theme.FONT_SECTION,
            fg_color=Theme.ACCENT_EMERALD,
            hover_color="#059669",
            text_color="#FFFFFF",
            corner_radius=10,
            height=46,
            command=self._start_decryption
        )
        self.btn_decrypt_action.grid(row=3, column=0, sticky="ew", padx=10, pady=(4, 10))

    # ==========================================================
    # TAB 3: KEY STUDIO
    # ==========================================================
    def _build_key_studio_tab(self):
        tab = self.tab_keys
        tab.columnconfigure((0, 1), weight=1)
        tab.rowconfigure(0, weight=1)

        # Left Card: Password Generator
        pwd_gen_card = ctk.CTkFrame(tab, fg_color=Theme.BG_CARD, corner_radius=12)
        pwd_gen_card.grid(row=0, column=0, sticky="nsew", padx=(10, 6), pady=10)
        pwd_gen_card.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            pwd_gen_card,
            text="⚡ Cryptographic Password Generator",
            font=Theme.FONT_TITLE,
            text_color=Theme.ACCENT_CYAN,
            anchor="w"
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(16, 6))

        # Mode selection
        ctk.CTkLabel(pwd_gen_card, text="Generator Mode:", font=Theme.FONT_SMALL, text_color=Theme.TEXT_MUTED).grid(row=1, column=0, sticky="w", padx=16, pady=(4, 2))
        self.gen_mode_menu = ctk.CTkSegmentedButton(
            pwd_gen_card,
            values=["Token (Symbols)", "Diceware Words", "256-bit Hex Key"],
            selected_color=Theme.ACCENT_BLUE,
            selected_hover_color="#2563EB",
            unselected_color=Theme.BG_INPUT,
            unselected_hover_color=Theme.BG_HOVER,
            command=self._on_gen_mode_change
        )
        self.gen_mode_menu.set("Token (Symbols)")
        self.gen_mode_menu.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 12))

        # Length Slider
        len_box = ctk.CTkFrame(pwd_gen_card, fg_color="transparent")
        len_box.grid(row=3, column=0, sticky="ew", padx=16, pady=4)
        len_box.columnconfigure(1, weight=1)

        ctk.CTkLabel(len_box, text="Length / Size:", font=Theme.FONT_BODY_BOLD, text_color=Theme.TEXT_MAIN).grid(row=0, column=0, sticky="w")
        self.gen_len_val_label = ctk.CTkLabel(len_box, text="24 chars", font=Theme.FONT_CODE_BOLD, text_color=Theme.ACCENT_CYAN)
        self.gen_len_val_label.grid(row=0, column=2, sticky="e")

        self.gen_slider = ctk.CTkSlider(
            pwd_gen_card,
            from_=8,
            to=64,
            number_of_steps=56,
            command=self._on_slider_change,
            progress_color=Theme.ACCENT_BLUE,
            button_color=Theme.ACCENT_CYAN,
            button_hover_color="#38BDF8"
        )
        self.gen_slider.set(24)
        self.gen_slider.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 12))

        # Options Checkboxes
        opts_box = ctk.CTkFrame(pwd_gen_card, fg_color=Theme.BG_CARD_ALT, corner_radius=8)
        opts_box.grid(row=5, column=0, sticky="ew", padx=16, pady=(0, 12))
        opts_box.columnconfigure((0, 1), weight=1)

        self.opt_upper = ctk.CTkCheckBox(opts_box, text="Uppercase (A-Z)", font=Theme.FONT_SMALL)
        self.opt_upper.select()
        self.opt_upper.grid(row=0, column=0, padx=12, pady=8, sticky="w")

        self.opt_lower = ctk.CTkCheckBox(opts_box, text="Lowercase (a-z)", font=Theme.FONT_SMALL)
        self.opt_lower.select()
        self.opt_lower.grid(row=0, column=1, padx=12, pady=8, sticky="w")

        self.opt_digits = ctk.CTkCheckBox(opts_box, text="Numbers (0-9)", font=Theme.FONT_SMALL)
        self.opt_digits.select()
        self.opt_digits.grid(row=1, column=0, padx=12, pady=(0, 8), sticky="w")

        self.opt_symbols = ctk.CTkCheckBox(opts_box, text="Symbols (!@#$)", font=Theme.FONT_SMALL)
        self.opt_symbols.select()
        self.opt_symbols.grid(row=1, column=1, padx=12, pady=(0, 8), sticky="w")

        # Result Display Box
        self.gen_result_box = ctk.CTkTextbox(
            pwd_gen_card,
            height=70,
            font=Theme.FONT_CODE_BOLD,
            fg_color=Theme.BG_INPUT,
            border_color=Theme.BORDER_SUBTLE,
            border_width=1,
            text_color=Theme.ACCENT_CYAN,
            wrap="char"
        )
        self.gen_result_box.grid(row=6, column=0, sticky="ew", padx=16, pady=(0, 10))

        # Buttons Row: Generate & Copy
        btn_row = ctk.CTkFrame(pwd_gen_card, fg_color="transparent")
        btn_row.grid(row=7, column=0, sticky="ew", padx=16, pady=(0, 16))
        btn_row.columnconfigure((0, 1), weight=1)

        btn_generate_now = ctk.CTkButton(
            btn_row,
            text="✨ Generate New",
            font=Theme.FONT_BODY_BOLD,
            fg_color=Theme.ACCENT_BLUE,
            hover_color="#2563EB",
            height=36,
            command=self._generate_studio_password
        )
        btn_generate_now.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self.btn_copy_pwd = ctk.CTkButton(
            btn_row,
            text="📋 Copy to Clipboard",
            font=Theme.FONT_BODY_BOLD,
            fg_color=Theme.BG_CARD_ALT,
            hover_color=Theme.BG_HOVER,
            border_width=1,
            border_color=Theme.BORDER_SUBTLE,
            text_color=Theme.TEXT_MAIN,
            height=36,
            command=self._copy_generated_pwd
        )
        self.btn_copy_pwd.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        # Trigger initial generation
        self._generate_studio_password()

        # Right Card: Keyfile Generator & Strength Tester
        right_card = ctk.CTkFrame(tab, fg_color=Theme.BG_CARD, corner_radius=12)
        right_card.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=10)
        right_card.columnconfigure(0, weight=1)

        # Keyfile Section
        ctk.CTkLabel(
            right_card,
            text="🔑 Two-Factor Keyfile Creator",
            font=Theme.FONT_TITLE,
            text_color=Theme.ACCENT_CYAN,
            anchor="w"
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(16, 4))

        ctk.CTkLabel(
            right_card,
            text="A keyfile adds physical 2-factor protection. An attacker must have BOTH the password and this file to decrypt.",
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MUTED,
            wraplength=380,
            justify="left"
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 10))

        btn_create_keyfile = ctk.CTkButton(
            right_card,
            text="💾 Create & Save Keyfile (.key)...",
            font=Theme.FONT_BODY_BOLD,
            fg_color=Theme.ACCENT_INDIGO,
            hover_color="#4F46E5",
            height=36,
            command=self._create_new_keyfile
        )
        btn_create_keyfile.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 16))

        # Divider
        divider = ctk.CTkFrame(right_card, fg_color=Theme.BORDER_SUBTLE, height=1)
        divider.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 16))

        # Password Strength Tester
        ctk.CTkLabel(
            right_card,
            text="🧪 Interactive Password Strength Lab",
            font=Theme.FONT_TITLE,
            text_color=Theme.TEXT_MAIN,
            anchor="w"
        ).grid(row=4, column=0, sticky="w", padx=16, pady=(0, 4))

        self.tester_entry = ctk.CTkEntry(
            right_card,
            font=Theme.FONT_BODY,
            fg_color=Theme.BG_INPUT,
            border_color=Theme.BORDER_SUBTLE,
            placeholder_text="Type or paste any password to analyze..."
        )
        self.tester_entry.grid(row=5, column=0, sticky="ew", padx=16, pady=(0, 8))
        self.tester_entry.bind("<KeyRelease>", self._on_tester_key_change)

        self.tester_strength = PasswordStrengthWidget(right_card)
        self.tester_strength.grid(row=6, column=0, sticky="ew", padx=16, pady=(0, 16))

    # ==========================================================
    # TAB 4: FILE SHREDDER
    # ==========================================================
    def _build_shredder_tab(self):
        tab = self.tab_shred
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        # Warning Card
        warn_card = ctk.CTkFrame(tab, fg_color="#2D1217", border_color=Theme.ACCENT_ROSE, border_width=1, corner_radius=10)
        warn_card.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 8))
        warn_card.columnconfigure(1, weight=1)

        ctk.CTkLabel(warn_card, text="⚠️", font=(Theme.FONT_FAMILY, 24)).grid(row=0, column=0, padx=(14, 8), pady=12)

        warn_text = (
            "PERMANENT DATA OBLITERATION: Files shredded here are repeatedly overwritten with CSPRNG random bytes, "
            "inverted bits, and zeros before unlinking. This prevents recovery by forensics and un-delete software."
        )
        ctk.CTkLabel(
            warn_card,
            text=warn_text,
            font=Theme.FONT_SMALL,
            text_color="#FECDD3",
            wraplength=800,
            justify="left"
        ).grid(row=0, column=1, sticky="w", padx=(0, 14), pady=12)

        # Middle: Selected Files List
        files_container = ctk.CTkFrame(tab, fg_color=Theme.BG_CARD, corner_radius=10)
        files_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=4)
        files_container.columnconfigure(0, weight=1)
        files_container.rowconfigure(1, weight=1)

        header_bar = ctk.CTkFrame(files_container, fg_color="transparent")
        header_bar.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 6))
        header_bar.columnconfigure(0, weight=1)

        self.shred_count_label = ctk.CTkLabel(
            header_bar,
            text="Files Queued for Shredding (0 files)",
            font=Theme.FONT_TITLE,
            text_color=Theme.TEXT_MAIN
        )
        self.shred_count_label.grid(row=0, column=0, sticky="w")

        btn_box = ctk.CTkFrame(header_bar, fg_color="transparent")
        btn_box.grid(row=0, column=1, sticky="e")

        btn_add = ctk.CTkButton(
            btn_box,
            text="+ Add Files",
            font=Theme.FONT_SMALL,
            width=80,
            height=26,
            fg_color=Theme.BG_INPUT,
            hover_color=Theme.BG_HOVER,
            command=self._browse_shred_files
        )
        btn_add.pack(side="left", padx=4)

        btn_clear = ctk.CTkButton(
            btn_box,
            text="Clear",
            font=Theme.FONT_SMALL,
            width=60,
            height=26,
            fg_color="transparent",
            hover_color=Theme.BG_HOVER,
            text_color=Theme.TEXT_MUTED,
            command=self._clear_shred_files
        )
        btn_clear.pack(side="left")

        self.shred_files_scroll = ctk.CTkScrollableFrame(
            files_container,
            fg_color="transparent"
        )
        self.shred_files_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Bottom: Options & Shred Button
        bottom_card = ctk.CTkFrame(tab, fg_color=Theme.BG_CARD, corner_radius=10)
        bottom_card.grid(row=2, column=0, sticky="ew", padx=10, pady=(6, 6))
        bottom_card.columnconfigure(1, weight=1)

        ctk.CTkLabel(
            bottom_card,
            text="Shredding Standard:",
            font=Theme.FONT_BODY_BOLD,
            text_color=Theme.TEXT_MAIN
        ).grid(row=0, column=0, padx=14, pady=12, sticky="w")

        self.shred_passes_menu = ctk.CTkOptionMenu(
            bottom_card,
            values=["3-Pass DoD 5220.22-M (Random -> Pattern -> Zeros)", "1-Pass Quick CSPRNG Wipe"],
            fg_color=Theme.BG_INPUT,
            button_color=Theme.BG_HOVER,
            text_color=Theme.TEXT_MAIN,
            height=30
        )
        self.shred_passes_menu.grid(row=0, column=1, padx=8, pady=12, sticky="w")

        self.btn_shred_action = ctk.CTkButton(
            tab,
            text="🔥 PERMANENTLY SHRED FILES",
            font=Theme.FONT_SECTION,
            fg_color=Theme.ACCENT_ROSE,
            hover_color="#BE123C",
            text_color="#FFFFFF",
            corner_radius=10,
            height=46,
            command=self._start_shredding
        )
        self.btn_shred_action.grid(row=3, column=0, sticky="ew", padx=10, pady=(4, 10))

    # ==========================================================
    # TAB 5: ACTIVITY LOG
    # ==========================================================
    def _build_logs_tab(self):
        tab = self.tab_logs
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        header_bar = ctk.CTkFrame(tab, fg_color="transparent")
        header_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 6))
        header_bar.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header_bar,
            text="Operation Audit Trail & Cryptographic Logs",
            font=Theme.FONT_TITLE,
            text_color=Theme.TEXT_MAIN
        ).grid(row=0, column=0, sticky="w")

        btn_box = ctk.CTkFrame(header_bar, fg_color="transparent")
        btn_box.grid(row=0, column=1, sticky="e")

        btn_copy = ctk.CTkButton(
            btn_box,
            text="Copy Logs",
            font=Theme.FONT_SMALL,
            width=80,
            height=26,
            fg_color=Theme.BG_INPUT,
            hover_color=Theme.BG_HOVER,
            command=self._copy_logs
        )
        btn_copy.pack(side="left", padx=4)

        btn_clear = ctk.CTkButton(
            btn_box,
            text="Clear",
            font=Theme.FONT_SMALL,
            width=60,
            height=26,
            fg_color="transparent",
            hover_color=Theme.BG_HOVER,
            text_color=Theme.TEXT_MUTED,
            command=self._clear_logs
        )
        btn_clear.pack(side="left")

        self.log_textbox = ctk.CTkTextbox(
            tab,
            font=Theme.FONT_CODE,
            fg_color=Theme.BG_CARD,
            text_color=Theme.TEXT_MAIN,
            border_width=1,
            border_color=Theme.BORDER_SUBTLE,
            corner_radius=10
        )
        self.log_textbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        self._log("CipherVault System initialized.")
        self._log("Cryptographic engine loaded: AES-256-GCM, ChaCha20-Poly1305, Argon2id, PBKDF2-SHA256.")

    # ==========================================================
    # STATUS & PROGRESS BAR
    # ==========================================================
    def _build_status_bar(self):
        status_frame = ctk.CTkFrame(self, fg_color=Theme.BG_CARD, height=48, corner_radius=0)
        status_frame.pack(fill="x", side="bottom")
        status_frame.pack_propagate(False)
        status_frame.columnconfigure(1, weight=1)

        self.status_icon = ctk.CTkLabel(status_frame, text="🟢", font=(Theme.FONT_FAMILY, 14), width=24)
        self.status_icon.grid(row=0, column=0, padx=(16, 6), pady=8)

        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Ready. Select files or drag & drop to get started.",
            font=Theme.FONT_BODY,
            text_color=Theme.TEXT_SUBTLE,
            anchor="w"
        )
        self.status_label.grid(row=0, column=1, sticky="ew", pady=8)

        self.progress_bar = ctk.CTkProgressBar(
            status_frame,
            width=220,
            height=8,
            corner_radius=4,
            fg_color=Theme.BG_INPUT,
            progress_color=Theme.ACCENT_CYAN
        )
        self.progress_bar.grid(row=0, column=2, padx=12, pady=8)
        self.progress_bar.set(0)

        self.btn_cancel = ctk.CTkButton(
            status_frame,
            text="Cancel",
            font=Theme.FONT_SMALL,
            fg_color=Theme.ACCENT_ROSE,
            hover_color="#BE123C",
            width=64,
            height=26,
            command=self._cancel_operation
        )
        self.btn_cancel.grid(row=0, column=3, padx=(0, 16), pady=8)
        self.btn_cancel.grid_remove()  # Hidden by default

    # ==========================================================
    # LOGGING HELPER
    # ==========================================================
    def _log(self, message: str):
        timestamp = time.strftime("[%H:%M:%S]")
        formatted = f"{timestamp} {message}\n"
        self.log_textbox.insert("end", formatted)
        self.log_textbox.see("end")

    def _copy_logs(self):
        content = self.log_textbox.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(content)
        messagebox.showinfo("Copied", "Logs copied to clipboard.")

    def _clear_logs(self):
        self.log_textbox.delete("1.0", "end")

    # ==========================================================
    # FILE MANAGEMENT: ENCRYPT
    # ==========================================================
    def _browse_encrypt_files(self):
        files = filedialog.askopenfilenames(
            title="Select Files to Encrypt",
            filetypes=[("All Files", "*.*")]
        )
        if files:
            self._add_encrypt_files(list(files))

    def _browse_encrypt_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Encrypt")
        if folder:
            all_files = []
            for root, _, files in os.walk(folder):
                for f in files:
                    all_files.append(os.path.join(root, f))
            if all_files:
                self._add_encrypt_files(all_files)

    def _add_encrypt_files(self, paths: List[str]):
        for p in paths:
            norm_p = os.path.normpath(p)
            if norm_p not in self.encrypt_files and os.path.isfile(norm_p):
                self.encrypt_files.append(norm_p)
                card = FileItemCard(self.enc_files_scroll, norm_p, on_remove=self._remove_encrypt_file)
                card.pack(fill="x", pady=2)
        self._update_encrypt_count()

    def _remove_encrypt_file(self, path: str):
        if path in self.encrypt_files:
            self.encrypt_files.remove(path)
        # Re-render list
        for child in self.enc_files_scroll.winfo_children():
            child.destroy()
        for p in self.encrypt_files:
            card = FileItemCard(self.enc_files_scroll, p, on_remove=self._remove_encrypt_file)
            card.pack(fill="x", pady=2)
        self._update_encrypt_count()

    def _clear_encrypt_files(self):
        self.encrypt_files.clear()
        for child in self.enc_files_scroll.winfo_children():
            child.destroy()
        self._update_encrypt_count()

    def _update_encrypt_count(self):
        count = len(self.encrypt_files)
        total_size = sum(os.path.getsize(f) for f in self.encrypt_files if os.path.isfile(f))
        self.enc_count_label.configure(
            text=f"Selected Files ({count} files • {format_bytes(total_size)})"
        )
        self.btn_encrypt_action.configure(
            text=f"🔒 ENCRYPT {count} FILE{'S' if count != 1 else ''}"
        )

    def _on_enc_pwd_change(self, event=None):
        pwd = self.enc_pwd_entry.get()
        self.enc_strength_widget.update_password(pwd)

    def _toggle_enc_pwd_visibility(self):
        if self.enc_pwd_entry.cget("show") == "•":
            self.enc_pwd_entry.configure(show="")
            self.enc_pwd_show_btn.configure(text="🔒")
        else:
            self.enc_pwd_entry.configure(show="•")
            self.enc_pwd_show_btn.configure(text="👁️")

    def _generate_and_fill_enc_password(self):
        new_pwd = generate_complex_password(length=24)
        self.enc_pwd_entry.delete(0, "end")
        self.enc_pwd_entry.insert(0, new_pwd)
        self._on_enc_pwd_change()
        self.clipboard_clear()
        self.clipboard_append(new_pwd)
        messagebox.showinfo(
            "Password Generated",
            f"Generated high-entropy password:\n\n{new_pwd}\n\n(Copied to clipboard automatically!)"
        )

    def _browse_enc_keyfile(self):
        if self.encrypt_keyfile:
            self.encrypt_keyfile = None
            self.enc_keyfile_label.configure(text="None (Optional)", text_color=Theme.TEXT_MUTED)
            self.enc_keyfile_btn.configure(text="Browse")
            return

        kf = filedialog.askopenfilename(
            title="Select Keyfile (.key) for Two-Factor Encryption",
            filetypes=[("Key Files", "*.key;*.bin;*.dat"), ("All Files", "*.*")]
        )
        if kf:
            self.encrypt_keyfile = kf
            name = os.path.basename(kf)
            self.enc_keyfile_label.configure(text=f"🔑 {name}", text_color=Theme.ACCENT_CYAN)
            self.enc_keyfile_btn.configure(text="Remove")

    # ==========================================================
    # FILE MANAGEMENT: DECRYPT
    # ==========================================================
    def _browse_decrypt_files(self):
        files = filedialog.askopenfilenames(
            title="Select Encrypted Files to Decrypt",
            filetypes=[("CipherVault Files", "*.cvault;*.enc"), ("All Files", "*.*")]
        )
        if files:
            self._add_decrypt_files(list(files))

    def _browse_decrypt_folder(self):
        folder = filedialog.askdirectory(title="Select Folder with Encrypted Files")
        if folder:
            all_files = []
            for root, _, files in os.walk(folder):
                for f in files:
                    if f.endswith(".cvault") or f.endswith(".enc"):
                        all_files.append(os.path.join(root, f))
            if all_files:
                self._add_decrypt_files(all_files)

    def _add_decrypt_files(self, paths: List[str]):
        for p in paths:
            norm_p = os.path.normpath(p)
            if norm_p not in self.decrypt_files and os.path.isfile(norm_p):
                self.decrypt_files.append(norm_p)
                card = FileItemCard(self.dec_files_scroll, norm_p, on_remove=self._remove_decrypt_file)
                card.pack(fill="x", pady=2)
        self._update_decrypt_count()

    def _remove_decrypt_file(self, path: str):
        if path in self.decrypt_files:
            self.decrypt_files.remove(path)
        for child in self.dec_files_scroll.winfo_children():
            child.destroy()
        for p in self.decrypt_files:
            card = FileItemCard(self.dec_files_scroll, p, on_remove=self._remove_decrypt_file)
            card.pack(fill="x", pady=2)
        self._update_decrypt_count()

    def _clear_decrypt_files(self):
        self.decrypt_files.clear()
        for child in self.dec_files_scroll.winfo_children():
            child.destroy()
        self._update_decrypt_count()

    def _update_decrypt_count(self):
        count = len(self.decrypt_files)
        total_size = sum(os.path.getsize(f) for f in self.decrypt_files if os.path.isfile(f))
        self.dec_count_label.configure(
            text=f"Encrypted Files to Restore ({count} files • {format_bytes(total_size)})"
        )
        self.btn_decrypt_action.configure(
            text=f"🔓 DECRYPT {count} FILE{'S' if count != 1 else ''}"
        )

    def _toggle_dec_pwd_visibility(self):
        if self.dec_pwd_entry.cget("show") == "•":
            self.dec_pwd_entry.configure(show="")
            self.dec_pwd_show_btn.configure(text="🔒")
        else:
            self.dec_pwd_entry.configure(show="•")
            self.dec_pwd_show_btn.configure(text="👁️")

    def _browse_decrypt_destination(self):
        folder = filedialog.askdirectory(title="Select Destination Directory for Decrypted Files")
        if folder:
            self.dec_dest_var.set(folder)

    def _browse_dec_keyfile(self):
        if self.decrypt_keyfile:
            self.decrypt_keyfile = None
            self.dec_keyfile_label.configure(text="None selected", text_color=Theme.TEXT_MUTED)
            self.btn_dec_keyfile.configure(text="Select Keyfile")
            return

        kf = filedialog.askopenfilename(
            title="Select Decryption Keyfile (.key)",
            filetypes=[("Key Files", "*.key;*.bin;*.dat"), ("All Files", "*.*")]
        )
        if kf:
            self.decrypt_keyfile = kf
            name = os.path.basename(kf)
            self.dec_keyfile_label.configure(text=f"🔑 {name}", text_color=Theme.ACCENT_CYAN)
            self.btn_dec_keyfile.configure(text="Remove")

    # ==========================================================
    # FILE MANAGEMENT: SHREDDER
    # ==========================================================
    def _browse_shred_files(self):
        files = filedialog.askopenfilenames(
            title="Select Files to Permanently Shred",
            filetypes=[("All Files", "*.*")]
        )
        if files:
            self._add_shred_files(list(files))

    def _add_shred_files(self, paths: List[str]):
        for p in paths:
            norm_p = os.path.normpath(p)
            if norm_p not in self.shred_files and os.path.isfile(norm_p):
                self.shred_files.append(norm_p)
                card = FileItemCard(self.shred_files_scroll, norm_p, on_remove=self._remove_shred_file)
                card.pack(fill="x", pady=2)
        self._update_shred_count()

    def _remove_shred_file(self, path: str):
        if path in self.shred_files:
            self.shred_files.remove(path)
        for child in self.shred_files_scroll.winfo_children():
            child.destroy()
        for p in self.shred_files:
            card = FileItemCard(self.shred_files_scroll, p, on_remove=self._remove_shred_file)
            card.pack(fill="x", pady=2)
        self._update_shred_count()

    def _clear_shred_files(self):
        self.shred_files.clear()
        for child in self.shred_files_scroll.winfo_children():
            child.destroy()
        self._update_shred_count()

    def _update_shred_count(self):
        count = len(self.shred_files)
        total_size = sum(os.path.getsize(f) for f in self.shred_files if os.path.isfile(f))
        self.shred_count_label.configure(
            text=f"Files Queued for Shredding ({count} files • {format_bytes(total_size)})"
        )
        self.btn_shred_action.configure(
            text=f"🔥 PERMANENTLY SHRED {count} FILE{'S' if count != 1 else ''}"
        )

    # ==========================================================
    # KEY STUDIO HANDLERS
    # ==========================================================
    def _on_gen_mode_change(self, mode: str):
        if mode == "Diceware Words":
            self.gen_slider.configure(from_=3, to=10, number_of_steps=7)
            self.gen_slider.set(5)
            self.gen_len_val_label.configure(text="5 words")
        elif mode == "256-bit Hex Key":
            self.gen_slider.configure(from_=16, to=64, number_of_steps=48)
            self.gen_slider.set(32)
            self.gen_len_val_label.configure(text="32 bytes (256-bit)")
        else:
            self.gen_slider.configure(from_=8, to=64, number_of_steps=56)
            self.gen_slider.set(24)
            self.gen_len_val_label.configure(text="24 chars")
        self._generate_studio_password()

    def _on_slider_change(self, val):
        val_int = int(val)
        mode = self.gen_mode_menu.get()
        if mode == "Diceware Words":
            self.gen_len_val_label.configure(text=f"{val_int} words")
        elif mode == "256-bit Hex Key":
            self.gen_len_val_label.configure(text=f"{val_int} bytes ({val_int * 8}-bit)")
        else:
            self.gen_len_val_label.configure(text=f"{val_int} chars")
        self._generate_studio_password()

    def _generate_studio_password(self):
        mode = self.gen_mode_menu.get()
        length = int(self.gen_slider.get())

        if mode == "Diceware Words":
            pwd = generate_passphrase(num_words=length)
        elif mode == "256-bit Hex Key":
            pwd = generate_hex_key(num_bytes=length)
        else:
            use_u = self.opt_upper.get() == 1
            use_l = self.opt_lower.get() == 1
            use_d = self.opt_digits.get() == 1
            use_s = self.opt_symbols.get() == 1
            pwd = generate_complex_password(length=length, use_upper=use_u, use_lower=use_l, use_digits=use_d, use_symbols=use_s)

        self.gen_result_box.delete("1.0", "end")
        self.gen_result_box.insert("1.0", pwd)
        self.btn_copy_pwd.configure(text="📋 Copy to Clipboard", text_color=Theme.TEXT_MAIN)

    def _copy_generated_pwd(self):
        pwd = self.gen_result_box.get("1.0", "end-1c")
        if pwd:
            self.clipboard_clear()
            self.clipboard_append(pwd)
            self.btn_copy_pwd.configure(text="✅ Copied!", text_color=Theme.ACCENT_EMERALD)
            self.after(2000, lambda: self.btn_copy_pwd.configure(text="📋 Copy to Clipboard", text_color=Theme.TEXT_MAIN))

    def _create_new_keyfile(self):
        dest = filedialog.asksaveasfilename(
            title="Save New Cryptographic Keyfile",
            defaultextension=".key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
        )
        if dest:
            try:
                generate_keyfile(dest, num_bytes=64)
                messagebox.showinfo(
                    "Keyfile Created",
                    f"Physical 512-bit keyfile generated successfully:\n\n{dest}\n\nKeep this file secure!"
                )
                self._log(f"Generated 512-bit physical keyfile: {dest}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save keyfile: {e}")

    def _on_tester_key_change(self, event=None):
        pwd = self.tester_entry.get()
        self.tester_strength.update_password(pwd)

    # ==========================================================
    # WORKER OPERATIONS: ENCRYPTION
    # ==========================================================
    def _start_encryption(self):
        if not self.encrypt_files:
            messagebox.showwarning("No Files", "Please add one or more files to encrypt.")
            return

        password = self.enc_pwd_entry.get()
        if not password and not self.encrypt_keyfile:
            messagebox.showwarning("Password Required", "Please enter a password or select a keyfile.")
            return

        cipher_choice = self.enc_cipher_menu.get()
        cipher_id = CIPHER_AES_256_GCM if "AES" in cipher_choice else CIPHER_CHACHA20_POLY1305

        kdf_choice = self.enc_kdf_menu.get()
        kdf_id = KDF_ARGON2ID if "Argon2" in kdf_choice else KDF_PBKDF2_SHA256

        shred_original = self.enc_shred_var.get()
        keyfile_path = self.encrypt_keyfile

        self._set_working_state(True)
        threading.Thread(
            target=self._worker_encrypt,
            args=(self.encrypt_files.copy(), password, cipher_id, kdf_id, keyfile_path, shred_original),
            daemon=True
        ).start()

    def _worker_encrypt(self, files: List[str], password: str, cipher_id: int, kdf_id: int, keyfile_path: Optional[str], shred_original: bool):
        keyfile_bytes = None
        if keyfile_path and os.path.exists(keyfile_path):
            with open(keyfile_path, "rb") as kf:
                keyfile_bytes = kf.read()

        total_files = len(files)
        success_count = 0
        error_count = 0

        self._log(f"Beginning encryption of {total_files} file(s)...")

        for idx, file_path in enumerate(files, start=1):
            if self.cancel_event.is_set():
                self._log("Encryption job cancelled by user.")
                break

            filename = os.path.basename(file_path)
            self._update_status(f"Encrypting ({idx}/{total_files}): {filename}...", progress=0.0)

            out_path = file_path + ".cvault"

            def progress_cb(processed: int, total: int, speed: float):
                pct = (processed / total) if total > 0 else 1.0
                speed_str = f"{speed:.1f} MB/s"
                msg = f"Encrypting ({idx}/{total_files}): {filename} • {format_bytes(processed)}/{format_bytes(total)} • {speed_str}"
                self._update_status(msg, progress=pct)

            try:
                meta = encrypt_file(
                    source_path=file_path,
                    output_path=out_path,
                    password=password,
                    cipher_id=cipher_id,
                    kdf_id=kdf_id,
                    keyfile_bytes=keyfile_bytes,
                    progress_callback=progress_cb,
                    cancel_check=lambda: self.cancel_event.is_set()
                )

                self._log(f"Encrypted: {filename} -> {os.path.basename(out_path)} ({meta['elapsed_seconds']:.2f}s)")

                if shred_original:
                    self._update_status(f"Shredding original: {filename}...", progress=1.0)
                    shred_file(file_path, passes=1)
                    self._log(f"Securely shredded original: {filename}")

                success_count += 1

            except Exception as e:
                error_count += 1
                self._log(f"ERROR encrypting {filename}: {e}")

        self._set_working_state(False)

        if not self.cancel_event.is_set():
            if error_count == 0:
                self._update_status(f"✅ Encryption complete! {success_count} file(s) secured.", progress=1.0, is_success=True)
                messagebox.showinfo("Success", f"All {success_count} file(s) encrypted successfully!")
            else:
                self._update_status(f"Completed with errors: {success_count} succeeded, {error_count} failed.", progress=1.0)
                messagebox.showwarning("Completed with Errors", f"{success_count} succeeded, {error_count} failed. See Activity Log for details.")
        else:
            self._update_status("Operation cancelled.", progress=0.0)

    # ==========================================================
    # WORKER OPERATIONS: DECRYPTION
    # ==========================================================
    def _start_decryption(self):
        if not self.decrypt_files:
            messagebox.showwarning("No Files", "Please add one or more encrypted files to decrypt.")
            return

        password = self.dec_pwd_entry.get()
        if not password and not self.decrypt_keyfile:
            messagebox.showwarning("Password Required", "Please enter a password or select a keyfile.")
            return

        custom_dest = self.dec_dest_var.get()
        if "(Same directory" in custom_dest:
            custom_dest = None

        keyfile_path = self.decrypt_keyfile

        self._set_working_state(True)
        threading.Thread(
            target=self._worker_decrypt,
            args=(self.decrypt_files.copy(), password, keyfile_path, custom_dest),
            daemon=True
        ).start()

    def _worker_decrypt(self, files: List[str], password: str, keyfile_path: Optional[str], custom_dest: Optional[str]):
        keyfile_bytes = None
        if keyfile_path and os.path.exists(keyfile_path):
            with open(keyfile_path, "rb") as kf:
                keyfile_bytes = kf.read()

        total_files = len(files)
        success_count = 0
        error_count = 0

        self._log(f"Beginning decryption of {total_files} file(s)...")

        for idx, file_path in enumerate(files, start=1):
            if self.cancel_event.is_set():
                self._log("Decryption job cancelled by user.")
                break

            filename = os.path.basename(file_path)
            self._update_status(f"Decrypting ({idx}/{total_files}): {filename}...", progress=0.0)

            out_dir = custom_dest if custom_dest else os.path.dirname(file_path)

            def progress_cb(processed: int, total: int, speed: float):
                pct = (processed / total) if total > 0 else 1.0
                speed_str = f"{speed:.1f} MB/s"
                msg = f"Decrypting ({idx}/{total_files}): {filename} • {format_bytes(processed)}/{format_bytes(total)} • {speed_str}"
                self._update_status(msg, progress=pct)

            try:
                restored_path, meta = decrypt_file(
                    source_path=file_path,
                    output_dir=out_dir,
                    password=password,
                    keyfile_bytes=keyfile_bytes,
                    progress_callback=progress_cb,
                    cancel_check=lambda: self.cancel_event.is_set()
                )

                self._log(f"Decrypted: {filename} -> {os.path.basename(restored_path)} ({meta['elapsed_seconds']:.2f}s)")
                success_count += 1

            except AuthenticationError as e:
                error_count += 1
                self._log(f"AUTH FAILED on {filename}: {e}")
            except Exception as e:
                error_count += 1
                self._log(f"ERROR decrypting {filename}: {e}")

        self._set_working_state(False)

        if not self.cancel_event.is_set():
            if error_count == 0:
                self._update_status(f"✅ Decryption complete! {success_count} file(s) restored.", progress=1.0, is_success=True)
                messagebox.showinfo("Success", f"All {success_count} file(s) decrypted and authenticated successfully!")
            else:
                self._update_status(f"Decryption errors: {success_count} succeeded, {error_count} failed.", progress=1.0)
                messagebox.showerror(
                    "Decryption Failed / Errors",
                    f"{error_count} file(s) failed authentication.\n\nPlease check your password and keyfile."
                )
        else:
            self._update_status("Operation cancelled.", progress=0.0)

    # ==========================================================
    # WORKER OPERATIONS: SHREDDER
    # ==========================================================
    def _start_shredding(self):
        if not self.shred_files:
            messagebox.showwarning("No Files", "Please add files to shred.")
            return

        count = len(self.shred_files)
        confirm = messagebox.askyesno(
            "Confirm Permanent Shredding",
            f"Are you ABSOLUTELY sure you want to permanently obliterate {count} file(s)?\n\n"
            "This action CANNOT be undone, and the files will be impossible to recover.",
            icon="warning"
        )
        if not confirm:
            return

        passes_text = self.shred_passes_menu.get()
        passes = 1 if "1-Pass" in passes_text else 3

        self._set_working_state(True)
        threading.Thread(
            target=self._worker_shred,
            args=(self.shred_files.copy(), passes),
            daemon=True
        ).start()

    def _worker_shred(self, files: List[str], passes: int):
        total_files = len(files)
        success_count = 0
        error_count = 0

        self._log(f"Starting permanent shredding of {total_files} file(s)...")

        for idx, file_path in enumerate(files, start=1):
            if self.cancel_event.is_set():
                self._log("Shredding cancelled by user.")
                break

            filename = os.path.basename(file_path)

            def progress_cb(written: int, total: int, pass_name: str):
                pct = (written / total) if total > 0 else 1.0
                msg = f"Shredding ({idx}/{total_files}): {filename} • {pass_name}"
                self._update_status(msg, progress=pct)

            try:
                shred_file(
                    file_path=file_path,
                    passes=passes,
                    progress_callback=progress_cb,
                    cancel_check=lambda: self.cancel_event.is_set()
                )
                self._log(f"Permanently shredded: {filename}")
                success_count += 1
            except Exception as e:
                error_count += 1
                self._log(f"ERROR shredding {filename}: {e}")

        # Clear shred files from UI
        self.after(0, self._clear_shred_files)
        self._set_working_state(False)

        if not self.cancel_event.is_set():
            self._update_status(f"✅ Shredding complete! {success_count} file(s) permanently erased.", progress=1.0, is_success=True)
            messagebox.showinfo("Shredding Complete", f"{success_count} file(s) have been permanently obliterated.")
        else:
            self._update_status("Shredding cancelled.", progress=0.0)

    # ==========================================================
    # STATE & THREADING HELPERS
    # ==========================================================
    def _set_working_state(self, is_working: bool):
        self.is_processing = is_working
        self.cancel_event.clear()

        def update_ui():
            if is_working:
                self.btn_cancel.grid()
                self.btn_encrypt_action.configure(state="disabled")
                self.btn_decrypt_action.configure(state="disabled")
                self.btn_shred_action.configure(state="disabled")
                self.status_icon.configure(text="⏳")
            else:
                self.btn_cancel.grid_remove()
                self.btn_encrypt_action.configure(state="normal")
                self.btn_decrypt_action.configure(state="normal")
                self.btn_shred_action.configure(state="normal")
                self.status_icon.configure(text="🟢")
                self.progress_bar.set(0)

        self.after(0, update_ui)

    def _update_status(self, text: str, progress: float = 0.0, is_success: bool = False):
        def update():
            self.status_label.configure(text=text)
            self.progress_bar.set(progress)
            if is_success:
                self.status_icon.configure(text="✅")
            elif self.is_processing:
                self.status_icon.configure(text="⏳")
            else:
                self.status_icon.configure(text="🟢")

        self.after(0, update)

    def _cancel_operation(self):
        if self.is_processing:
            self.cancel_event.set()
            self._update_status("Cancelling current operation...")

    def destroy(self):
        """Clean teardown on exit."""
        if self.dnd_handler:
            self.dnd_handler.teardown()
        super().destroy()
