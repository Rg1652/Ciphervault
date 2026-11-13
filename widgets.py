"""
CipherVault Custom UI Widgets
Polished widgets for file lists, password strength indicators, drop zones, and progress cards.
"""

import os
import customtkinter as ctk
from typing import Callable, Optional, List
from ui.theme import Theme
from core.keys import evaluate_password_strength


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable string (KB, MB, GB)."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


def get_file_icon(filename: str) -> str:
    """Return an appropriate emoji icon based on file extension."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in (".cvault", ".enc", ".aes", ".gpg"):
        return "🔒"
    elif ext in (".zip", ".rar", ".7z", ".tar", ".gz"):
        return "📦"
    elif ext in (".pdf", ".docx", ".doc", ".xlsx", ".pptx", ".txt", ".md", ".csv"):
        return "📄"
    elif ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp"):
        return "🖼️"
    elif ext in (".mp4", ".mkv", ".mov", ".avi", ".webm"):
        return "🎬"
    elif ext in (".mp3", ".wav", ".flac", ".m4a"):
        return "🎵"
    elif ext in (".exe", ".msi", ".dll", ".bin"):
        return "⚙️"
    elif ext in (".key", ".pem", ".pub", ".crt"):
        return "🔑"
    return "📁"


class PasswordStrengthWidget(ctk.CTkFrame):
    """Real-time visual password strength evaluator."""
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.columnconfigure(0, weight=1)

        self.info_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.info_frame.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        self.info_frame.columnconfigure(0, weight=1)

        self.label_strength = ctk.CTkLabel(
            self.info_frame,
            text="Password Strength: None",
            font=Theme.FONT_BODY_BOLD,
            text_color=Theme.TEXT_MUTED,
            anchor="w"
        )
        self.label_strength.grid(row=0, column=0, sticky="w")

        self.label_details = ctk.CTkLabel(
            self.info_frame,
            text="0 bits entropy",
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="e"
        )
        self.label_details.grid(row=0, column=1, sticky="e")

        self.bar = ctk.CTkProgressBar(
            self,
            height=6,
            corner_radius=3,
            fg_color=Theme.BG_INPUT,
            progress_color=Theme.TEXT_MUTED
        )
        self.bar.grid(row=1, column=0, sticky="ew")
        self.bar.set(0)

        self.label_crack = ctk.CTkLabel(
            self,
            text="Crack resistance: -",
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="w"
        )
        self.label_crack.grid(row=2, column=0, sticky="w", pady=(3, 0))

    def update_password(self, password: str):
        stats = evaluate_password_strength(password)
        score = stats["score"]
        self.bar.set(score / 100.0)
        self.bar.configure(progress_color=stats["color"])

        if not password:
            self.label_strength.configure(text="Password Strength: None", text_color=Theme.TEXT_MUTED)
            self.label_details.configure(text="0 bits entropy", text_color=Theme.TEXT_MUTED)
            self.label_crack.configure(text="Enter a password to evaluate strength", text_color=Theme.TEXT_MUTED)
        else:
            self.label_strength.configure(
                text=f"Strength: {stats['label']}",
                text_color=stats["color"]
            )
            self.label_details.configure(
                text=f"{stats['entropy_bits']} bits entropy",
                text_color=Theme.TEXT_SUBTLE
            )
            self.label_crack.configure(
                text=f"Estimated crack time: {stats['crack_time_str']} ({stats['description']})",
                text_color=Theme.TEXT_SUBTLE
            )


class FileItemCard(ctk.CTkFrame):
    """Card representing a single file in the selection list."""
    def __init__(self, master, file_path: str, on_remove: Optional[Callable[[str], None]] = None, **kwargs):
        super().__init__(
            master,
            fg_color=Theme.BG_CARD,
            border_width=1,
            border_color=Theme.BORDER_SUBTLE,
            corner_radius=8,
            **kwargs
        )
        self.file_path = file_path
        self.on_remove = on_remove

        self.columnconfigure(1, weight=1)

        filename = os.path.basename(file_path)
        icon = get_file_icon(filename)

        try:
            size_bytes = os.path.getsize(file_path)
            size_str = format_bytes(size_bytes)
        except OSError:
            size_str = "Unknown size"

        # Icon
        self.icon_label = ctk.CTkLabel(
            self,
            text=icon,
            font=(Theme.FONT_FAMILY, 16),
            width=32
        )
        self.icon_label.grid(row=0, column=0, rowspan=2, padx=(10, 8), pady=8)

        # Filename
        display_name = filename if len(filename) <= 45 else filename[:22] + "..." + filename[-20:]
        self.name_label = ctk.CTkLabel(
            self,
            text=display_name,
            font=Theme.FONT_BODY_BOLD,
            text_color=Theme.TEXT_MAIN,
            anchor="w"
        )
        self.name_label.grid(row=0, column=1, sticky="w", padx=(0, 8), pady=(8, 0))

        # File path & size
        display_path = os.path.dirname(file_path)
        if len(display_path) > 50:
            display_path = display_path[:20] + "..." + display_path[-25:]
        meta_str = f"{size_str}  •  {display_path}"

        self.meta_label = ctk.CTkLabel(
            self,
            text=meta_str,
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MUTED,
            anchor="w"
        )
        self.meta_label.grid(row=1, column=1, sticky="w", padx=(0, 8), pady=(0, 8))

        # Status badge
        self.badge = ctk.CTkLabel(
            self,
            text="Ready",
            font=Theme.FONT_SMALL,
            fg_color=Theme.BG_INPUT,
            text_color=Theme.TEXT_SUBTLE,
            corner_radius=4,
            padx=8,
            pady=2
        )
        self.badge.grid(row=0, column=2, rowspan=2, padx=(8, 6), pady=8)

        # Remove button
        if on_remove:
            self.btn_remove = ctk.CTkButton(
                self,
                text="✕",
                font=(Theme.FONT_FAMILY, 11, "bold"),
                width=28,
                height=28,
                corner_radius=6,
                fg_color="transparent",
                hover_color=Theme.BG_HOVER,
                text_color=Theme.TEXT_MUTED,
                command=lambda: self.on_remove(self.file_path)
            )
            self.btn_remove.grid(row=0, column=3, rowspan=2, padx=(2, 10), pady=8)

    def set_status(self, text: str, color: str = Theme.TEXT_SUBTLE, bg_color: str = Theme.BG_INPUT):
        self.badge.configure(text=text, text_color=color, fg_color=bg_color)


class DropZoneWidget(ctk.CTkFrame):
    """Sleek drag & drop zone for user files."""
    def __init__(
        self,
        master,
        on_browse_files: Callable[[], None],
        on_browse_folder: Callable[[], None],
        hint_text: str = "Drag & Drop files here, or browse",
        **kwargs
    ):
        super().__init__(
            master,
            fg_color=Theme.BG_CARD,
            border_width=1,
            border_color=Theme.BORDER_SUBTLE,
            corner_radius=12,
            **kwargs
        )
        self.columnconfigure(0, weight=1)

        self.icon_label = ctk.CTkLabel(
            self,
            text="📥",
            font=(Theme.FONT_FAMILY, 32),
        )
        self.icon_label.grid(row=0, column=0, pady=(20, 6))

        self.title_label = ctk.CTkLabel(
            self,
            text=hint_text,
            font=Theme.FONT_TITLE,
            text_color=Theme.TEXT_MAIN
        )
        self.title_label.grid(row=1, column=0, pady=(0, 2))

        self.subtitle_label = ctk.CTkLabel(
            self,
            text="Supports single files, multiple files, or entire folders of any size",
            font=Theme.FONT_SMALL,
            text_color=Theme.TEXT_MUTED
        )
        self.subtitle_label.grid(row=2, column=0, pady=(0, 14))

        # Button container
        btn_box = ctk.CTkFrame(self, fg_color="transparent")
        btn_box.grid(row=3, column=0, pady=(0, 20))

        self.btn_files = ctk.CTkButton(
            btn_box,
            text="📁 Browse Files",
            font=Theme.FONT_BODY_BOLD,
            fg_color=Theme.ACCENT_BLUE,
            hover_color="#2563EB",
            text_color="#FFFFFF",
            corner_radius=8,
            height=34,
            command=on_browse_files
        )
        self.btn_files.pack(side="left", padx=8)

        self.btn_folder = ctk.CTkButton(
            btn_box,
            text="📂 Browse Folder",
            font=Theme.FONT_BODY_BOLD,
            fg_color=Theme.BG_CARD_ALT,
            hover_color=Theme.BG_HOVER,
            border_width=1,
            border_color=Theme.BORDER_SUBTLE,
            text_color=Theme.TEXT_MAIN,
            corner_radius=8,
            height=34,
            command=on_browse_folder
        )
        self.btn_folder.pack(side="left", padx=8)
