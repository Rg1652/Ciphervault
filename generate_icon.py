"""
Generates high-resolution application icons and logos for CipherVault.
"""

import os
from PIL import Image, ImageDraw

def create_cipher_icon():
    os.makedirs("assets", exist_ok=True)
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background rounded rectangle (Dark Navy Slate)
    draw.rounded_rectangle([16, 16, 240, 240], radius=54, fill=(12, 17, 27, 255), outline=(0, 210, 255, 255), width=5)

    # Inner subtle glow outline
    draw.rounded_rectangle([24, 24, 232, 232], radius=46, outline=(30, 41, 59, 255), width=2)

    # Draw Shield shape
    # Points for a sleek shield:
    # Top left: (50, 60), Top right: (206, 60), Middle bottom: (128, 215)
    shield_pts = [
        (56, 68),
        (200, 68),
        (200, 135),
        (128, 205),
        (56, 135),
    ]
    draw.polygon(shield_pts, fill=(21, 28, 44, 255), outline=(59, 130, 246, 255))

    # Shackle of the Lock (Arc)
    # Lock body is at [88, 120, 168, 185]
    draw.arc([100, 80, 156, 140], start=180, end=0, fill=(0, 210, 255, 255), width=12)

    # Shackle vertical pillars
    draw.rectangle([100, 110, 112, 128], fill=(0, 210, 255, 255))
    draw.rectangle([144, 110, 156, 128], fill=(0, 210, 255, 255))

    # Lock Body
    draw.rounded_rectangle([86, 124, 170, 184], radius=14, fill=(0, 210, 255, 255), outline=(255, 255, 255, 180), width=2)

    # Keyhole
    # Circle top of keyhole
    draw.ellipse([121, 140, 135, 154], fill=(12, 17, 27, 255))
    # Trapezoid / Triangle stem of keyhole
    draw.polygon([(124, 150), (132, 150), (134, 168), (122, 168)], fill=(12, 17, 27, 255))

    # Cyan laser / cybersecurity dot
    draw.ellipse([126, 145, 130, 149], fill=(0, 210, 255, 255))

    # Save PNG
    png_path = os.path.join("assets", "icon.png")
    img.save(png_path, format="PNG")

    # Save Multi-resolution ICO
    ico_path = os.path.join("assets", "icon.ico")
    img.save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    )
    print(f"Icons generated successfully: {png_path}, {ico_path}")

if __name__ == "__main__":
    create_cipher_icon()
