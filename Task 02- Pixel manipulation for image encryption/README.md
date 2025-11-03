🖼️ Task 02 — Image Encryption & Decryption Tool

Description:
A Python-based GUI application that allows users to encrypt and decrypt images using password-based XOR and pixel permutation techniques.
This project demonstrates how symmetric encryption concepts can be visually applied to images — turning them into encrypted pixel patterns that can only be restored using the correct key or password.

Key Features:

🔐 Password or Integer Key Support: Generate a deterministic numeric key using SHA-256 hashing or enter a manual key.

🌀 Pixel Shuffling: Randomly permutes pixel order to enhance confusion.

⚡ Fast XOR-based Encryption: Lightweight symmetric transformation applied to image bytes.

🖥️ Interactive GUI: Built using Tkinter, supports image browsing, encryption, decryption, and instant preview.

💾 Automatic File Naming: Encrypted and decrypted images are saved with _enc or _dec suffixes.

How It Works:

The user selects an image file (PNG, JPG, BMP, etc.).

A password or integer key is provided.

The program converts that key into a deterministic integer via SHA-256 hashing.

The image is converted into RGBA bytes.

Each byte is XORed with a key-derived value and (optionally) pixel-shuffled.

The result is saved as an encrypted image file.

Using the same key and shuffle settings, the image can be perfectly decrypted.

Skills Demonstrated:

Cryptography Fundamentals (XOR operations, permutations, hashing)

Python GUI Development (Tkinter)

File Handling & Image Processing (PIL / Pillow)

Secure Key Derivation using SHA-256

Usage:

Run the script:

python image_encrypt_gui.py


Browse and select an image.

Choose password or integer key mode.

Click Encrypt ▶ to encrypt or Decrypt ◀ to decrypt.

The processed image will be saved in the same folder with _enc or _dec suffixes.

Dependencies:

pip install pillow


Developer:
🧠 Mashallah Naveed
✨ Developed as part of the Prodigy InfoTech Cybersecurity Internship
