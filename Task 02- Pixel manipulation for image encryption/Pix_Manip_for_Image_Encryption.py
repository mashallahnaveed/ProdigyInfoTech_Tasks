# image_encrypt_gui.py
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import random
import os
import hashlib

# ---------- Core transforms ----------
def xor_bytes(data: bytearray, key_byte: int) -> None:
    for i in range(len(data)):
        data[i] ^= key_byte

def get_permutation(n: int, key: int):
    rng = random.Random(key)
    perm = list(range(n))
    rng.shuffle(perm)
    return perm

def invert_permutation(perm): 
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

# Convert a password string to a numeric key (deterministic)
def password_to_key(password: str) -> int:
    # SHA-256 -> integer
    h = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return int(h, 16)

def default_out_path(in_path: str, mode: str):
    base, ext = os.path.splitext(in_path)
    if mode == "enc":
        return f"{base}_enc{ext}"
    else:
        return f"{base}_dec{ext}"

# ---------- Encrypt / Decrypt ----------
def encrypt_image(in_path: str, out_path: str, key_int: int, shuffle: bool = True):
    img = Image.open(in_path).convert("RGBA")
    width, height = img.size
    n_pixels = width * height
    raw = bytearray(img.tobytes())  # RGBA bytes

    # XOR
    xor_bytes(raw, key_int & 0xFF)

    if shuffle:
        # group by pixel (4 bytes)
        pixels = [raw[i*4:(i+1)*4] for i in range(n_pixels)]
        perm = get_permutation(n_pixels, key_int)
        shuffled = bytearray()
        for idx in perm:
            shuffled.extend(pixels[idx])
        raw = shuffled

    out = Image.frombytes("RGBA", (width, height), bytes(raw))
    out.save(out_path)
    return out_path

def decrypt_image(in_path: str, out_path: str, key_int: int, shuffle: bool = True):
    img = Image.open(in_path).convert("RGBA")
    width, height = img.size
    n_pixels = width * height
    raw = bytearray(img.tobytes())

    if shuffle:
        pixels = [raw[i*4:(i+1)*4] for i in range(n_pixels)]
        perm = get_permutation(n_pixels, key_int)
        # inverse the permutation
        unshuffled = [None] * n_pixels
        for i, p in enumerate(perm):
            unshuffled[p] = pixels[i]
        raw = bytearray().join(unshuffled)

    xor_bytes(raw, key_int & 0xFF)
    out = Image.frombytes("RGBA", (width, height), bytes(raw))
    out.save(out_path)
    return out_path

# ---------- GUI ----------
class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        root.title("Image Pixel Encryptor")
        root.geometry("620x360")
        root.resizable(False, False)

        self.file_path = tk.StringVar()
        self.use_password = tk.BooleanVar(value=True)
        self.key_var = tk.StringVar(value="1234")
        self.shuffle_var = tk.BooleanVar(value=True)

        # Top frame - file select & preview
        top = tk.Frame(root, padx=12, pady=8)
        top.pack(fill="x")
        tk.Label(top, text="Image file:").grid(row=0, column=0, sticky="w")
        tk.Entry(top, textvariable=self.file_path, width=46).grid(row=0, column=1, padx=6)
        tk.Button(top, text="Browse", command=self.browse).grid(row=0, column=2)

        # preview area
        self.preview_label = tk.Label(root, text="Preview will appear here", width=60, height=8, bd=1, relief="solid")
        self.preview_label.pack(padx=12, pady=(6, 8))

        # key options
        frm_key = tk.Frame(root, padx=12)
        frm_key.pack(fill="x")
        tk.Radiobutton(frm_key, text="Use password", variable=self.use_password, value=True, command=self.update_key_mode).grid(row=0, column=0, sticky="w")
        tk.Radiobutton(frm_key, text="Use integer key", variable=self.use_password, value=False, command=self.update_key_mode).grid(row=0, column=1, sticky="w", padx=(8,0))

        tk.Label(frm_key, text="Password / Key:").grid(row=1, column=0, sticky="w", pady=(8,0))
        self.key_entry = tk.Entry(frm_key, textvariable=self.key_var, width=30)
        self.key_entry.grid(row=1, column=1, sticky="w", padx=(8,0), pady=(8,0))

        tk.Checkbutton(frm_key, text="Shuffle pixels (recommended)", variable=self.shuffle_var).grid(row=1, column=2, padx=12)

        # action buttons
        frm_actions = tk.Frame(root, padx=12, pady=12)
        frm_actions.pack()
        tk.Button(frm_actions, text="Encrypt ▶", width=14, bg="#45A29E", command=self.do_encrypt).grid(row=0, column=0, padx=8)
        tk.Button(frm_actions, text="Decrypt ◀", width=14, bg="#66FCF1", command=self.do_decrypt).grid(row=0, column=1, padx=8)
        tk.Button(frm_actions, text="Open Output Folder", command=self.open_output_folder).grid(row=0, column=2, padx=8)

        # status bar
        self.status = tk.Label(root, text="Select image, enter password/key, then Encrypt or Decrypt.", anchor="w")
        self.status.pack(fill="x", padx=12, pady=(4,8))

        # hold image preview reference
        self._preview_image = None
        self.update_key_mode()  # set initial mode

    def browse(self):
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.tiff")])
        if path:
            self.file_path.set(path)
            self.show_preview(path)

    def show_preview(self, path):
        try:
            img = Image.open(path)
            # resize to fit preview box but keep aspect ratio
            img.thumbnail((560, 140))
            self._preview_image = ImageTk.PhotoImage(img)
            self.preview_label.configure(image=self._preview_image, text="")
        except Exception as e:
            self.preview_label.configure(text=f"Preview error: {e}", image="")
            self._preview_image = None

    def update_key_mode(self):
        if self.use_password.get():
            self.key_entry.delete(0, tk.END)
            self.key_entry.config(show="")  # show text
            self.key_var.set("")  # empty placeholder
        else:
            self.key_entry.delete(0, tk.END)
            self.key_entry.config(show="")  # show integer text
            self.key_var.set("1234")

    def compute_key(self):
        raw = self.key_var.get()
        if self.use_password.get():
            if not raw:
                raise ValueError("Enter a password (non-empty).")
            return password_to_key(raw)
        else:
            try:
                return int(raw)
            except ValueError:
                raise ValueError("Integer key required when 'Use integer key' is selected.")

    def do_encrypt(self):
        path = self.file_path.get()
        if not path:
            messagebox.showwarning("No file", "Please select an image file first.")
            return
        try:
            key_int = self.compute_key()
        except ValueError as e:
            messagebox.showerror("Invalid key", str(e))
            return
        out = default_out_path(path, "enc")
        try:
            encrypt_image(path, out, key_int, shuffle=self.shuffle_var.get())
            self.status.config(text=f"Encrypted and saved: {out}")
            messagebox.showinfo("Done", f"Encrypted and saved:\n{out}")
            # refresh preview to show encrypted (optional)
            self.show_preview(out)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt: {e}")

    def do_decrypt(self):
        path = self.file_path.get()
        if not path:
            messagebox.showwarning("No file", "Please select an image file first.")
            return
        try:
            key_int = self.compute_key()
        except ValueError as e:
            messagebox.showerror("Invalid key", str(e))
            return
        out = default_out_path(path, "dec")
        try:
            decrypt_image(path, out, key_int, shuffle=self.shuffle_var.get())
            self.status.config(text=f"Decrypted and saved: {out}")
            messagebox.showinfo("Done", f"Decrypted and saved:\n{out}")
            self.show_preview(out)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt: {e}")

    def open_output_folder(self):
        path = self.file_path.get()
        if not path:
            messagebox.showwarning("No file", "No file selected.")
            return
        folder = os.path.dirname(path)
        if os.name == "nt":
            os.startfile(folder)
        else:
            try:
                os.system(f'xdg-open "{folder}"')
            except Exception:
                messagebox.showinfo("Folder", folder)

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
