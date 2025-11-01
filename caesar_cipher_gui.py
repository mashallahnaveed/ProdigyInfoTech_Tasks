# caesar_cipher_gui.py
import tkinter as tk
from tkinter import messagebox
import string

# --- Core Cipher Logic ---
ALPHABET_LOWER = string.ascii_lowercase
ALPHABET_UPPER = string.ascii_uppercase

def caesar_shift_char(ch: str, shift: int) -> str:
    if ch.islower():
        i = ALPHABET_LOWER.index(ch)
        return ALPHABET_LOWER[(i + shift) % 26]
    if ch.isupper():
        i = ALPHABET_UPPER.index(ch)
        return ALPHABET_UPPER[(i + shift) % 26]
    return ch  # non-alpha characters unchanged

def encrypt(message: str, shift: int) -> str:
    shift = shift % 26
    return ''.join(caesar_shift_char(ch, shift) for ch in message)

def decrypt(ciphertext: str, shift: int) -> str:
    shift = (-shift) % 26
    return ''.join(caesar_shift_char(ch, shift) for ch in ciphertext)


# --- GUI Application ---
def run_caesar_gui():
    def handle_encrypt():
        text = entry_text.get("1.0", tk.END).strip()
        try:
            shift = int(entry_shift.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Shift must be an integer!")
            return
        result = encrypt(text, shift)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)

    def handle_decrypt():
        text = entry_text.get("1.0", tk.END).strip()
        try:
            shift = int(entry_shift.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Shift must be an integer!")
            return
        result = decrypt(text, shift)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)

    def handle_clear():
        entry_text.delete("1.0", tk.END)
        output_text.delete("1.0", tk.END)
        entry_shift.delete(0, tk.END)

    def copy_result():
        result = output_text.get("1.0", tk.END).strip()
        if result:
            root.clipboard_clear()
            root.clipboard_append(result)
            messagebox.showinfo("Copied", "Result copied to clipboard!")
        else:
            messagebox.showwarning("Empty", "No result to copy.")

    # --- Main Window ---
    root = tk.Tk()
    root.title("Caesar Cipher — Encrypt / Decrypt")
    root.geometry("600x500")
    root.configure(bg="#0B0C10")

    # --- Title ---
    title_label = tk.Label(
        root,
        text="🔐 Caesar Cipher Encryption Tool",
        font=("Consolas", 20, "bold"),
        fg="#66FCF1",
        bg="#0B0C10"
    )
    title_label.pack(pady=20)

    # --- Input Frame ---
    frame_input = tk.Frame(root, bg="#0B0C10")
    frame_input.pack(pady=10)

    input_label = tk.Label(frame_input, text="Enter your text:", fg="#C5C6C7", bg="#0B0C10", font=("Consolas", 12))
    input_label.pack(anchor="w")
    entry_text = tk.Text(frame_input, height=5, width=65, bg="#1F2833", fg="#45A29E", insertbackground="white", relief="flat", font=("Consolas", 11))
    entry_text.pack(pady=5)

    shift_label = tk.Label(frame_input, text="Shift (integer):", fg="#C5C6C7", bg="#0B0C10", font=("Consolas", 12))
    shift_label.pack(anchor="w", pady=(10, 0))
    entry_shift = tk.Entry(frame_input, width=10, justify="center", font=("Consolas", 11), bg="#1F2833", fg="#66FCF1", relief="flat")
    entry_shift.pack(pady=5)

    # --- Buttons ---
    frame_buttons = tk.Frame(root, bg="#0B0C10")
    frame_buttons.pack(pady=20)

    btn_style = {"font": ("Consolas", 12, "bold"), "width": 12, "height": 1, "bd": 0, "relief": "flat", "cursor": "hand2"}

    btn_encrypt = tk.Button(frame_buttons, text="Encrypt", bg="#45A29E", fg="#0B0C10", command=handle_encrypt, **btn_style)
    btn_encrypt.grid(row=0, column=0, padx=8)

    btn_decrypt = tk.Button(frame_buttons, text="Decrypt", bg="#66FCF1", fg="#0B0C10", command=handle_decrypt, **btn_style)
    btn_decrypt.grid(row=0, column=1, padx=8)

    btn_clear = tk.Button(frame_buttons, text="Clear", bg="#C5C6C7", fg="#0B0C10", command=handle_clear, **btn_style)
    btn_clear.grid(row=0, column=2, padx=8)

    btn_copy = tk.Button(frame_buttons, text="Copy Result", bg="#45A29E", fg="#0B0C10", command=copy_result, **btn_style)
    btn_copy.grid(row=0, column=3, padx=8)

    # --- Output Frame ---
    output_label = tk.Label(root, text="Result:", fg="#C5C6C7", bg="#0B0C10", font=("Consolas", 12))
    output_label.pack(anchor="w", padx=40)

    output_text = tk.Text(root, height=6, width=65, bg="#1F2833", fg="#66FCF1", insertbackground="white", relief="flat", font=("Consolas", 11))
    output_text.pack(pady=10)

    # --- Footer ---
    footer = tk.Label(root, text="A learning project for exploring classical encryption techniques ✨", fg="#C5C6C7", bg="#0B0C10", font=("Consolas", 10))
    footer.pack(side="bottom", pady=10)

    # --- Run App ---
    root.mainloop()


# --- Run GUI if executed directly ---
if __name__ == "__main__":
    run_caesar_gui()