# password_checker_gui.py
import tkinter as tk
from tkinter import messagebox
import re

# --- Password Strength Logic ---
def check_strength(password):
    length = len(password)
    lower = re.search(r"[a-z]", password)
    upper = re.search(r"[A-Z]", password)
    digit = re.search(r"[0-9]", password)
    special = re.search(r"[@$!%*?&]", password)

    if length < 6:
        return "Weak", "Password too short! Use at least 6 characters."
    elif lower and upper and digit and special and length >= 8:
        return "Strong", "Great! Your password is strong 💪"
    elif (lower or upper) and digit and length >= 6:
        return "Medium", "Good! Add uppercase, lowercase, and special characters to strengthen it."
    else:
        return "Weak", "Weak password! Try mixing letters, numbers, and symbols."


# --- GUI Application ---
def run_gui():
    def on_check():
        password = entry.get()
        if not password:
            messagebox.showwarning("Empty", "Please enter a password.")
            return
        strength, msg = check_strength(password)
        lbl_result.config(text=f"Strength: {strength}", fg=color_map[strength])
        messagebox.showinfo("Password Check", msg)

    def toggle_password():
        if entry.cget("show") == "":
            entry.config(show="*")
            btn_toggle.config(text="👁 Show")
        else:
            entry.config(show="")
            btn_toggle.config(text="🙈 Hide")

    def clear_fields():
        entry.delete(0, tk.END)
        lbl_result.config(text="")

    # --- Main Window ---
    root = tk.Tk()
    root.title("🔐 Password Strength Checker")
    root.geometry("520x350")
    root.resizable(False, False)
    root.configure(bg="#0B0C10")

    color_map = {"Weak": "#FF4C4C", "Medium": "#FFA500", "Strong": "#00FF99"}

    # --- Title ---
    tk.Label(
        root,
        text="🛡️ Password Strength Analyzer",
        font=("Consolas", 18, "bold"),
        fg="#66FCF1",
        bg="#0B0C10"
    ).pack(pady=20)

    # --- Input Frame ---
    frame_input = tk.Frame(root, bg="#0B0C10")
    frame_input.pack(pady=10)

    tk.Label(
        frame_input,
        text="Enter Password:",
        font=("Consolas", 13),
        fg="#C5C6C7",
        bg="#0B0C10"
    ).grid(row=0, column=0, padx=10, pady=5, sticky="e")

    entry = tk.Entry(
        frame_input,
        font=("Consolas", 13),
        width=25,
        bg="#1F2833",
        fg="#45A29E",
        insertbackground="white",
        show="*",
        relief="flat"
    )
    entry.grid(row=0, column=1, padx=10)

    btn_toggle = tk.Button(
        frame_input,
        text="👁 Show",
        font=("Consolas", 10),
        bg="#45A29E",
        fg="#0B0C10",
        width=8,
        bd=0,
        command=toggle_password
    )
    btn_toggle.grid(row=0, column=2, padx=5)

    # --- Buttons ---
    frame_buttons = tk.Frame(root, bg="#0B0C10")
    frame_buttons.pack(pady=15)

    btn_style = {"font": ("Consolas", 12, "bold"), "width": 13, "height": 1, "bd": 0, "relief": "flat", "cursor": "hand2"}

    tk.Button(frame_buttons, text="Check Strength", bg="#45A29E", fg="#0B0C10", command=on_check, **btn_style).grid(row=0, column=0, padx=8)
    tk.Button(frame_buttons, text="Clear", bg="#C5C6C7", fg="#0B0C10", command=clear_fields, **btn_style).grid(row=0, column=1, padx=8)

    # --- Result Label ---
    lbl_result = tk.Label(
        root,
        text="",
        font=("Consolas", 14, "bold"),
        bg="#0B0C10"
    )
    lbl_result.pack(pady=10)

    # --- Tips Section ---
    tk.Label(
        root,
        text="💡 Tip: Use upper, lower, digits & symbols for stronger passwords",
        fg="#C5C6C7",
        bg="#0B0C10",
        font=("Consolas", 10)
    ).pack(pady=8)

    # --- Footer ---
    footer = tk.Label(
        root,
        text="<< Developed by Mashallah Naveed :: Cybersecurity Intern 2025 >>",
        fg="#45A29E",
        bg="#0B0C10",
        font=("Consolas", 9)
    )
    footer.pack(side="bottom", pady=10)

    root.mainloop()


if __name__ == "__main__":
    run_gui()
