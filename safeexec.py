import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Encryption Key Size
KEY_SIZE = 32
BLOCK_SIZE = 16

class SafeExec:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SafeExec - Executable Encryption Tool")
        self.root.geometry("400x300")

        self.file_path = ""
        self.init_gui()

    def init_gui(self):
        tk.Label(self.root, text="SafeExec", font=("Arial", 20)).pack(pady=10)

        # File Selection
        tk.Button(self.root, text="Select File", command=self.select_file).pack(pady=5)
        self.file_label = tk.Label(self.root, text="No file selected", wraplength=300)
        self.file_label.pack(pady=5)

        # Password Entry
        tk.Label(self.root, text="Enter Password:").pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack(pady=5)

        # Buttons for Encrypt and Decrypt
        tk.Button(self.root, text="Encrypt", command=self.encrypt_file).pack(pady=5)
        tk.Button(self.root, text="Decrypt", command=self.decrypt_file).pack(pady=5)

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
        if self.file_path:
            self.file_label.config(text=self.file_path)

    def encrypt_file(self):
        password = self.password_entry.get()
        if not self.file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return

        try:
            with open(self.file_path, "rb") as f:
                data = f.read()

            key = self._get_key(password)
            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE))

            with open(self.file_path + ".enc", "wb") as f:
                f.write(cipher.iv + ciphertext)

            messagebox.showinfo("Success", "File encrypted successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def decrypt_file(self):
        password = self.password_entry.get()
        if not self.file_path or not password:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return

        try:
            with open(self.file_path, "rb") as f:
                iv = f.read(16)
                ciphertext = f.read()

            key = self._get_key(password)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)

            original_file = self.file_path.replace(".enc", "_decrypted.exe")
            with open(original_file, "wb") as f:
                f.write(plaintext)

            messagebox.showinfo("Success", f"File decrypted successfully as {original_file}.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def _get_key(self, password):
        return pad(password.encode(), KEY_SIZE)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = SafeExec()
    app.run()
