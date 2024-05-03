import subprocess
import os
import sys

required_packages = [
    'cryptography',
    'bcrypt',
]

# Check and install required packages
for package in required_packages:
    try:
        __import__(package)
        print(f"{package} is already installed.")
    except ImportError:
        print(f"{package} not found. Installing...")
        subprocess.run(['pip', 'install', package])

import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import bcrypt

# Utility function to clear the console
def clear_console():
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # macOS and Linux
        os.system('clear')

# Function to derive a cryptographic key
def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32  # 256-bit key
    )
    key = kdf.derive(passphrase.encode())
    return key

# Function to create a deterministic IV from passphrase and salt
def derive_iv(passphrase, salt):
    hash = hashes.Hash(hashes.SHA256())
    hash.update(passphrase.encode())
    hash.update(salt)
    iv = hash.finalize()[:16]  # AES block size
    return iv

# Function to encrypt text
def custom_encrypt(text, passphrase, salt):
    key = derive_key(passphrase, salt)
    iv = derive_iv(passphrase, salt)  # Deterministic IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode())
    encrypted_text += encryptor.finalize()
    tag = encryptor.tag  # Get the encryption tag
    return encrypted_text + tag  # Return encrypted text and tag together

# Function to decrypt text
def custom_decrypt(encrypted_text, passphrase, salt):
    key = derive_key(passphrase, salt)
    iv = derive_iv(passphrase, salt)  # Deterministic IV
    tag = encrypted_text[-16:]  # Last 16 bytes are the GCM tag
    encrypted_text = encrypted_text[:-16]  # Remove the tag from the encrypted data
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    return decrypted_text

# Main function to display the menu and handle choices
def main():
    salt = os.urandom(16)  # Generate a random salt

    while True:
        print("\nMenu")
        print("1. Encrypt a sentence")
        print("2. Decrypt a sentence")
        print("3. Encrypt a text file to .crybill and delete the original")
        print("4. Decrypt an encrypted .crybill file and create a new .txt file")
        print("5. Exit")

        choice = input("Enter your choice (1, 2, 3, 4, or 5): ")

        if choice == '1':
            # Encrypt a sentence
            sentence_to_encrypt = input("Enter the sentence to encrypt: ")
            password = input("Enter a password for encryption: ")
            encrypted_text = custom_encrypt(sentence_to_encrypt, password, salt)

            # Display the results
            print("Encrypted Sentence:", urlsafe_b64encode(encrypted_text).decode())
            print("Salt:", urlsafe_b64encode(salt).decode())

            # Clear the console and display the menu again
            input("\nPress Enter to continue...")
            clear_console()

        elif choice == '2':
            # Decrypt a sentence
            try:
                encrypted_text_input = input("Enter the encrypted text: ")
                salt_input = input("Enter the salt: ")

                # Decode input values
                encrypted_text = urlsafe_b64decode(encrypted_text_input.encode())
                salt = urlsafe_b64decode(salt_input.encode())

                password = input("Enter the password for decryption: ")

                decrypted_text = custom_decrypt(encrypted_text, salt, password)

                # Display the decrypted text
                print("Decrypted Sentence:", decrypted_text.decode())

                # Clear the console and display the menu again
                input("\nPress Enter to continue...")
                clear_console()

            except Exception as e:
                print(f"Decryption error: {e}")

        elif choice == '3':
            # Encrypt a text file to .crybill and delete the original
            text_file_path = input("Drag and drop a text file to encrypt: ")
            if not os.path.isfile(text_file_path):
                print("Invalid file path. Please try again.")
                continue

            with open(text_file_path, 'r') as file:
                file_content = file.read()

            password = input("Enter a password for encryption: ")
            salt = os.urandom(16)  # New unique salt for each encryption

            encrypted_text = custom_encrypt(file_content, password, salt)

            # Save the encrypted content to a .crybill file
            crybill_file_path = text_file_path + '.crybill'
            with open(crybill_file_path, 'wb') as encrypted_file:
                encrypted_file.write(urlsafe_b64encode(encrypted_text))
                encrypted_file.write(b'\n')
                encrypted_file.write(urlsafe_b64encode(salt))

            # Delete the original .txt file
            os.remove(text_file_path)

            print(f"File encrypted and saved as {crybill_file_path}. Original .txt file has been deleted.")

            # Clear the console and display the menu again
            input("\nPress Enter to continue...")
            clear_console()

        elif choice == '4':
            # Decrypt an encrypted .crybill file and create a new .txt file
            crybill_file_path = input("Drag and drop an encrypted .crybill file to decrypt: ")
            if not os.path.isfile(crybill_file_path):
                print("Invalid file path. Please try again.")
                continue

            with open(crybill_file_path, 'rb') as encrypted_file:
                # Read the encrypted content and salt from the .crybill file
                lines = encrypted_file.readlines()
                encrypted_text = urlsafe_b64decode(lines[0].strip())
                salt = urlsafe_b64decode(lines[1].strip())

            password = input("Enter a password for decryption: ")

            try:
                decrypted_text = custom_decrypt(encrypted_text, password, salt)

                # Create a new .txt file with the decrypted content
                new_text_file_path = crybill_file_path.replace('.crybill', '_decrypted.txt')
                with open(new_text_file_path, 'w') as new_file:
                    new_file.write(decrypted_text.decode())

                print(f"File decrypted and saved as {new_text_file_path}.")

                # Clear the console and display the menu again
                input("\nPress Enter to continue...")
                clear_console()

            except Exception as e:
                print(f"Decryption error: {e}")

        elif choice == '5':
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")

if __name__ == "__main__":
    main()
