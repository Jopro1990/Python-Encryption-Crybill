import subprocess
import random
import os

# List of required packages
required_packages = [
    'cryptography',
    'bcrypt',
    'colorama',
]

# Check and install required packages
for package in required_packages:
    try:
        __import__(package)
        print(f"{package} is already installed.")
    except ImportError:
        print(f"{package} not found. Installing...")
        subprocess.run(['pip', 'install', package])

# Import the required modules after installing dependencies
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from colorama import init, Fore
import bcrypt

init(autoreset=True)

def hash_password(password):
    # Use bcrypt to hash the password
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed

def verify_password(hashed, password):
    # Verify the password against the stored hash
    return bcrypt.checkpw(password.encode(), hashed)

def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # Adjust the number of iterations based on your security requirements
        salt=salt,
        length=32  # 256-bit key
    )
    key = kdf.derive(passphrase.encode())
    return key

def custom_encrypt(text, passphrase, salt, iv):
    key = derive_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(text.encode()) + encryptor.finalize()
    return encrypted_text, encryptor.tag, iv

def custom_decrypt(encrypted_text, tag, iv, passphrase, salt):
    key = derive_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    return decrypted_text

def print_colored(text, color=Fore.WHITE):
    print(color + text)

def self_destruct():
    print_colored("Self-destruct initiated...", Fore.RED)
    try:
        # Get the absolute path of the current script
        script_path = os.path.abspath(__file__)

        # Delete the script file
        os.remove(script_path)

        print_colored("Self-destruct complete. The script has been deleted.", Fore.RED)

    except Exception as e:
        print_colored(f"Error during self-destruct: {e}", Fore.RED)

def main():
    correct_password_hashed = hash_password("Eselsreiter345+")
    max_attempts = 3
    attempts = 0

    while attempts < max_attempts:
        entered_password = input("Password: ")

        if not verify_password(correct_password_hashed, entered_password):
            attempts += 1
            print_colored(f"Incorrect password. Attempts remaining: {max_attempts - attempts}", Fore.RED)

            if attempts == max_attempts:
                self_destruct()
                return

        else:
            print_colored("Welcome to Crybill Encryption!", Fore.GREEN)
            print_colored("""
 ██████╗██████╗ ██╗   ██╗██████╗ ██╗██╗     ██╗     
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██║██║     ██║     
██║     ██████╔╝ ╚████╔╝ ██████╔╝██║██║     ██║     
██║     ██╔══██╗  ╚██╔╝  ██╔══██╗██║██║     ██║     
╚██████╗██║  ██║   ██║   ██████╔╝██║███████╗███████╗
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝╚══════╝╚══════╝
          """,Fore.GREEN)


            salt = os.urandom(16)  # Generate a random salt

            while True:
                print("\nMenu")
                print_colored("1. Encrypt a sentence", Fore.GREEN)
                print_colored("2. Decrypt a sentence", Fore.BLUE)
                print_colored("3. Exit", Fore.RED)

                choice = input("Enter your choice (1, 2, or 3): ")

                if choice == '1':
                    # Generate a random IV
                    iv = os.urandom(16)

                    # Get user input for the sentence to encrypt
                    sentence_to_encrypt = input("Enter the sentence to encrypt: ")

                    # Encrypt the sentence
                    encrypted_text, tag, _ = custom_encrypt(sentence_to_encrypt, entered_password, salt, iv)

                    # Display the results
                    print_colored("Encrypted Sentence:", Fore.YELLOW)
                    print_colored(urlsafe_b64encode(encrypted_text).decode(), Fore.YELLOW)
                    print_colored("Tag:", Fore.YELLOW)
                    print_colored(urlsafe_b64encode(tag).decode(), Fore.YELLOW)
                    print_colored("IV:", Fore.YELLOW)
                    print_colored(urlsafe_b64encode(iv).decode(), Fore.YELLOW)

                elif choice == '2':
                    try:
                        # Get user input for the encrypted text, tag, and IV
                        encrypted_text_input = input("Enter the encrypted text: ")
                        tag_input = input("Enter the tag: ")
                        iv_input = input("Enter the IV: ")

                        # Decode input values
                        encrypted_text = urlsafe_b64decode(encrypted_text_input.encode())
                        tag = urlsafe_b64decode(tag_input.encode())
                        iv = urlsafe_b64decode(iv_input.encode())

                        # Decrypt the sentence
                        decrypted_text = custom_decrypt(encrypted_text, tag, iv, entered_password, salt)

                        # Display the decrypted text
                        print_colored("Decrypted Sentence:", Fore.YELLOW)
                        print_colored(decrypted_text.decode(), Fore.YELLOW)

                    except Exception as e:
                        print_colored(f"Decryption error: {e}", Fore.RED)

                elif choice == '3':
                    print_colored("Exiting the program. Goodbye!", Fore.RED)
                    break

                else:
                    print_colored("Invalid choice. Please enter 1, 2, or 3.", Fore.RED)

if __name__ == "__main__":
    main()
