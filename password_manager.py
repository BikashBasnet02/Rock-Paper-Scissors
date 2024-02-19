from cryptography.fernet import Fernet
import os

# Function to generate and save the encryption key
def generate_key():
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)

# Function to load the encryption key
def load_key():
    if not os.path.exists("key.key"):
        generate_key()
    with open("key.key", "rb") as key_file:
        return key_file.read()

# Function to encrypt data
def encrypt_data(data, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data.encode())

# Function to decrypt data
def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_data).decode()

# Function to view passwords
def view_passwords(key):
    try:
        with open('passwords.txt', 'r') as f:
            for line in f:
                if "|" in line:
                    account, pwd = line.split('|')
                    print(f"Account: {account.strip()}, Password: {decrypt_data(pwd.strip().encode(), key)}")
    except FileNotFoundError:
        print("No passwords stored yet.")

# Function to add a new password
def add_password(key):
    account = input("Enter the account name: ")
    password = input("Enter the password: ")
    with open('passwords.txt', 'a') as f:
        encrypted_pwd = encrypt_data(password, key)
        f.write(f"{account} | {encrypted_pwd.decode()}\n")
    print("Password added successfully!")

def main():
    print("Welcome to the Password Manager!")
    key = load_key()
    while True:
        mode = input("Would you like to add a new password or view existing ones? (add/view/q to quit): ").lower()
        if mode == "q":
            print("Goodbye!")
            break
        elif mode == "add":
            add_password(key)
        elif mode == "view":
            view_passwords(key)
        else:
            print("Invalid input. Please try again.")

if __name__ == "__main__":
    main()
