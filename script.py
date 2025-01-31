import random
import os
import json
import sys
import argparse
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import platform
import shutil
import getpass
import pwinput
from typing import Tuple, Optional


# Constants
SPECIAL_CHARS = ['!', '@', '#', '$', '%', '^', '&', '£', '*', '(', ')', ';', ':', '-', 'ò', 'ç', '°', '§', 'é', 'è', '[', ']', '+', '*', '=', '|', '/', '"', ',', '<', '>']
SALT = b'salt_'
IV_SIZE = 16  # 16 bytes for AES
METADATA_SIZE = 8  # 8 bytes for metadata
CHUNK_SIZE = 64 * 1024  # 64 KB chunks

# Global variables as in original code
KEY_FILE = None
ENC_KEY = None
METADATA = None

def get_key_file_path():
    """Get the central path for storing the encryption keys across all platforms."""
    if platform.system() == "Windows":
        key_dir = os.path.join(os.getenv('PROGRAMDATA'), 'terminal_encryption')
    else:
        key_dir = os.path.join(os.path.expanduser("~"), ".config", "terminal_encryption")
    
    os.makedirs(key_dir, exist_ok=True)
    return os.path.join(key_dir, "encryption_keys.json")


def generate_key(user_key):
    """Generate an AES-256 key from the user's key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(user_key.encode())

def encrypt_file(file_path, key, remove_original=False):
    """Encrypt a single file using AES-256 and create a copy with .enc extension."""
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    encrypted_file_path = file_path + '.enc'
    try:
        with open(file_path, 'rb') as in_file, open(encrypted_file_path, 'wb') as out_file:
            # Write metadata as binary
            out_file.write(METADATA.encode('utf-8'))  # Ensure metadata is properly encoded if intended as text
            out_file.write(iv)
            
            while True:
                chunk = in_file.read(CHUNK_SIZE)
                if not chunk:
                    break
                padded_chunk = padder.update(chunk)
                encrypted_chunk = encryptor.update(padded_chunk)
                out_file.write(encrypted_chunk)
            
            final_padded_chunk = padder.finalize()
            final_encrypted_chunk = encryptor.update(final_padded_chunk) + encryptor.finalize()
            out_file.write(final_encrypted_chunk)
        
        if remove_original:
            os.remove(file_path)
        print(f"Encrypted and copied: {file_path} -> {encrypted_file_path}")
    except Exception as e:
        print(f"Encryption failed for: {file_path}. Error: {str(e)}")
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)

def decrypt_file(file_path, key, remove_enc=False):
    """Decrypt a single file using AES-256."""
    decrypted_file_path = file_path[:-4] if file_path.endswith('.enc') else f'{file_path.split(".")[0]}_dec.{file_path.split(".")[1]}'
    try:
        with open(file_path, 'rb') as in_file:
            # Read metadata as binary
            metadata = in_file.read(METADATA_SIZE)
            # print(f"Raw metadata read: {metadata}")  # Debug line to check raw metadata

            # Ensure you are handling metadata correctly
            iv = in_file.read(IV_SIZE)  # Read IV as binary
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

            with open(decrypted_file_path, 'wb') as out_file:
                while True:
                    chunk = in_file.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    decrypted_chunk = decryptor.update(chunk)
                    unpadded_chunk = unpadder.update(decrypted_chunk)
                    out_file.write(unpadded_chunk)

                final_decrypted_chunk = decryptor.finalize()
                final_unpadded_chunk = unpadder.update(final_decrypted_chunk) + unpadder.finalize()
                out_file.write(final_unpadded_chunk)

        if remove_enc:
            os.remove(file_path)
        print(f"Decrypted: {file_path} -> {decrypted_file_path}")
    except PermissionError as e:
        print(f"Permission denied for file: {file_path}. Error: {e}")
    except Exception as e:
        print(f"Decryption failed for: {file_path}. Error: {str(e)}")
        if os.path.exists(decrypted_file_path):
            os.remove(decrypted_file_path)
def process_directory(directory, key, action, passkey=None):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if action == 'encrypt' and not file.endswith('.enc'):
                encrypt_file(file_path, key, True)
            elif action == 'decrypt' and file.endswith('.enc'):
                try:
                    if passkey is None:
                        raise ValueError("Passkey is not provided for decryption")
                    decryption_key = get_decryption_key(passkey, file_path)
                    file_key = generate_key(decryption_key)
                    decrypt_file(file_path, file_key, True)
                except Exception as e:
                    print(f"Failed to process {file_path}: {str(e)}")

def get_metadata_e(key):
    """Extract metadata information from the key."""
    MM_start = key.find('MM')
    NN_start = key.find('NN')
    return MM_start != -1, NN_start != -1, max(MM_start, 0), max(NN_start, 0)

def generate_encryption_key(key):
    """Generate the encryption key and metadata."""
    M_valid, N_valid, MM_start, NN_start = get_metadata_e(key)
    today_date = datetime.now().strftime('%d')[::]
    today_month = datetime.now().strftime('%m')
    
    key = key.replace('MM', today_month)
    key = key.replace('NN', today_date)
    
    metadata = "".join(['1' if M_valid else '0', '1' if N_valid else '0', 
                        str(MM_start), str(NN_start), str(today_month), str(today_date)])
    return key, metadata

def get_metadata(filePath):
    """Extract metadata from an encrypted file."""
    metadata = None
    with open(filePath, 'rb') as f:
        metadata = f.read(METADATA_SIZE)
    metadata = metadata.decode()
    return (metadata[:1] == '1', metadata[1:2] == '1', int(metadata[2:3]), 
            int(metadata[3:4]), metadata[4:6], metadata[6:8])

def check_and_generate_decryption_key(key, M_st, N_st, enc_month, enc_date):
    """Check and generate the decryption key based on metadata, reversing MM or NN if any special character is in the key."""
    today_date = datetime.now().strftime('%d')
    today_month = datetime.now().strftime('%m')
    
    # Check if any special character exists anywhere in the key
    special_char_in_key = any(char in SPECIAL_CHARS for char in key)
    
    if M_st is not None:
        month = key[M_st:M_st + 2]
        # Reverse the month if any special character is found in the key
        if special_char_in_key:
            month = month[::-1]
        if month != today_month:
            print("Invalid key. Exiting...")
            sys.exit(1)
        key = key[:M_st] + enc_month + key[M_st + 2:]

    if N_st is not None:
        date = key[N_st:N_st + 2]
        # Reverse the date if any special character is found in the key
        if special_char_in_key:
            date = date[::-1]
        if date != today_date:
            print("Invalid key. Exiting...")
            sys.exit(1)
        key = key[:N_st] + enc_date + key[N_st + 2:]

    return key

def get_decryption_key(key, path):
    """Get the decryption key for a file."""
    M_valid, N_valid, MM_start, NN_start, enc_month, enc_date = get_metadata(path)
    if not M_valid:
        MM_start = None
    if not N_valid:
        NN_start = None
    key = check_and_generate_decryption_key(key, MM_start, NN_start, enc_month, enc_date)
    return key

def main():
    global KEY_FILE, METADATA
    KEY_FILE = get_key_file_path()
    parser = argparse.ArgumentParser(description="File Encryption and Decryption Tool (AES-256)")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform")
    parser.add_argument('paths', nargs='+', help="Files or directories to process")
    args = parser.parse_args()

    if args.action == 'encrypt':
        userkey = pwinput.pwinput("Enter your key: ")
        if len(userkey) != 7:
            print("Enter a key having exactly 7 chars")
            exit(1)
        ## added confirmation key feature for better usability
        confirm_key = pwinput.pwinput("Re-enter your key for confirmation: ")
        if userkey != confirm_key:
            print("Keys do not match. Exiting...")
            exit(1)
        ENC_KEY = userkey
        final_key, metadata = generate_encryption_key(userkey)
        METADATA = metadata
       ##print(f"Generated Key: {final_key}")
        key = generate_key(final_key)

        for path in args.paths:
            if path.endswith('/') or path.endswith('\\'):
                path = path[:-1]
            if os.path.isfile(path):
                if not path.endswith('.enc'):
                    encrypt_file(path, key)
            elif os.path.isdir(path):
                new_dir_name = path + '_enc'
                if not os.path.exists(new_dir_name):
                    shutil.copytree(path, new_dir_name)
                process_directory(new_dir_name, key, 'encrypt')
                print(f"Encrypted directory and created a copy: {path} -> {new_dir_name}")
            else:
                print(f"Invalid path: {path}")

    elif args.action == 'decrypt':
        passkey = pwinput.pwinput(prompt="Enter key for Decryption: ")
        if len(passkey) != 7:
            print("incorrect key")
            exit(1)

        for path in args.paths:
            if path.endswith('/') or path.endswith('\\'):
                path = path[:-1]
            if os.path.isfile(path):
                if path.endswith('.enc'):
                    decryption_key = get_decryption_key(passkey, path)
                    key = generate_key(decryption_key)
                    decrypt_file(path, key)
            elif os.path.isdir(path):
                new_dir_name = path[:-4] if path.endswith('_enc') else path + '_dec'
                if os.path.exists(new_dir_name):
                    new_dir_name += '_' + str(random.randint(1, 100))
                shutil.copytree(path, new_dir_name)
                process_directory(new_dir_name, None, 'decrypt', passkey)
                print(f"Decrypted directory and created a copy: {path} -> {new_dir_name}")
            else:
                print(f"Invalid path: {path}")

if __name__ == "__main__":
    main()
