#!/bin/python3

import sys
from Cryptodome.Cipher import AES

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def decrypt_file(encrypted_file, key):
    try:
        with open(encrypted_file, 'rb') as f:
            iv = f.read(AES.block_size)
            encrypted_data = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_data = unpad(cipher.decrypt(encrypted_data))

        with open(encrypted_file+'.decrypt', 'wb') as f:
            f.write(decrypted_data)

        print(f"Decryption successful. Decrypted file saved as: {encrypted_file+'.decrypt'}")

    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python aes_decrypt.py <encrypted_file> <encryption_key>")
        sys.exit(1)

    encrypted_file = sys.argv[1]
    key = bytearray.fromhex(sys.argv[2])

    if len(key) not in [16, 24, 32]:
        print("Error: Encryption key must be 16, 24, or 32 bytes long.")
        sys.exit(1)

    decrypt_file(encrypted_file, key)

if __name__ == '__main__':
    main()
