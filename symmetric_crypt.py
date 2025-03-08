import os
import hashlib
from cryptography.hazmat.primitives import padding  # Padding module for PKCS7 padding scheme
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Import AES cipher and modes
from cryptography.hazmat.backends import default_backend  # Default cryptographic backend

# AES encryption requires a secret key. AES-256 uses a 32-byte (256-bit) key.
# Instead of using a random key, we derive one from a password.
password = "my password"  # User-defined password
print("Password:", password)

# Convert the password into a 256-bit key using SHA-256 hashing.
# - SHA-256 always outputs a 32-byte hash, which is perfect for AES-256.
key = hashlib.sha256(password.encode()).digest()  # Generate a fixed-size 256-bit key

# Initialization Vector (IV):
# - Used in Cipher Block Chaining (CBC) mode to introduce randomness.
# - Ensures the same plaintext encrypts to different ciphertexts.
# - The IV must be unique per encryption operation but does not need to be secret.
iv = os.urandom(16)  # AES block size is 128 bits (16 bytes), so the IV must be 16 bytes long

print("AES Key (hex):", key.hex())  # Display the derived key in hex format
print("Initialization Vector (IV) (hex):", iv.hex())  # Display the IV in hex format

# Sample plaintext message to encrypt
plaintext = b"this is my secret in plaintext"  # User-defined message in bytes
print("Original plaintext:", plaintext)

# PKCS7 padding ensures that plaintext is a multiple of the AES block size (128 bits / 16 bytes).
# - AES operates on fixed-size blocks, meaning messages shorter than a full block require padding.
# - PKCS7 padding appends extra bytes to match the required block size.
padder = padding.PKCS7(128).padder()  # 128-bit padding (AES block size is 16 bytes)
padded_plaintext = padder.update(plaintext) + padder.finalize()  # Apply padding

# Explanation of padding:
# - `padder.update(plaintext)`: Adds as much padding as possible to the input data.
# - `padder.finalize()`: Completes the padding process, ensuring correct alignment.

# AES encryption in CBC mode requires a key and an IV.
# - Each plaintext block is XORed with the previous ciphertext block before encryption.
# - The IV acts as the 'previous' block for the first plaintext block.
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

# Create an encryptor object from the cipher
encryptor = cipher.encryptor()

# Encrypt the padded plaintext
# - The encryptor processes data block by block.
# - `update()` encrypts as much data as possible in chunks.
# - `finalize()` completes the encryption and handles any remaining data.
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
print("Encrypted ciphertext (hex):", ciphertext.hex())  # Convert ciphertext to hex for readable output

# Decryption process:
# - Uses the same key and IV as encryption.
# - Decrypts the ciphertext back to a padded plaintext.
# - Padding must then be removed to recover the original message.
decryptor = cipher.decryptor()

# Decrypt the ciphertext back to padded plaintext
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

# PKCS7 padding must be removed after decryption to restore the original plaintext.
# - Unpadding reverses the padding process.
# - Ensures that we only get the original message without extra bytes.
unpadder = padding.PKCS7(128).unpadder()
decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()

print("Decrypted text:", decrypted_text)  # Output should match the original plaintext
