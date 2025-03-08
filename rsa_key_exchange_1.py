from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# RSA-based key exchange involves one party generating a symmetric key and securely sending it to another party
# using RSA encryption. This method is often used in hybrid encryption systems.

# Step 1: Generate RSA key pairs for Alice and Bob
# - Alice and Bob each generate their own RSA key pairs
alice_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
alice_public_key = alice_private_key.public_key()

bob_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
bob_public_key = bob_private_key.public_key()

# Step 2: Alice generates a symmetric AES key to use for encryption
symmetric_key = os.urandom(32)  # 256-bit AES key
print("Generated AES Key (hex):", symmetric_key.hex())

# Step 3: Alice encrypts the AES key using Bob’s public RSA key
# - This ensures that only Bob (who has the private key) can decrypt it
encrypted_symmetric_key = bob_public_key.encrypt(
    symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Encrypted AES Key (hex):", encrypted_symmetric_key.hex())

# Step 4: Bob receives the encrypted AES key and decrypts it using his private RSA key
# - This allows Bob to retrieve the original symmetric key

decrypted_symmetric_key = bob_private_key.decrypt(
    encrypted_symmetric_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Ensure that the decrypted key matches the original
assert decrypted_symmetric_key == symmetric_key
print("Decrypted AES Key (hex):", decrypted_symmetric_key.hex())

# Step 5: Use the shared symmetric AES key for message encryption
iv = os.urandom(16)  # AES block size is 128 bits (16 bytes)
cipher = Cipher(algorithms.AES(decrypted_symmetric_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Sample message to encrypt
plaintext = b"This is a secure message using RSA key exchange and AES"

# Padding is required since AES operates on fixed-size blocks
from cryptography.hazmat.primitives import padding
padder = padding.PKCS7(128).padder()
padded_plaintext = padder.update(plaintext) + padder.finalize()

# Encrypt the message
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
print("Encrypted ciphertext (hex):", ciphertext.hex())

# Step 6: Bob decrypts the message using the symmetric key
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

# Remove padding
unpadder = padding.PKCS7(128).unpadder()
decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()
print("Decrypted text:", decrypted_text.decode())
