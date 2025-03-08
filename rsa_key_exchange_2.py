from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# RSA-based key exchange and message encryption workflow
# - Alice encrypts an AES key using Bob's public key and signs it with her private key
# - Alice then encrypts a message using AES and sends both the AES-encrypted message and the IV to Bob
# - Bob decrypts the AES key using his private RSA key and verifies Alice's signature
# - Bob uses the decrypted AES key to decrypt the received message

# Step 1: Generate RSA key pairs for Alice and Bob
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

# Step 3: Alice signs the AES key using her private RSA key to prove authenticity
signature = alice_private_key.sign(
    symmetric_key,
    asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Signature (hex):", signature.hex())

# Step 4: Alice encrypts the AES key using Bob’s public RSA key for secure transmission
encrypted_symmetric_key = bob_public_key.encrypt(
    symmetric_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Encrypted AES Key (hex):", encrypted_symmetric_key.hex())

# Step 5: Alice encrypts the message using the AES key
iv = os.urandom(16)  # AES block size is 128 bits (16 bytes)
cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Sample message to encrypt
plaintext = b"This is a secure message using RSA key exchange and AES"

# Padding is required since AES operates on fixed-size blocks
padder = padding.PKCS7(128).padder()
padded_plaintext = padder.update(plaintext) + padder.finalize()

# Encrypt the message
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
print("Encrypted Message (hex):", ciphertext.hex())
print("IV (hex):", iv.hex())

# Alice sends (encrypted_symmetric_key, ciphertext, iv) to Bob

# Step 6: Bob decrypts the AES key using his private RSA key
decrypted_symmetric_key = bob_private_key.decrypt(
    encrypted_symmetric_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Step 7: Bob verifies Alice’s signature using her public key
try:
    alice_public_key.verify(
        signature,
        decrypted_symmetric_key,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature verification successful: The key came from Alice.")
except:
    print("Signature verification failed!")
    exit()

# Step 8: Bob decrypts the message using the AES key and IV
cipher = Cipher(algorithms.AES(decrypted_symmetric_key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

# Remove padding
unpadder = padding.PKCS7(128).unpadder()
decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()
print("Decrypted text:", decrypted_text.decode())
