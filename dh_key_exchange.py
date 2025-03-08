from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Diffie-Hellman (DH) is a key exchange algorithm that allows two parties to securely share a secret key
# - The shared secret key can then be used for symmetric encryption (e.g., AES)
# - The key exchange happens over an insecure channel without exposing the secret key

# Step 1: Generate Diffie-Hellman (DH) parameters (only needs to be done once)
print("Initializing")
dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

# Step 2: Alice generates her private and public key pair
print("Generating Alice's keys")
alice_private_key = dh_parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

# Step 3: Bob generates his private and public key pair
print("Generating Bob's keys")
bob_private_key = dh_parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

# Step 4: Exchange public keys between Alice and Bob (in a real-world scenario, this would happen over a network)
print("Alice and Bob exchange public keys...(over a network)")
#   Diffie-Hellman (DH) is an asymmetric cryptographic algorithm 
#   used to establish a shared secret over an insecure channel. 
#   It allows two parties, Alice and Bob, to generate the same 
#   shared key without ever transmitting it directly.
#   Since Alice and Bob independently derive the same shared secret,
#   it can now be used for symmetric encryption (like AES).

# Step 5: Compute the shared secret
# - Both Alice and Bob use their private key and the other party's public key to derive the same shared secret
print("Generating shared secret")
alice_shared_secret = alice_private_key.exchange(bob_public_key)
bob_shared_secret = bob_private_key.exchange(alice_public_key)

# The shared secrets must be the same
assert alice_shared_secret == bob_shared_secret

# Step 6: Derive a symmetric key from the shared secret using HKDF
# - HKDF (HMAC-based Extract-and-Expand Key Derivation Function) ensures the key is cryptographically strong
symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES-256 encryption
        salt=None,  # Salt can be used for additional security, but is optional
        info=b"key exchange",  # Additional context (optional)
        backend=default_backend()
    ).derive(alice_shared_secret)  # Either party's shared secret will produce the same key

print("Derived AES Key (hex):", symmetric_key.hex())

# Step 7: Encrypt a message using AES-CBC with the derived symmetric key
iv = os.urandom(16)  # AES block size is 128 bits (16 bytes)
cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Sample message to encrypt
plaintext = b"This is a secret message encrypted using AES and a shared secret after DH key exchange"

# Padding is required since AES operates on fixed-size blocks
padder = padding.PKCS7(128).padder()
padded_plaintext = padder.update(plaintext) + padder.finalize()

# Encrypt the message
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
print("Encrypted ciphertext (hex):", ciphertext.hex())

# Step 8: Decrypt the message
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

# Remove padding
unpadder = padding.PKCS7(128).unpadder()
decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()
print("Decrypted text:", decrypted_text.decode())
