from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm that uses a key pair:
# - The **public key** is used to encrypt data.
# - The **private key** is used to decrypt data.
# - This allows secure communication where only the intended recipient (holding the private key) can decrypt the message.

# Generate RSA Key Pair
# - The key size determines security strength (2048-bit is common for strong security).
# - The public exponent (65537) is a commonly used prime number for security.
private_key = rsa.generate_private_key(
        public_exponent=65537,  # Common exponent providing a good balance of security and performance
        key_size=2048  # RSA key size in bits (larger keys increase security but reduce performance)
    )

# Extract the public key from the private key
public_key = private_key.public_key()

# Serialize keys to PEM format (optional, for saving or sharing keys)
# - **PEM (Privacy-Enhanced Mail)** is a widely used format for encoding cryptographic keys and certificates.
# - **PKCS8 (Public-Key Cryptography Standards #8)** is a standard for storing private keys.
# - **SubjectPublicKeyInfo** is the standard format for storing public keys.
private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # Encode key in PEM format (Base64 with headers)
        format=serialization.PrivateFormat.PKCS8,  # Store private key in PKCS8 format (standardized private key storage)
        encryption_algorithm=serialization.NoEncryption()  # No password encryption (for simplicity; use password for security)
    )

public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # Encode key in PEM format
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard format for public keys
    )

# Print out the keys in PEM format (for reference; in real-world scenarios, store these securely)
print("Private Key (PEM):\n", private_pem.decode())
print("Public Key (PEM):\n", public_pem.decode())

# Sample plaintext message to encrypt
plaintext = b"this is my secret in plaintext"  # Message must be in bytes
print("Original plaintext:", plaintext)

# Encrypt the plaintext using the public key
# - This ensures that only someone with the private key can decrypt it.
ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function (MGF1) using SHA-256
                    algorithm=hashes.SHA256(),  # Hash function used for OAEP padding
                    label=None  # Optional label; typically not used (must match during decryption)
                )
    )

print("Encrypted ciphertext (hex):", ciphertext.hex())  # Display encrypted data in hexadecimal format

# Decrypt the ciphertext using the private key
# - Only the private key holder can decrypt the message, ensuring confidentiality.
decrypted_text = private_key.decrypt(
        ciphertext,
        padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),  # MGF1 with SHA-256 for security
                    algorithm=hashes.SHA256(),  # Same hash function used during encryption
                    label=None  # Label must match encryption; since it was None, it remains None
                )
    )

print("Decrypted text:", decrypted_text)  # Should match the original plaintext
