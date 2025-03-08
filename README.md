# High School Encryption Demo in Python

This repository contains intentionally simple demos of symmetric and asymmetric encryption implemented in Python. The demos illustrate fundamental cryptography concepts such as RSA, Diffie-Hellman key exchange, and AES encryption. This should be simple enough for motivated high-school students to fully grasp in a few hours.

## Contents

- **symmetric_crypt.py**: Demonstrates AES encryption/decryption using a password-derived key.
- **asymmetric_crypt.py**: Shows how RSA can generate key pairs and perform encryption/decryption.
- **rsa_key_exchange_1.py**: Implements RSA-based key exchange to securely share an AES key.
- **rsa_key_exchange_2.py**: Extends RSA key exchange with digital signatures for authenticity.
- **dh_key_exchange.py**: Demonstrates Diffie-Hellman key exchange to derive a shared AES key.

## Getting Started

1. Ensure you have Python 3 installed. (We used Python v3.13)
2. Install the required dependencies:
   ````bash
   pip install cryptography
   ````
3. Run any of the demo scripts (for example):
   ````bash
   python symmetric_crypt.py
   ````

## Usage

Each script is self-contained and demonstrates various encryption concepts:
- **Symmetric Encryption**: AES encryption using CBC mode and PKCS7 padding.
- **Asymmetric Encryption**: RSA encryption/decryption and digital signatures.
- **Key Exchange**: Securely exchanging keys using RSA or Diffie-Hellman.

## License

This project is licensed under the MIT License.

