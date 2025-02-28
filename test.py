# Example usage:

from rsa import rsa_key, RSA

PUBLIC_KEY = 0
PRIVATE_KEY = 1
NOT_KEY = 2
CRT = 1
FXGCD = True  # Fast Large-Integer Extended GCD Flag
PAIR = 0

# Generate an RSA key pair
public_key, private_key = rsa_key.generate(bits=4096, multi_process=True)
epriv_key = rsa_key.encode_asn1(private_key)
epub_key = rsa_key.encode_asn1(public_key, type=PUBLIC_KEY)
public_key = epub_key
private_key = epriv_key

# Create an RSA instance for encryption/decryption
rsa = RSA(private_key)

# Sample plaintext message (convert to bytes)
plaintext = "If you're computing modular inverses frequently (e.g., in cryptographic applications), you should use Montgomery reduction. It avoids expensive division using bitwise operations and shifts. RSA加密演法"

# Encrypt the message
ciphertext = rsa.encrypt(plaintext)
print("Ciphertext:", ciphertext)

# Decrypt the ciphertext
plaintextRecovered = rsa.decrypt(ciphertext)
print("Plaintext Recovered:", plaintextRecovered)
