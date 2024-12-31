from rsa import rsa_key, RSA, decore_string
from limit import memory
import argparse

PUBLIC_KEY = 0
PRIVATE_KEY = 1
NOT_KEY = 2
CRT = 1
FXGCD = True  # Fast Large-Integer Extended GCD Flag
PAIR = 0

# Generate RSA keys
def generate_keys(key_size,mul_proc=False):
    public_key, private_key = rsa_key.generate(bits=key_size, multi_process=mul_proc)
    epriv_key = rsa_key.encode_asn1(private_key)
    epub_key = rsa_key.encode_asn1(public_key, type=PUBLIC_KEY)

    # Display public and private keys
    print(f"\n-----BEGIN RSA PUBLIC KEY-----\n{decore_string(epub_key)}\n-----END RSA PUBLIC KEY-----\n")
    print(f"\n-----BEGIN RSA PRIVATE KEY-----\n{decore_string(epriv_key)}\n-----END RSA PRIVATE KEY-----\n")

    return epub_key, epriv_key

#@memory(limit_kb=4069)
def main():
    # Default settings
    mp = False

    # Argument parser configuration
    parser = argparse.ArgumentParser(description="Public-private key cryptosystem RSA")
    parser.add_argument("-t", "--test", help="Run a test example", action="store_true")
    parser.add_argument("-d", "--decrypt", help="Decrypt a cypher text (BASE64 encoded)", action="store_true")
    parser.add_argument("-e", "--encrypt", help="Encrypt a plain text (UTF-8 encoded)", action="store_true")
    parser.add_argument("-b", "--bits", type=int, default=2048, help="Key size in bits (default: 2048)")
    parser.add_argument("-mp", "--multi-process", action="store_true", help="Enable multi-process for key generation")
    parser.add_argument("-i", "--input", type=str ,help="Input string for encryption or decryption")
    parser.add_argument("-a", "--auto", help="Auto generate key",action="store_true")
    parser.add_argument("-k", "--key", type=str,help="Private key to decrypt")
    parser.add_argument("-kf", "--key-format", type=str, default="CRT", choices=["PAIR", "CRT"], 
                        help="Key format to decrypt: PAIR (n, d) or CRT (n, p, q, dP, dQ, qInv)")

    # Parse arguments
    args = parser.parse_args()
    test = args.test
    key_size = args.bits
    mp = args.multi_process
    input_text = args.input
    key_format = PAIR if args.key_format == "PAIR" else CRT
    key = args.key

    # print(f"args: {args}")
    print("\nINFOR:")
    print(f"\tKEY SIZE: {key_size}")
    print(f"\tMULTI-PROCESS: {mp}")

    # Test example
    if test:
        message = "RSA加密演算法"
        print(f"MESSAGE: {message}")
        print("\nCYPHER TEXT (Test Example):\n")
        epub_key, epriv_key = generate_keys(key_size,mul_proc=mp)
        cypher_text = RSA(epub_key).encrypt(message)
        print(cypher_text)
        print("\n\nPLAIN TEXT (Test Example):\n")
        plain_text = RSA(epriv_key).decrypt(cypher_text, key_form=key_format)
        print(plain_text)
        if message == plain_text:
            print("\nTEST: COMPLETE.")
        else:
            print("\nTEST: FAILED.")

    # Encryption and decryption modes
    if args.encrypt:
        if args.auto:
            epub_key, epriv_key = generate_keys(key_size,mul_proc=mp)
        print("\nEncrypting input text...\n")
        message = input_text
        cypher_text = RSA(epub_key).encrypt(message)
        print("CYPHER TEXT:\n", decore_string(cypher_text,80))

    if args.decrypt:
        print("\nDecrypting...\n")
        c = input_text
        plain_text = RSA(key).decrypt(c, key_form=key_format)
        print("PLAIN TEXT:\n", plain_text)

if __name__ == "__main__":
    main()
