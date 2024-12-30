from rsa import *
from limit import *

#@memory(limit_kb=4069)
def main():
    debug()
    public_key, private_key = rsa_key.generate(bits=4096,multi_process=True)
    epriv_key = rsa_key.encode_asn1(private_key)
    epub_key = rsa_key.encode_asn1(public_key,type=PUBLIC_KEY)

    mesage = "RSA加密演算法"
    print(f"\n-----BEGIN RSA PUBLIC KEY-----\n{decore_string(epub_key)}\n-----END RSA PUBLIC KEY-----\n")
    print(f"\n-----BEGIN RSA PRIVATE KEY-----\n{decore_string(epriv_key)}\n-----END RSA PRIVATE KEY-----\n")
    print("\nCYPHER TEXT:\n")
    c = RSA(epub_key).encrypt(mesage)
    print(c)
    print("\n\nPLAIN TEXT:\n")
    m = RSA(epriv_key).decrypt(c,key_form=PAIR)
    print(m)
main()
