from base64 import b64encode, b64decode
import struct
import random
import time

import prime_list

from xgcd.xgcd import *
from xgcd.util import print_debug

from concurrent.futures import ProcessPoolExecutor
from multiprocessing import cpu_count
from functools import lru_cache


PUBLIC_KEY = 0
PRIVATE_KEY = 1
NOT_KEY = 2
CRT = 1
FXGCD = True # Fast Large-Integer Extended GCD Flag
DEBUG = True
PAIR = 0

class rsa_key:
    class priv:
        def __init__(self,n ,e ,d=None, p=None, q=None, dp=None, dq=None, qinv=None):
            self.n=n
            self.e=e
            self.d=d
            self.p=p
            self.q=q
            self.dp=dp
            self.dq=dq
            self.qinv=qinv
    class pub:
        def __init__(self,n,e):
            self.n = n
            self.e = e
    @staticmethod
    @lru_cache(maxsize=1024)
    def miller_rabin_witness(n, a, d, r):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    @staticmethod
    def miller_rabin(n, k=40):
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Use list prime numbers as first witnesses
        small_primes = prime_list.list
        witnesses = small_primes[:min(k, len(small_primes))]
        witnesses.extend(random.randrange(2, n - 1) for _ in range(k - len(witnesses)))
        
        return all(rsa_key.miller_rabin_witness(n, a, d, r) for a in witnesses)

    @staticmethod
    def generate_prime(bits):
        # print("Generate prime...")
        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1  # Make sure it's odd and has the right bit length
            if rsa_key.miller_rabin(n):
                return n

    @staticmethod
    def extended_gcd(a, b):
        # Test fasted
        if FXGCD==True:

            #print_debug(DEBUG,"Extended GCD...", endl=' ')
            obj = xgcd_model(a,b,debug_print=False)
            #print_debug(DEBUG,"Complete.")
            #print_debug(DEBUG,"==============================")
            #print_debug(DEBUG,f"GCD:{obj[0]}, A:{obj[1]}, B:{obj[2]}.")
            #print_debug(DEBUG,"==============================")

            gcd,x,y,_,_ = obj
            return gcd, x, y
        else:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = rsa_key.extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            #print_debug(DEBUG,f"GCD:{gcd}, A:{x}, B:{y}.")
            return gcd, x, y

    @staticmethod
    def mod_inverse(e, phi):
        gcd, x, _ = rsa_key.extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi

    @classmethod
    def generate_prime_multi_process(cls, bits):
        """Generates two prime numbers concurrently using multiple processes.
        
        Args:
            cls: The class containing the `generate_prime` method
            bits: The number of bits for the prime numbers
        
        Returns:
            tuple: Two prime numbers
        """
        worker_count = min(2, cpu_count())
        
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(cls.generate_prime, bits) for _ in range(2)]
            
            # Use as_completed to get results as soon as they're ready
            from concurrent.futures import as_completed
            return [future.result() for future in as_completed(futures)]


    @classmethod
    def generate(cls, bits=2048, multi_process = True):
        # Generate two prime numbers
        #print_debug(DEBUG,"Generate prime...",endl=' ')
        p,q = None,None
        if multi_process:
            # print("multi_process...")
            p,q = cls.generate_prime_multi_process(bits // 2);
        
        else:
            # print("Normal...")
            p = cls.generate_prime(bits // 2)
            q = cls.generate_prime(bits // 2)
        #print(f"p:{p}, q:{q}")

        #print_debug(DEBUG,"Complete.")
        #print_debug(DEBUG,"==============================")
        #print_debug(DEBUG,f"p:{p}, q:{q}")
        #print_debug(DEBUG,"==============================")

        n = p * q

        # Calculate Euler's totient function φ(n)
        phi = (p - 1) * (q - 1)

        # Choose public exponent e
        e = 65537  # Common choice for e

        # Calculate private exponent d
        d = cls.mod_inverse(e, phi)

        # Calculate CRT components
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = cls.mod_inverse(q, p)

        # Create public and private key objects
        public_key = cls.pub(n, e)
        private_key = cls.priv(n, e, d, p, q, dp, dq, qinv)
        return public_key, private_key

    @staticmethod
    def encode_asn1_integer(value):
        """Encode an integer in ASN.1 DER format."""
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, byteorder='big', signed=False)
        if value_bytes[0] & 0x80:  # Ensure the integer is positive
            value_bytes = b'\x00' + value_bytes

        length = len(value_bytes)
        if length <= 127:  # Short-form length
            length_bytes = length.to_bytes(1, byteorder='big')
        else:  # Long-form length
            length_bytes = (0x80 | ((length.bit_length() + 7) // 8)).to_bytes(1, byteorder='big')
            length_bytes += length.to_bytes((length.bit_length() + 7) // 8, byteorder='big')

        return b'\x02' + length_bytes + value_bytes


    @classmethod
    def encode_asn1(cls,key,type=True):
        """Encode the RSA key as an ASN.1 DER SEQUENCE."""
        elements = None
        if type == NOT_KEY:
            elements = [cls.encode_asn1_integer(c) for c in key]
        else:
            elements = [
                cls.encode_asn1_integer(key.n),
                cls.encode_asn1_integer(key.e),
            ]
            if type == PRIVATE_KEY:
                elements.extend([
                    cls.encode_asn1_integer(key.d),
                    cls.encode_asn1_integer(key.p),
                    cls.encode_asn1_integer(key.q),
                    cls.encode_asn1_integer(key.dp),
                    cls.encode_asn1_integer(key.dq),
                    cls.encode_asn1_integer(key.qinv)
                ])
        if elements == None:
            raise ValueError("Can't read 'elements' variable")
        sequence_body = b''.join(elements)
        # Encode the length of the sequence body correctly with multiple bytes if necessary
        sequence_length = len(sequence_body)
        if sequence_length <= 127:
            length_bytes = sequence_length.to_bytes(1, byteorder='big')
        else:
            # Long-form length encoding
            length_bytes = (0x80 | ((sequence_length.bit_length() + 7) // 8)).to_bytes(1, byteorder='big')
            length_bytes += sequence_length.to_bytes((sequence_length.bit_length() + 7) // 8, byteorder='big')

        encoded_key = b'\x30' + length_bytes + sequence_body
        return b64encode(encoded_key).decode()

    @staticmethod
    def decode_asn1_integer(data):
        """Decode an ASN.1 DER integer."""
        if data[0] != 0x02:
            raise ValueError("Expected ASN.1 INTEGER type")

        length = data[1]
        if length & 0x80:  # Long-form length
            num_length_bytes = length & 0x7F
            length = int.from_bytes(data[2:2 + num_length_bytes], byteorder='big')
            value_bytes = data[2 + num_length_bytes:2 + num_length_bytes + length]
            return int.from_bytes(value_bytes, byteorder='big'), data[2 + num_length_bytes + length:]
        else:  # Short-form length
            value_bytes = data[2:2 + length]
            return int.from_bytes(value_bytes, byteorder='big'), data[2 + length:]

    @classmethod
    def decode_asn1(cls, data, type=True):
        """Decode an RSA key from an ASN.1 DER SEQUENCE."""
        data = b64decode(data.encode())
        if data[0] != 0x30:
            raise ValueError("Expected ASN.1 SEQUENCE type")
        length = data[1]
        if length & 0x80:  # Long-form length
            num_length_bytes = length & 0x7F
            length = int.from_bytes(data[2:2 + num_length_bytes], byteorder='big')
            body = data[2 + num_length_bytes:2 + num_length_bytes + length]
        else:  # Short-form length
            body = data[2:2 + length]
        if type == NOT_KEY:
            integers = []
            current_body = body
            while current_body:
                try:
                    value, current_body = cls.decode_asn1_integer(current_body)
                    integers.append(value)
                except (ValueError, IndexError):
                    break
            return integers
        else: # KEY
            n, body = cls.decode_asn1_integer(body)
            e, body = cls.decode_asn1_integer(body)
            if type == PRIVATE_KEY:
                d, body = cls.decode_asn1_integer(body)
                p, body = cls.decode_asn1_integer(body)
                q, body = cls.decode_asn1_integer(body)
                dp, body = cls.decode_asn1_integer(body)
                dq, body = cls.decode_asn1_integer(body)
                qinv, _ = cls.decode_asn1_integer(body)
                return cls.priv(n,e,d,p,q,dp,dq,qinv)
            elif type == PUBLIC_KEY:
                return cls.pub(n,e)
            else:
                raise ValueError("Invalid key type")


class RSA:
    def __init__(self, key):
        self.key=key
    def RSAEP(self,m):
        key = vars(rsa_key.decode_asn1(self.key,0))
        n = key['n']
        e = key['e']
        # c = m^e mod n
        c = [pow(ch, e, n) for ch in m.encode('utf-8')]
        for c_i in c:
            if c_i > n:
                raise ValueError("Ciphertex inavlid")
        return rsa_key.encode_asn1(c,type=NOT_KEY)

    def RSADP(self,c,key_form = CRT):

        # Get cyphert text
        c = rsa_key.decode_asn1(c,type=NOT_KEY)
        # Get private key
        priv_key = vars(rsa_key.decode_asn1(self.key))

        if priv_key == None:
            raise ValueError("INVALID_PRIVATE_KEY")
        n = priv_key['n']
        m = []
        if key_form == PAIR:
            d = priv_key['d']
            m = [pow(c_i,d,n) for c_i in c]
        elif key_form == CRT:
            p = priv_key['p']
            dp = priv_key['dp']
            q = priv_key['q']
            dq = priv_key['dq']
            qinv = priv_key['qinv']

            for c_i in c:
                # 2.2 Let m_1 = c^dP mod p.
                m_1 = pow(c_i,dp,p)
                # 2.3 Let m_2 = c^dQ mod q.
                m_2 = pow(c_i,dq,q)
                # 2.4 Let h = qInv ( m_1 - m_2 ) mod p.
                h = pow(qinv*(m_1 - m_2),1, p)
                # 2.5 Let m = m_2 + hq.
                m_i = m_2 + h*q
                if m_i > n:
                    raise ValueError("Ciphertex inavlid")
                else:
                    m.append(m_i)
        else:
            raise ValueError(f"INVALID KEY FORMAT: {key_form}")
        try:
            return bytes([i % 256 for i in m]).decode('utf-8')
        except UnicodeDecodeError:
            # Fallback for partial bytes
            return bytes([i % 256 for i in m]).decode('utf-8', errors='replace')

    def encrypt(self,m):
        return  self.RSAEP(m)
    def decrypt(self,c,key_form = CRT):
        return  self.RSADP(c,key_form)

def decore_string(Strings,line_len=70):
    return "\n".join(Strings[i:i+line_len] for i in range(0, len(Strings), line_len))

def debug():
    DEBUG = True
    # #print_debug(DEBUG,"\nTEST\n=======================================")
    # public_key, private_key = rsa_key.generate(bits=4096)
    # epriv_key = rsa_key.encode_asn1(private_key)
    # dpriv_key = rsa_key.decode_asn1(epriv_key,type=PRIVATE_KEY)
    # epub_key = rsa_key.encode_asn1(public_key,type=PUBLIC_KEY)
    # dpub_key = rsa_key.decode_asn1(epub_key,0)

    # pub = decore_string(epub_key)
    # priv = decore_string(epriv_key)
    # print(f"\n-----BEGIN RSA PUBLIC KEY-----\n{pub}\n-----END RSA PUBLIC KEY-----\n")
    # #print_debug(DEBUG,f"Detail:{vars(dpub_key)}")
    # print(f"\n-----BEGIN RSA PRIVATE KEY-----\n{priv}\n-----END RSA PRIVATE KEY-----\n")
    # #print_debug(DEBUG,f"Detail: {vars(dpriv_key)}")
    # mesage = "RSA加密演算法"
    # print("\nCYPHER TEXT:\n")
    # c = RSA(epub_key).RSAEP(mesage)
    # print(decore_string(c,90))
    # print("\n\nPLAIN TEXT:\n")
    # m = RSA(epriv_key).RSADP(c,PAIR)
    # print(m)

