from base64 import b64encode, b64decode
import struct
import random
from math import gcd

PUBLIC_KEY = 0
PRIVATE_KEY = 1
NOT_KEY = 2
BASIC = 0
CRT = 1
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

        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = (x * x) % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime(bits):
        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1  # Make sure it's odd and has the right bit length
            if rsa_key.miller_rabin(n):
                return n

    @staticmethod
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = rsa_key.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    @staticmethod
    def mod_inverse(e, phi):
        gcd, x, _ = rsa_key.extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % phi

    @classmethod
    def generate(cls, bits=2048):
        # Generate two prime numbers
        p = cls.generate_prime(bits // 2)
        q = cls.generate_prime(bits // 2)
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
    def encode(cls,key,type=True):
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
    def decode(cls, data, type=True):
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
            else:
                return cls.pub(n,e)
            
PAIR = 0
class RSA:
    def __init__(self, key):
        self.key=key
    def RSAEP(self,m):
        key = vars(rsa_key.decode(self.key,0))
        n = key['n']
        e = key['e']
        # c = m^e mod n
        c = [pow(ch, e, n) for ch in m.encode('utf-8')]
        for c_i in c:
            if c_i > n:
                raise ValueError("Ciphertex inavlid")
        return rsa_key.encode(c,type=NOT_KEY)
        
    def RSADP(self,c,key_form = CRT):
        # get key
        c = rsa_key.decode(c,type=NOT_KEY)
        priv_key = vars(rsa_key.decode(self.key))
        if priv_key == None:
            raise ValueError("INVALID_PRIVATE_KEY")
        n = priv_key['n']
        p = priv_key['p']
        dp = priv_key['dp']
        q = priv_key['q']
        dq = priv_key['dq']
        qinv = priv_key['qinv']
        m = []
        if key_form == PAIR:            
            m = [pow(c_i,d,n) for c_i in c]
        else:
            for c_i in c:
                # 2.2 Let m_1 = c^dP mod p.
                m_1 = pow(c_i,dp,p)
                #2.3 Let m_2 = c^dQ mod q.
                m_2 = pow(c_i,dq,q)
                #2.4 Let h = qInv ( m_1 - m_2 ) mod p.
                h = pow(qinv*(m_1 - m_2),1, p)
                #2.5 Let m = m_2 + hq.
                m_i = m_2 + h*q
                if m_i > n:
                    raise ValueError("Ciphertex inavlid")
                else:
                    m.append(m_i)
        try:
            return bytes([i % 256 for i in m]).decode('utf-8')
        except UnicodeDecodeError:
            # Fallback for partial bytes
            return bytes([i % 256 for i in m]).decode('utf-8', errors='replace')

    def encrypt(self,m,mode=BASIC):
        n = len(m)
        c = []
        if mode == BASIC:
            for ch in m:
                t_c = ch**2 % 3
                c.append(t_c)
        return ''.join(c)
    def decrypt(self,key):
        return

# Example Usage
private_key_test = rsa_key.priv(
    n=119804358589858644765221877549031317428421793169529619015017035148384373331588708250559706937964533013912466456159861052033183530768187408065883203743172073032605882094995169159012628394796247305000768589287207171193112355182932682868233823669460266648742193878806746540150812713265025918931473273940617379341,
    e=65537,
    d=106600414526283122676337772058443508926575651111401959248084339955183886147645817369167626689968472438062339883188216387510308137589698651356545358241593832313386664321337106681626487700416644455858577695017816213777721379443488277768733460815264369384861873095290119265671695181560821821783096125368474995521,
    p=11566986730936860971910390078849278858098272684424077553791128622900966264328729763844321012962641096026515406397977404619149939073000444825059285211420809,
    q=10357438923088931776550441064406061930351159891168701394279293653530689078216947924230103840846272356312833681438072738204279209761613925157478841129013349,
    dp=96719543594509968607151590143116175812714244336243564695935707849760128062806413332723315304385725935311815351726377736718100715809454869220936086422305,
    dq=7581157897684911688376408103202142160900638417677992674116571044751318416803744326492181229616791811226126183660899175300353597086601766785239788347937353,
    qinv=2329944665090987338560595738197238447371796287202569281514887490447756566514464885724105909481310943154811363003736545418041764952931797296683430290492436
)
public_key_test = rsa_key.pub(
    n=119804358589858644765221877549031317428421793169529619015017035148384373331588708250559706937964533013912466456159861052033183530768187408065883203743172073032605882094995169159012628394796247305000768589287207171193112355182932682868233823669460266648742193878806746540150812713265025918931473273940617379341,
    e=65537
)




import resource
import platform
import sys

def memory_limit_mb(limit_mb: int):
    """
    Sets the memory limit in MB for the current process on Linux.

    Args:
        limit_mb: The memory limit in MB.
    """
    if platform.system() != "Linux":
        print('Only works on Linux!')
        return

    # Convert limit_mb to bytes
    limit_bytes = limit_mb * 1024 * 1024

    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, hard))

def memory(limit_mb: int):
    """
    Decorator to limit memory usage for the decorated function.

    Args:
        limit_mb: The memory limit in MB.

    Raises:
        MemoryError: If the memory limit is exceeded.
    """
    def decorator(function):
        def wrapper(*args, **kwargs):
            memory_limit_mb(limit_mb)
            try:
                return function(*args, **kwargs)
            except MemoryError:
                print(f"Memory limit of {limit_mb} MB exceeded.")
                sys.exit(1)
        return wrapper
    return decorator
@memory(limit_mb=1)

def decore_string(Strings,line_len=50):
    return "\n".join(Strings[i:i+line_len] for i in range(0, len(Strings), line_len))

def debug():
    public_key, private_key = rsa_key.generate()
    epriv_key = rsa_key.encode(private_key)
    dpriv_key = rsa_key.decode(epriv_key,type=PRIVATE_KEY)
    epub_key = rsa_key.encode(public_key,type=PUBLIC_KEY)
    dpub_key = rsa_key.decode(epub_key,0)

    pub = decore_string(epub_key)
    priv = decore_string(epriv_key)
    print(f"\n-----BEGIN RSA PUBLIC KEY-----\n{pub}\n-----END RSA PUBLIC KEY-----\n")
    #print("Detail:{vars(dpub_key)}")
    print(f"\n-----BEGIN RSA PRIVATE KEY-----\n{priv}\n-----END RSA PRIVATE KEY-----\n")
    #print("Detail: {vars(dpriv_key)}")
    print("\nTEST\n=======================================")
    mesage = "hello 只在linux操作系统起作用"
    # mesage = "zebra2711"
    print("\nCYPHER TEXT:\n")
    c = RSA(epub_key).RSAEP(mesage)
    print(decore_string(c,150))
    print("\n\nPLAIN TEXT:\n")
    m = RSA(epriv_key).RSADP(c)
    print(m)

debug()
