from Crypto.Util import number
from cryptopalsmod import number_theory as nt

class RSAServer():

    def __init__(self, e = 3, prime_size = 1024):


        p = number.getPrime(prime_size)
        q = number.getPrime(prime_size)

        #gcd(e, (p-1)*(q-1)) needs to be 1 for the algorithm to work

        while nt.gcd(e, p - 1) > 1:
            p = number.getPrime(prime_size)
        while nt.gcd(e, q - 1) > 1:
            q = number.getPrime(prime_size)


        self.e = e
        self.n = p * q
        totient = (p - 1) * (q - 1)
        self.d = nt.invmod(e, totient)

    def send_public_key(self):
        """output the public keyt for the client
        returns:
            int: e value in rsa
            int: modulus = p*q in rsa
        """
        return self.e, self.n

    def decrypt(self, ciphertext):
        return nt.modexp(ciphertext, self.d, self.n)

class RSAClient():
    def __init__(self):
        self.e = 0
        self.n = 0

    def recv_public_key(self, e, n):
        #receive public key from the server
        self.e = e
        self.n = n
        return

    def encrypt(self, plaintext):
        return nt.modexp(plaintext, self.e, self.n)
