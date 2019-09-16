from hashlib import sha256
import secrets
from cryptopalsmod import number_theory as nt

class DSAUser(object):

    def __init__(self, hash_func = sha256):

        self.p = int("""800000000000000089e1855218a0e7dac38136ffafa72eda7
                        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
                        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
                        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
                        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
                        1a584471bb1""".replace('\n', '').replace(' ', ''), 16)
 
        self.q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
 
        self.g = int("""5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
                        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
                        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
                        0f5b64c36b625a097f1651fe775323556fe00b3608c887892
                        878480e99041be601a62166ca6894bdd41a7054ec89f756ba
                        9fc95302291""".replace('\n', '').replace(' ', ''), 16)

        self.hash = hash_func

        self.key_generation()

    def key_generation(self):
        self.secret_key = secrets.randbelow(self.q)
        self.public_key = nt.modexp(self.g, self.secret_key, self.p)


    def sign_message(self, message):
 
        r = s = 0
 
        while r == 0 or s == 0:
        
            k = secrets.randbelow(self.q)
 
            r = nt.modexp(self.g, k, self.p) % self.q
 
            k_inv = nt.invmod(k, self.q)
 
            msg_hash = int(self.hash(message).hexdigest(), 16)
            s = (k_inv * (msg_hash + self.secret_key * r)) % self.q
        
        return self.public_key, r, s


    def verify(self, message, public_key, r, s):

        if not (0 < r < self.q and 0 < s < self.p):
            return False
        
        s_inv = nt.invmod(s, self.q)
        
        msg_hash = int(self.hash(message).hexdigest(), 16)
        exp1 = msg_hash * s_inv % self.q
        
        exp2 = r * s_inv % self.q
        
        v = ((nt.modexp(self.g, exp1, self.p) * nt.modexp(public_key, exp2, self.p)) % self.p) % self.q

        return v == r