from cryptopalsmod.ciphers.mt_cipher import MTCipher
import cryptopalsmod.mersenne_twister_attacks as mt_attacks
from cryptopalsmod.random.mersenne_twister import MT19937
import cryptopalsmod.bytestringops as bso
import secrets

class ChallengeCipher(MTCipher):
    def __init__(self):
        seed = secrets.randbelow(2**16)
        MTCipher.__init__(self, seed)

    def encrypt(self, plaintext):
        num_bytes = secrets.randbelow(32)
        prefix = secrets.token_bytes(num_bytes)
        return MTCipher.encrypt(self, prefix + plaintext)

    def decrypt(self, ciphertext):
        return MTCipher.encrypt(self, ciphertext)


def main():

    cipher = ChallengeCipher()
    known_plaintxt = b'AAAAAAAAAAAAAA'
    ciphertext = cipher.encrypt(known_plaintxt)
    start = len(ciphertext) - len(known_plaintxt)
    output = bso.FixedXOR(known_plaintxt, ciphertext[start:start + len(known_plaintxt)])


    seed = mt_attacks.brute_attack(output, start, range(1, 2**16))

    assert seed == cipher.seed
    
if __name__ == "__main__":
    main()