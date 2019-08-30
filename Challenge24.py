from cryptopalsmod.ciphers.mt_cipher import MTCipher
import cryptopalsmod.mersenne_twister_attacks as mt_attacks
from cryptopalsmod.random.mersenne_twister import MT19937
import cryptopalsmod.bytestringops as bso
import secrets
import time

class ChallengeCipher(MTCipher):
    def __init__(self):
        seed = secrets.randbelow(2**16)
        MTCipher.__init__(self, 4)

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

    seed = mt_attacks.brute_attack(ciphertext, b'AAAAAAAAAAAAAA', range(1, 2**16))

    assert seed == cipher.seed
    
    ## pasword_simulation
    key = int(time.time())
    print(key.bit_length())
    pasword_token_plaintext = b'random_username' + b'password_reset'
    cipher = MTCipher(key)

    ciphertext = cipher.encrypt(secrets.token_bytes(25) + pasword_token_plaintext)
    
    time.sleep(5)

    #Password reset token is valid for one day
    
    current_time = int(time.time())
    viable_key_values = list(reversed(range(current_time - 24*60*60, current_time)))
    
    seed = mt_attacks.brute_attack(ciphertext, b'random_username', key_values = viable_key_values)

    plaintext = MTCipher(seed).decrypt(ciphertext)
    assert b'password_reset' in plaintext


if __name__ == "__main__":
    main()