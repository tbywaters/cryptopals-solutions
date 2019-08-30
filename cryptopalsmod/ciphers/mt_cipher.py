from cryptopalsmod.random.mersenne_twister import MT19937
import cryptopalsmod.bytestringops as bso

class MTCipher(object):
    def __init__(self, seed):
        self.prng = MT19937(seed)
        self.seed = seed

    def encrypt(self, plaintext):
        keystream = b''

        while len(keystream) < len(plaintext):
            new_num = self.prng.extract_number()

            #The key stream is a sequence of bytes. There are a few ways to
            # extract a byte from a 32 bit number. We have chosen to jsut take
            # the lowest 8 bits 
            new_num = ((1 << 8) - 1) & new_num
            keystream += bytes([new_num])
        
        return bso.zipXOR(plaintext, keystream)

    def reset_stream(self):
        self.prng = MT19937(self.seed)

    def decrypt(self, ciphertext):
        """encryption and decryption are the same"""
        return self.encrypt(ciphertext)

        