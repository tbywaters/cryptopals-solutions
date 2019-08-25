from Crypto.Cipher import AES 
import cryptopalsmod.bytestringops as bso
import secrets


class AES_ECB:
    """Class which implements AES_ECB after being given a key"""
    def __init__(self, key):
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        plaintext = bso.pad_by_multiple(plaintext, 16)
        return self.cipher.encrypt(plaintext)

    def decrypt(self,ciphertext):
        return self.cipher.decrypt(ciphertext)

class AES_ECB_random(AES_ECB):
    """Class which implements AES_ECB but with a random key. Useful as 
    simulating an oracle"""
    def __init__(self):
        AES_ECB.__init__(self, secrets.token_bytes(16))

