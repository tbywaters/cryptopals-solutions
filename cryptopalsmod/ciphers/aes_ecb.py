from Crypto.Cipher import AES 
import cryptopalsmod.bytestringops as bso


class AES_ECB:
    def __init__(self, key):
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        plaintext = bso.pad_by_multiple(plaintext, 16)
        return self.cipher.encrypt(plaintext)

    def decrypt(self,ciphertext):
        return self.cipher.decrypt(ciphertext)