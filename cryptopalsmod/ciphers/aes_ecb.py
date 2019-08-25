from Crypto.Cipher import AES 


class AES_ECB:
    def __init__(self, key):
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        return self.cipher.encrypt(plaintext)

    def decrypt(self,ciphertext):
        return self.cipher.decrypt(ciphertext)