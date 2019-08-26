from cryptopalsmod.ciphers.aes_cbc import AES_CBC_random
import cryptopalsmod.bytestringops as bso 
import  cryptopalsmod.stringops as sops 


class ChallengeCipher(AES_CBC_random):
    """Cipher designed specifically for this challenge. Encryption function
    takes strings as input, cleans meta character, prepends and appends the 
    specified bytes and encrypts. Decryption removes padding. is_admin method 
    takes in a ciphertext, decrypts and checks wether the user is an admin as
    specified by the challenge.
    """
    def __init__(self):
        self.prepad = b"comment1=cooking%20MCs;userdata="
        self.postpad = b";comment2=%20like%20a%20pound%20of%20bacon"
        AES_CBC_random.__init__(self)

    def encrypt(self, plaintext):
        plaintext = sops.remove_meta_chars(plaintext, "=;").encode()
        return AES_CBC_random.encrypt(self, self.prepad + plaintext + self.postpad)

    def decrypt(self, ciphertext):
        plaintext = AES_CBC_random.decrypt(self, ciphertext)
        plaintext = bso.remove_padding_pkcs7(plaintext)
        return plaintext
    
    def is_admin(self, ciphertext):
        plaintext = self.decrypt(ciphertext)
        fields = plaintext.split(b';')
        for field in fields:
            if field == b'admin=true':
                return True
        return False

        

def main():
    cipher = ChallengeCipher()

    plaintextpt1 = '----------------'
    plaintextpt2 = ';admin=true;----'
    replacementBlock = bytes(16*[1])
    plaintextpt2 = bso.FixedXOR(plaintextpt2.encode(), replacementBlock)
    plaintext = plaintextpt1 + plaintextpt2.decode()


    ciphertext = cipher.encrypt(plaintext)
    ciphertext = ciphertext[:32] + bso.FixedXOR(ciphertext[32:48], replacementBlock) + ciphertext[48:]

    
    assert cipher.is_admin(ciphertext) 



if __name__ == "__main__":
    main()