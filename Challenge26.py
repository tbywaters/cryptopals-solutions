from cryptopalsmod.ciphers.aes_ctr import AES_CTR_random
import cryptopalsmod.bytestringops as bso 
import  cryptopalsmod.stringops as sops 


class ChallengeCipher(AES_CTR_random):
    """Cipher designed specifically for this challenge. Encryption function
    takes strings as input, cleans meta character, prepends and appends the 
    specified bytes and encrypts. is_admin method 
    takes in a ciphertext, decrypts and checks wether the user is an admin as
    specified by the challenge.
    """
    def __init__(self):
        self.prepad = b"comment1=cooking%20MCs;userdata="
        self.postpad = b";comment2=%20like%20a%20pound%20of%20bacon"
        AES_CTR_random.__init__(self)

    def encrypt(self, plaintext):
        plaintext = sops.remove_meta_chars(plaintext, "=;").encode()
        return AES_CTR_random.encrypt_decrypt(self, self.prepad + plaintext + self.postpad, 0)

    def decrypt(self, ciphertext):
        plaintext = AES_CTR_random.encrypt_decrypt(self, ciphertext, 0)
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

    plaintext = bytes(12*[0]).decode()
    desired_plaintext = b';admin=true;'
    

    ciphertext = cipher.encrypt(plaintext)
    ciphertext = ciphertext[:32] + bso.FixedXOR(ciphertext[32:44], desired_plaintext) + ciphertext[44:]

    
    assert cipher.is_admin(ciphertext)



if __name__ == "__main__":
    main()