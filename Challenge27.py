import secrets
from cryptopalsmod.ciphers.aes_cbc import AES_CBC
import cryptopalsmod.stringops as sops
import cryptopalsmod.bytestringops as bso
import cryptopalsmod.aes_cbc_attacks as cbc_attacks

class ChallengeCipher(AES_CBC):
    """Cipher designed specifically for this challenge. IV and key are the same
    Encryption function takes strings as input, cleans meta character, prepends
    and appends the specified bytes and encrypts. Decryption removes padding
    and raises an exception if the ASCII is not valid. Exception message is the
    decrypted text. is_admin method takes in a ciphertext, decrypts and checks 
    whether the user is an admin.
    """
    def __init__(self):
        self.prepad = b"comment1=cooking%20MCs;userdata="
        self.postpad = b";comment2=%20like%20a%20pound%20of%20bacon"
        key = secrets.token_bytes(16)
        AES_CBC.__init__(self, key, key)

    def encrypt(self, plaintext):
        plaintext = sops.remove_meta_chars(plaintext, "=;").encode()
        return AES_CBC.encrypt(self, self.prepad + plaintext + self.postpad)

    def decrypt(self, ciphertext):
        plaintext = AES_CBC.decrypt(self, ciphertext)
        plaintext = bso.remove_padding_pkcs7(plaintext)
        return plaintext
    
    def is_admin(self, ciphertext):
        plaintext = self.decrypt(ciphertext)
        fields = plaintext.split(b';')
        for field in fields:
            if field == b'admin=true':
                return True
        return False
    
    def check_ascii(self, ciphertext):
        plaintext = self.decrypt(ciphertext)
        
        for byte in plaintext:
            if byte > 126:
                raise Exception(plaintext, 'Not valid ascii')
        return True

def main():
    cipher = ChallengeCipher()
    ciphertext = cipher.encrypt('')
    

    key = cbc_attacks.IV_equals_key(cipher.check_ascii, ciphertext)
    assert key == cipher.IV


    return

if __name__ == "__main__":
    main()