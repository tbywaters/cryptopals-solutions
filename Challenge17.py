from cryptopalsmod.ciphers.aes_cbc import AES_CBC_random
import cryptopalsmod.bytestringops as bso 
import secrets
import base64
import cryptopalsmod.aes_cbc_attacks as cbc_attacks

class PaddingOracle(AES_CBC_random):
    def __init__(self):
        AES_CBC_random.__init__(self)

    def generate_encryption(self):
        messages_in_64 = [  'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
                            'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
                            'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
                            'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
                            'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
                            'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
                            'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
                            'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
                            'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
                            'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
        message_bytes = base64.b64decode(secrets.choice(messages_in_64))

        return self.IV, AES_CBC_random.encrypt(self, message_bytes)

    def check_padding(self, ciphertext, IV = None):
        """Decrypts and attemts to remove padding. If the padding is invalid
        raises an exception. Returns true otherwise"""
        plaintext = AES_CBC_random.decrypt(self, ciphertext, IV)
        plaintext = bso.remove_padding_pkcs7(plaintext)

        return True

def main():
    cipher = PaddingOracle()
    IV, ciphertext = cipher.generate_encryption()
    
    
    oracle_dec = cbc_attacks.padding_oracle_attack(ciphertext, IV, cipher.check_padding, 16)
    assert oracle_dec == cipher.decrypt(ciphertext)
    return

if __name__ == "__main__":
    main()