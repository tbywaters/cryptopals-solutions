from Crypto.Cipher import AES 
import cryptopalsmod.bytestringops as bso 
import secrets


class AES_CBC:
    def __init__(self, key, initialistaion_vector):
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.IV = initialistaion_vector

    def encrypt(self, plaintext):
        ciphertext = b''

        #separate plaintext into blocks for encryption. Pad the last block
        plaintext_blocks = [plaintext[i: i+16] for i in range(0, len(plaintext), 16)]
        plaintext_blocks[-1] = bso.pad_pkcs7(plaintext_blocks[-1], 16)

        #CBC loop
        previous = self.IV
        for block in plaintext_blocks:
            new_block_to_encrypt = bso.FixedXOR(block, previous)
            encrypted_block = self.cipher.encrypt(new_block_to_encrypt)
            previous = encrypted_block
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self,ciphertext):

        ciphertext_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        #ciphertext should not need padding or something has gone wrong
        
        previous = self.IV

        plaintext = b''
        #CBC loop

        for block in ciphertext_blocks:
            decrypted_block = self.cipher.decrypt(block)
            decrypted_block = bso.FixedXOR(decrypted_block, previous)
            plaintext += decrypted_block
            previous = block
        
        return plaintext 


class AES_CBC_random(AES_CBC):
    """Implements AES_CBC but with a random key and iniaialisation vector. 
    Useful for simulating an oracle"""
    def __init__(self):
        AES_CBC.__init__(self, secrets.token_bytes(16), secrets.token_bytes(16))