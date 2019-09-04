from Crypto.Cipher import AES 
import cryptopalsmod.bytestringops as bso 
import secrets


class AES_CBC:
    def __init__(self, key, initialistaion_vector):
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.IV = initialistaion_vector

    def encrypt(self, plaintext, IV = None):
        ciphertext = b''

        #There is an option argument to change the IV. Added check that if an 
        #IV has been entered, it has the same length as the origianl.
        if IV == None:
            IV = self.IV
        else:
            assert len(IV) == len(self.IV)
        
        #Always pad plaintext so that padding can be checked for validity
        plaintext = bso.pad_by_multiple(plaintext, 16, extra_block=True)

        #separate plaintext into blocks for encryption.
        plaintext_blocks = [plaintext[i: i+16] for i in range(0, len(plaintext), 16)]

        #CBC loop
        previous = IV
        for block in plaintext_blocks:
            new_block_to_encrypt = bso.FixedXOR(block, previous)
            encrypted_block = self.cipher.encrypt(new_block_to_encrypt)
            previous = encrypted_block
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self, ciphertext, IV = None):

        ciphertext_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        #ciphertext should not need padding or something has gone wrong
        
        #There is an option argument to change the IV. Added check that if an 
        #IV has been entered, it has the same length as the origianl.
        if IV == None:
            IV = self.IV
        else:
            assert len(IV) == len(self.IV)


        previous = IV

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