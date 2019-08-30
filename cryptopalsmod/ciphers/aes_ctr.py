from Crypto.Cipher import AES
import struct
import cryptopalsmod.bytestringops as bso
import secrets

class AES_CTR(object):
    def __init__(self, key, nonce, counter_start = 0):
        """Initialise the cipher.

        Args:
            key (bytes): sectret key to be used, length 16
            nonce (int): used in encryption
            counter_start (int): initial values of counter used in encryption.
        """
        assert len(key) == 16
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.nonce = nonce
        self.counter = counter_start

    def encrypt_decrypt(self, bytestring, reset_counter = -1):
        """Encryption and decryption are the same function in CTR. This function
        does either
        
        Args:
            bytestring (bytes): bytes to be encripted of decrypted
            reset_counter (int) = -1: If nonnegative, counter is set to be this
            counter. 
        """

        bytestring = [bytestring[i:i+16] for i in range(0, len(bytestring), 16)]
        encryption = b''
        
        for block in bytestring:
            
            #Converts nonce and count to bytes of legnth 8 using little endian
            #and concatenates them
            concat = struct.pack('<QQ', self.nonce, self.counter)
            
            XORBlock = self.cipher.encrypt(concat)

            encrypted_block = bso.zipXOR(block, XORBlock)
            
            encryption += encrypted_block

            self.counter += 1
        
        
        if reset_counter >= 0:
            self.counter = reset_counter

        return encryption

    def edit(self, ciphertext, offset, new_text):

        """takes an encrypted by changes the plaintext at position offset to 
        be new_text. Returns the new encrypted ciphertext"""

        old_plaintext = self.encrypt_decrypt(ciphertext[:offset + len(new_text)], 0)
        new_plaintext = old_plaintext[:offset] + new_text
        new_ciphertext = self.encrypt_decrypt(new_plaintext, 0) + ciphertext[offset + len(new_text):]
        return new_ciphertext

class AES_CTR_random(AES_CTR):
    """ An AES_CTR but with random key and nonce"""
    def __init__(self):
        nonce = secrets.randbelow(2**(4*16))
        key = secrets.token_bytes(16)
        AES_CTR.__init__(self, key, nonce)
