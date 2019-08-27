from Crypto.Cipher import AES
import struct
import cryptopalsmod.bytestringops as bso

class AES_CTR(object):
    def __init__(self, key, nonce, counter_start = 0):
        """Initialise the cipher.

        Args:
            key (bytes): sectret key to be used, lenmgth 16
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
