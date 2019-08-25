from cryptopalsmod.ciphers.aes_ecb import AES_ECB_random
import base64
import cryptopalsmod.bytestringops as bso
import cryptopalsmod.aes_ecb_attacks as ecb_attcks

class challenge_cipher(AES_ECB_random):
    def __init__(self):
        AES_ECB_random.__init__(self)
        self.postPadText = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

    def encrypt(self, plaintext):
        return AES_ECB_random.encrypt(self, plaintext + self.postPadText)

def decrypt_ECB_with_oracle(oracle, key_length):
    decryption = b''
    ciphertextlength = len(oracle.encrypt(b''))
    while len(decryption) < ciphertextlength:
        decryption = decrypt_next_block(oracle, decryption, key_length)
    return decryption

def decrypt_next_block(oracle, decryption, key_length):

    next_decryption_size = len(decryption) + key_length
    block_position = len(decryption)

    while len(decryption) < next_decryption_size:

        prefix = (next_decryption_size - len(decryption) - 1)*b'A'
        encrypted_block = oracle.encrypt(prefix)[:next_decryption_size]        

        #If we are at the padding of the original message which changes when we
        #change the prefix, we will not find a match. Track wether a match is
        #found
        added_byte = False
        for byte in range(0, 255):
            test_message = prefix + decryption + bytes([byte])
            test_encryption = oracle.encrypt(test_message)[:next_decryption_size]

            
            if test_encryption == encrypted_block:
                decryption += bytes([byte])
                added_byte = True
                break

        #If no matchiny bytes is found, pad out our decryption to end the loop
        if not added_byte:
            decryption = bso.pad_by_multiple(decryption, key_length)
    return decryption

def main():
    cipher = challenge_cipher()
    key_length = ecb_attcks.determine_ECB_keylength(cipher)
    
    assert key_length == 16

    result = b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
    assert decrypt_ECB_with_oracle(cipher, key_length)[:len(result)] == result

    return


if __name__ == "__main__":
    main()