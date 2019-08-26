from cryptopalsmod.ciphers.aes_ecb import AES_ECB_random
import secrets
import cryptopalsmod.aes_ecb_attacks as ecb_attacks
import base64 
import cryptopalsmod.bytestringops as bso

class challenge_cipher(AES_ECB_random):
    """AES_ECB cipher used as an oracle in the challenge. Before encryption,
    cipher adds a message to the end of the given paintext and fixed random 
    bytes at the begining"""
    
    def __init__(self):
       AES_ECB_random.__init__(self)
       self.postPadText = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
       self.prePadText = secrets.token_bytes(secrets.choice(range(1,32)))

    def encrypt(self, plaintext):
       return AES_ECB_random.encrypt(self,self.prePadText + plaintext + self.postPadText)

def decrypt_ECB_with_oracle(oracle, key_length, prepad_length):
    decryption = b''
    
    #When decrypting, will will add some junk characters to ensure that the text
    #before the message is an multiple of key_length.
    junk_char = key_length - (prepad_length % key_length)
    assert (junk_char + prepad_length)% key_length == 0

    ciphertextlength = len(oracle.encrypt(b'')) - prepad_length
    while len(decryption) < ciphertextlength:
        decryption = decrypt_next_block(oracle, decryption, key_length, prepad_length)
    return decryption

def decrypt_next_block(oracle, decryption, key_length, prepad_length):

    #When decrypting, will will add some junk characters to ensure that the text
    #before the message is an multiple of key_length.
    junk_char = key_length - (prepad_length % key_length)
    assert (junk_char + prepad_length) % key_length == 0

    next_decryption_size = len(decryption) + key_length

    block_start = len(decryption) + prepad_length + junk_char
    block_end = block_start + key_length
    
    while len(decryption) < next_decryption_size:

        junk_bytes = junk_char*b'A'
        prefix = (next_decryption_size - len(decryption) - 1)*b'A'
        encrypted_block = oracle.encrypt(junk_bytes + prefix)[block_start:block_end]        

        #If we are at the padding of the original message which changes when we
        #change the prefix, we will not find a match. Track wether a match is
        #found
        added_byte = False
        for byte in range(0, 255):
            test_message = junk_bytes + prefix + decryption + bytes([byte])
            test_encryption = oracle.encrypt(test_message)[block_start:block_end]

            
            if test_encryption == encrypted_block:
                decryption += bytes([byte])
                added_byte = True
                break

        #If no matchiny bytes is found, pad out our decryption to end the loop
        if not added_byte:
            decryption = bso.pad_by_multiple(decryption, key_length)
    return decryption

def main():
    oracle = challenge_cipher()
    key_length = ecb_attacks.determine_ECB_keylength(oracle)
    assert key_length == 16
    prepad_length = ecb_attacks.determine_prepad_length(oracle)
    decryption = decrypt_ECB_with_oracle(oracle, key_length, prepad_length)
    result = b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by"
    assert decryption[:len(result)] == result

if __name__ == "__main__":
    main()