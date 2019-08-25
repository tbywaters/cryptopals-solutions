from cryptopalsmod.ciphers.aes_cbc import AES_CBC
from cryptopalsmod.ciphers.aes_ecb import AES_ECB
import secrets
import cryptopalsmod.aes_ecb_attacks as ecb_attacks 



def encryption_orcle(plaintext):
    """Encrypts plaintext randomly using eith CBC or ECB with a random key.
    Use for testing a function which detects which method is used. Returns a
    tuple of either 'ECB' or 'CBC' depending on the method used and also the 
    ciphertext"""
    
    IV = bytes(16*[0])
    key = secrets.token_bytes(16)

    cipher_mode = secrets.choice(['ECB', 'CBC'])

    if cipher_mode == 'ECB':
        cipher = AES_ECB(key)
    else:
        cipher = AES_CBC(key, IV)

    return cipher_mode, cipher.encrypt(plaintext)

def cipher_mode_guesser(ciphertext):
    if ecb_attacks.detect_ECB(ciphertext):
        return 'ECB'
    return 'CBC'

def main():
    
    sample = bytes(64*[0])

    for attempt in range(0,1000):
        cipher_mode, ciphertext = encryption_orcle(sample)
        guessed_mode = cipher_mode_guesser(ciphertext)
        assert cipher_mode == guessed_mode


        


if __name__ == "__main__":
    main()