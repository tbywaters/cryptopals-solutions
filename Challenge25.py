from cryptopalsmod.ciphers.aes_ctr import AES_CTR_random
import cryptopalsmod.aes_ctr_attacks as ctr_attacks
import base64
from cryptopalsmod.ciphers.aes_ecb import AES_ECB

def load_challenge_text():
    
    with open('25.txt') as file:
        ecb_ciphertext = base64.b64decode(file.read())

    cipher = AES_ECB(b'YELLOW SUBMARINE')
    return cipher.decrypt(ecb_ciphertext)

def main():
    plaintext = load_challenge_text()
    cipher = AES_CTR_random()
    ciphertext = cipher.encrypt_decrypt(plaintext, 0)

    print(ctr_attacks.read_write_attack(ciphertext, cipher.edit))
if __name__ == "__main__":
    main()