import cryptopalsmod.ciphers.aes_ecb
import base64

def main():
    
    key = b'YELLOW SUBMARINE'
    
    cipher = cryptopalsmod.ciphers.aes_ecb.AES_ECB(key)

    with open('7.txt') as file:
        ciphertext64 = file.read()

    ciphertext = base64.b64decode(ciphertext64)

    assert cipher.decrypt(ciphertext)[:33] == b"I'm back and I'm ringin' the bell"

if __name__ == "__main__":
    main()