from cryptopalsmod.ciphers.aes_cbc import AES_CBC
import base64

def loadChallengeData():
    with open('10.txt') as file:
        ciphertext = file.read()
    return base64.b64decode(ciphertext)

    


def main():
    key = b'YELLOW SUBMARINE'
    initialisation_vector = bytes(16*[0])

    cipher = AES_CBC(key, initialisation_vector)
    assert cipher.decrypt(loadChallengeData())[:33] == b"I'm back and I'm ringin' the bell"

if __name__ == "__main__":
    main()

