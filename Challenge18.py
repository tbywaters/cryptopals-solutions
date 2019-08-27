from cryptopalsmod.ciphers.aes_ctr import AES_CTR
import base64

def main():
    challenge_string = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    challenge_string = base64.b64decode(challenge_string)
    cipher = AES_CTR(b'YELLOW SUBMARINE',0,0)

    assert cipher.encrypt_decrypt(challenge_string) == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

if __name__ == "__main__":
    main()