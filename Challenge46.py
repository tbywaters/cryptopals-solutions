from cryptopalsmod.ciphers import rsa
from cryptopalsmod import rsa_attacks
import base64
from cryptopalsmod import bytestringops as bso

class RSAParityOracle(rsa.RSAServer):
    """An RSA server which has the added functionality of returning true of flase
    depending on if the decryption of a ciphertext as even or odd"""
    def is_even(self, ciphertext):
        decryption = self.decrypt(ciphertext)
        return "{0:b}".format(decryption)[-1] == '0'


def main():
    server = RSAParityOracle()
    client = rsa.RSAClient()
    e, mod = server.send_public_key()
    client.recv_public_key(e, mod)

    plaintext = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='
    plaintext = base64.b64decode(plaintext)

    integer_plaintext = int(bso.bytes_to_hex(plaintext), 16)
    ciphertext = client.encrypt(integer_plaintext)

    cracked_plaintext = rsa_attacks.parity_oracle_attack(ciphertext,
                                                        e, 
                                                        mod, 
                                                        lambda val: server.is_even(val))
                                                        
    assert bso.hex_to_bytes(hex(cracked_plaintext)[2:]) == b"That's why I found you don't play around with the Funky Cold Medind"

if __name__ == "__main__":
    main()
        