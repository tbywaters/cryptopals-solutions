from cryptopalsmod.ciphers import rsa
import secrets
from cryptopalsmod import bytestringops as bso
import cryptopalsmod.number_theory as nt
from cryptopalsmod import rsa_attacks

class RSAPaddingOracle(rsa.RSAServer):
    """Server used to simulate RSA with padding"""
    def decrypt_to_bytes_and_check_padding(self, ciphertext):

        #Decrypt a la RSA
        plaintext = nt.modexp(ciphertext, self.d, self.n)

        plaintext = plaintext.to_bytes(bso.byte_len(self.n), 'big')

        #Check the padding before returning the decryption
        if self.check_padding_from_bytes(plaintext):
            return plaintext
        else:
            raise Exception('Invalid padding')

    def check_padding_from_ciphertext(self, ciphertext):
        
        #Check padding by looking at numerical range of the decrypted ciphertext
        B = 2**(8*(bso.byte_len(self.n) - 2))
        return 2*B <= self.decrypt(ciphertext) <= 3*B - 1
        
    def check_padding_from_bytes(self, plaintext):
        #Checks bytes of plaintext to determine if padding is valid
        if (plaintext[:2] != b'\x00\x02'
            or len(plaintext) != bso.byte_len(self.n)):
            return False
        else:
            return True

class ChallengeRSAClient(rsa.RSAClient):
    """Client used to simulate RSA with padding"""

    def pad_and_encrypt(self, plaintext):
        plaintext = self.pad(plaintext)
        plaintext = int(bso.bytes_to_hex(plaintext), 16)
        return self.encrypt(plaintext)

    def pad(self, plaintext):
        desired_length = bso.byte_len(self.n)
        if len(plaintext) > desired_length - 11:
            raise Exception('Message too long')
 
        plaintext = bytes([0]) + plaintext
        plaintext = secrets.token_bytes(desired_length - len(plaintext) - 2) + plaintext
        plaintext = bytes([0]) + bytes([2]) + plaintext
    
        return plaintext


def main():
    server = RSAPaddingOracle(prime_size = 128)
    client = ChallengeRSAClient()

    e, mod = server.send_public_key()
    client.recv_public_key(e, mod)
    message = b'kick it, CC'    

    ciphertext = client.pad_and_encrypt(message)
    assert server.decrypt_to_bytes_and_check_padding(ciphertext)[-len(message):] == message

    #For debugging
    plaintext = server.decrypt(ciphertext)

    attacker = rsa_attacks.Bleichenbacher(ciphertext, e, mod, server.check_padding_from_ciphertext)
    plaintext = attacker.run()
    assert plaintext.to_bytes(bso.byte_len(mod), 'big') == server.decrypt_to_bytes_and_check_padding(ciphertext)



if __name__ == "__main__":
    main()
        
        