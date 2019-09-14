from cryptopalsmod.ciphers import rsa
from hashlib import sha256
import cryptopalsmod.bytestringops as bso
from cryptopalsmod import number_theory as nt

class RSAOracle(rsa.RSAServer):
    def __init__(self, e = 3, prime_pair = None):
        
        rsa.RSAServer.__init__(self, e, prime_pair)
        
        self.decrypted_ciphertexts_hashes = []

    def decrypt(self, ciphertext):
        
        ciphertext_hash = sha256(bso.int_to_bytes(ciphertext)).digest()
        
        if ciphertext_hash in self.decrypted_ciphertexts_hashes:
            raise Exception('I have already decrypted this message!')
        
        self.decrypted_ciphertexts_hashes.append(ciphertext_hash)

        return rsa.RSAServer.decrypt(self, ciphertext)

def main():

    oracle = RSAOracle()

    client = rsa.RSAClient()
    client.recv_public_key(*oracle.send_public_key())

    message = b'A secret message'

    #Client encrypts the message
    message_int = int(bso.bytes_to_hex(message), 16)
    ciphertext = client.encrypt(message_int)

    #Client sends ciphertext which gets decrypted

    assert message == bso.hex_to_bytes(hex(oracle.decrypt(ciphertext))[2:])

    #Attacker intercepts the ciphertext and tries to get the plaintext from 
    #the oracle. This fails because the oracle only decrypts each plaintext once

    try:
        successfully_decrypted = message == bso.hex_to_bytes(hex(oracle.decrypt(ciphertext))[2:])
    except:
        successfully_decrypted = False

    assert successfully_decrypted == False

    #instead the attacker can get the decryption of an alternate ciphertext and
    # convert it to the original message. This attack uses the fat that exponentiation
    # is a homomorphism

    e, n = oracle.send_public_key()

    #S can be any value

    S = 2

    altered_ciphertext = nt.modexp(S, e, n)*ciphertext % n

    altered_message = oracle.decrypt(altered_ciphertext)

    #altered message = S * message

    new_message = altered_message * nt.invmod(S, n) % n
    assert message == bso.hex_to_bytes(hex(new_message)[2:])


    



if __name__ == '__main__':
    main()