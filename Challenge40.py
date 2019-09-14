from cryptopalsmod.ciphers import rsa
import cryptopalsmod.bytestringops as bso
from cryptopalsmod import rsa_attacks

def main():
    message = b'A test message'
    message_int = int(bso.bytes_to_hex(message), 16)

    ciphertexts = []
    public_keys = []

    #Encrypt the same message 3 times with 3 different public keys. Keep track 
    # of the ciphertext and public key. It is not necessary to use 3, just need to 
    # use the value of e in rsa.
    
    while len(ciphertexts) < 3:
        server = rsa.RSAServer(e = 3)
        client = rsa.RSAClient()
        e, n = server.send_public_key()
        client.recv_public_key(e, n)
        ciphertext = client.encrypt(message_int)
        ciphertexts.append(ciphertext)
        public_keys.append(n)

    #Now decrypt without using the secret key
    
    discovered_message_int = rsa_attacks.hastad_attack(3, ciphertexts, public_keys)
    discovered_message = bso.hex_to_bytes(hex(discovered_message_int)[2:])
    
    assert discovered_message == message



if __name__ == '__main__':
    main()