from cryptopalsmod.ciphers.diffiehellman import DiffieHellman
from cryptopalsmod.ciphers.aes_cbc import AES_CBC
from cryptopalsmod.hash.sha1 import SHA1
from cryptopalsmod import bytestringops as bso
import secrets

def simulate_communication_with_dh_key(prime, base):
    """ Simulates a communication between two parties who first exhanges key via
    diffiehillman and encrypt messages using aes_cbc. Returns two messages, one
    encrypted by each party
    """

    alice = {}


    alice['dh'] = DiffieHellman(prime, base, secret_key=secrets.randbelow(prime))
    alice_pub = alice['dh'].gen_public_key() 

    #bob recieves alice's public key, generates their own public key and
    #the shared key. Sends their public key ot alice
    bob = {'dh':DiffieHellman(prime, base, secret_key=secrets.randbelow(prime))}
    bob_pub = bob['dh'].gen_public_key()
    bob['dh'].gen_shared_key(alice_pub)

    ### Alice recieves Bob's public key, generates the shared key and encrypts
    ### message for bob

    alice['dh'].gen_shared_key(bob_pub)
    alice['message'] = b'Message to Bob'   

    alice['sha1'] = SHA1(bso.int_to_bytes(alice['dh'].shared_key))
    alice['cipher'] = AES_CBC(alice['sha1'].digest()[:16], secrets.token_bytes(16))
    alice_ciphertext = alice['cipher'].encrypt(alice['message'])
    alice_ciphertext += alice['cipher'].IV

    #Bob encrypts his own ciphertext.

    bob['message'] = b'Message to Alice'

    bob['sha1'] = SHA1(bso.int_to_bytes(bob['dh'].shared_key))
    bob['cipher'] = AES_CBC(bob['sha1'].digest()[:16], secrets.token_bytes(16))
    bob_ciphertext = bob['cipher'].encrypt(bob['message'])
    bob_ciphertext += bob['cipher'].IV


    ### Check decryption works

    assert(bso.remove_padding_pkcs7(alice['cipher'].decrypt(bob_ciphertext[:-16], bob_ciphertext[-16:])) == bob['message'])

    
    assert(bso.remove_padding_pkcs7(bob['cipher'].decrypt(alice_ciphertext[:-16], alice_ciphertext[-16:])) == alice['message'])

    ## return ciphertexts for the man in the middle to decrypt

    return alice_ciphertext, bob_ciphertext

def main():

    prime = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    
    for base in [1, prime, prime - 1]:
        messages = simulate_communication_with_dh_key(prime, base)
        if base == prime:
            secret_key = 0
        else:
            secret_key = 1
            
        aes_key = SHA1(bso.int_to_bytes(secret_key)).digest()[:16]
        malcolm = AES_CBC(aes_key, b'0'*16)

        assert bso.remove_padding_pkcs7(malcolm.decrypt(messages[0][:-16], messages[0][-16:])) == b'Message to Bob'


        assert bso.remove_padding_pkcs7(malcolm.decrypt(messages[1][:-16], messages[1][-16:])) == b'Message to Alice'


if __name__ == "__main__":
    main()