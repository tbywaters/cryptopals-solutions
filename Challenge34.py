from cryptopalsmod.ciphers.diffiehellman import DiffieHellman
import secrets
from cryptopalsmod.hash.sha1 import SHA1
from cryptopalsmod.ciphers.aes_cbc import AES_CBC
import struct
import cryptopalsmod.bytestringops as bso

def diffiehellman_mitm_sim(prime, base):
    """This function simulates an exchange between two parties, first using 
    Diffie Hillmann to exchange secret keys and then AES CBC to exchange 
    messages. However, the function uses yield functionality to simulate a man
    in the middle attack.
    """
    alice = {}

    #Alice generates their public key an sends to 'bob'
    alice['dh'] = DiffieHellman(prime, base, secret_key=secrets.randbelow(prime))
    alice_pub = alice['dh'].gen_public_key()

    (prime, base, key_for_bob) = yield (prime, base, alice_pub)

    

    #bob recieves 'alice's' public key, generates their own public key and
    #the shared key. Sends their public key ot 'alice'
    bob = {'dh':DiffieHellman(prime, base, secret_key=secrets.randbelow(prime))}
    bob_pup = bob['dh'].gen_public_key()
    bob['dh'].gen_shared_key(key_for_bob)

    key_for_alice = yield bob_pup

    ### Alice recieves Bob's public key, generates the shared key and encrypts
    ### message for bob

    alice['dh'].gen_shared_key(key_for_alice)
    
    alice['sha1'] = SHA1(bso.int_to_bytes(alice['dh'].shared_key))
    alice['cipher'] = AES_CBC(alice['sha1'].digest()[:16], secrets.token_bytes(16))
    alice_ciphertext = alice['cipher'].encrypt(b'Message to Bob')
    alice_ciphertext += alice['cipher'].IV

    ciphertext_for_bob = yield alice_ciphertext
     
    #Bob recieves the ciphertext, decrypts it and send a reply.

    bob['sha1'] = SHA1(bso.int_to_bytes(bob['dh'].shared_key))
    bob['cipher'] = AES_CBC(bob['sha1'].digest()[:16], secrets.token_bytes(16))
    bob_ciphertext = bob['cipher'].encrypt(b'Message to Alice')
    bob_ciphertext += bob['cipher'].IV

    ciphertext_for_alice = yield bob_ciphertext

    ### Finally alice decrypts bobs reply

    alice['cipher'].decrypt(ciphertext_for_alice[:-16], ciphertext_for_alice[-16:])
    

def main():
    """Simulate a man in the middle attack on Diffie Hellman key exchange"""

    prime = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    base = 2
    
    connection = diffiehellman_mitm_sim(prime, base)

    # intercept alices public key
    prime, base , _ = next(connection)

    # send prime instead of alices public key to bob. Recieve Bobs public key, 
    # which we forget as it is not needs. The shared kill will be 0.

    connection.send((prime, base, prime))

    #Send prime as bob's public key to alice. We have ensured that the shared
    #hared secret key is 0. Recieve Alice's ciphertext for bob
    ciphertext_a2b = connection.send(prime)

    # decrypt
    malcolm = AES_CBC(SHA1(bso.int_to_bytes(0)).digest()[:16], b'0'*16)
    messages = []
    messages.append(bso.remove_padding_pkcs7(malcolm.decrypt(ciphertext_a2b[:-16], ciphertext_a2b[-16:])))

    #Send the ciphertext to bob. Recieve his response
    ciphertext_b2a = connection.send(ciphertext_a2b)

    messages.append(bso.remove_padding_pkcs7(malcolm.decrypt(ciphertext_b2a[:-16], ciphertext_b2a[-16:])))

    assert messages[0] == b'Message to Bob'
    assert messages[1] == b'Message to Alice'

    
    return

if __name__ == "__main__":
    main()