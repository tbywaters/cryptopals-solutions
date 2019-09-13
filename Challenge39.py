from cryptopalsmod.ciphers import rsa
import secrets
from cryptopalsmod import bytestringops as bso

def main():
    alice = rsa.RSAServer()
    bob = rsa.RSAClient()
    e, n = alice.send_public_key()
    bob.recv_public_key(e, n)

    bob_msg = secrets.randbelow(2**1024)
    ciphertext = bob.encrypt(bob_msg)
    assert alice.decrypt(ciphertext) == bob_msg

    plaintext = b'A random message'
    plaintext_int = int(bso.bytes_to_hex(plaintext), 16)
    decrypted_message = alice.decrypt(bob.encrypt(plaintext_int))
    decrypted_message = hex(decrypted_message)

    decrypted_message = bso.hex_to_bytes(decrypted_message[2:])
    assert decrypted_message == plaintext
if __name__ == '__main__':
    main()