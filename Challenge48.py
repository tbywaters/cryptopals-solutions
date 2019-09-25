from cryptopalsmod.ciphers import rsa
import secrets
from cryptopalsmod import bytestringops as bso
import cryptopalsmod.number_theory as nt
from cryptopalsmod import rsa_attacks
import Challenge47


def main():
    server = Challenge47.RSAPaddingOracle(prime_size = 768//2)
    client = Challenge47.ChallengeRSAClient()

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
    for num in range(0,100):
        main()
        print(num)
