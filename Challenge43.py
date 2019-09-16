from cryptopalsmod.hash.sha1 import SHA1
from cryptopalsmod.ciphers import dsa
from cryptopalsmod import dsa_attacks

def main():

    #Check that the DSA works as expected
    message = b"""For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch\n"""

    signatory = dsa.DSAUser(hash_func=SHA1)
    verifier = dsa.DSAUser(hash_func=SHA1)

    assert verifier.verify(message, *signatory.sign_message(message))
    assert not verifier.verify(message, 1, 1, 1)

    #crack the nonce as specified in the challenge
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    attacker = dsa_attacks.DSAattacks(SHA1)

    secret_key = attacker.brute_force_attack_on_nonce(message,
                                                        r,
                                                        s,
                                                        max_nonce=2**16)

    assert SHA1(hex(secret_key)[2:].encode()).hexdigest() == '0954edd5e0afe5542a4adf012611a91912a3ec16'
if __name__ == "__main__":
    main()