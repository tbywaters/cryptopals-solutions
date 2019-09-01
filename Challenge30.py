from cryptopalsmod.hash import md4
import hashlib
from cryptopalsmod import mac_attacks
import secrets

class ChallengeOracleSHA1:
    """Oracle used to generate MAC and obtain the key value and new MACs"""
    def __init__(self):
        self.key = secrets.token_bytes(secrets.randbelow(100))

    def MAC(self, plaintext):
        return md4.MD4(self.key + plaintext).digest()


def main():
    mymd4 = md4.MD4(b'hello').digest()

    trusted_md4 = hashlib.new('md4', b'hello').digest()

    assert mymd4 == trusted_md4

    oracle = ChallengeOracleSHA1()
    
    original = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    hashtext = oracle.MAC(original)
    plaintext_to_add = b';admin=true'
    

    for key_length in range(0, 100):
        text_original_length = key_length + len(original)
        fake_hash_text = mac_attacks.md4_keyed_mac_length_extension(hashtext, plaintext_to_add, text_original_length)

        glue_padding = md4.MD4.padding(text_original_length)
    
        altered_plain_text = original + glue_padding + plaintext_to_add
        
        if oracle.MAC(altered_plain_text) == fake_hash_text:
            return fake_hash_text
    
    raise Exception('Unable to alter hash')



if __name__ == "__main__":
    main()