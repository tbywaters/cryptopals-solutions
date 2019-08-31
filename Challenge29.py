from cryptopalsmod.hash import sha1
import cryptopalsmod.mac_attacks as mac_attacks
import secrets

class ChallengeOracleSHA1:
    """Oracle used to generate MAC and obtain the key value and new MACs"""
    def __init__(self):
        self.key = secrets.token_bytes(secrets.randbelow(100))

    def MAC(self, plaintext):
        return sha1.sha1_key_msg_MAC(self.key, plaintext)

def main():
    
    oracle = ChallengeOracleSHA1()
    
    original = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    hashtext = oracle.MAC(original)
    plaintext_to_add = b';admin=true'
    

    for key_length in range(0, 100):
        text_original_length = 8*(key_length + len(original))
        fake_hash_text = mac_attacks.sha1_keyed_mac_length_extension(hashtext, plaintext_to_add, text_original_length)

        glue_padding = sha1.sha_padding(text_original_length)
        glue_padding_bytes = b''.join([bytes([int(glue_padding[i:i+8], 2)]) for i in range(0, len(glue_padding), 8)])  
    
        altered_plain_text = original + glue_padding_bytes + plaintext_to_add
        
        if oracle.MAC(altered_plain_text) == fake_hash_text:
            return fake_hash_text
    
    raise Exception('Unable to alter hash')

if __name__ == "__main__":
    main()