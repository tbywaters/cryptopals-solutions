from cryptopalsmod.hash import sha1
import secrets
import hashlib

def main():
    test_message = b"hello, is it me you're looking for"
    key = secrets.token_bytes(16)
    reliable_hash = hashlib.sha1(key + test_message).digest()
    my_hash = sha1.sha1_key_msg_MAC(key, test_message)
    assert reliable_hash == my_hash
    
if __name__ == "__main__":
    main()