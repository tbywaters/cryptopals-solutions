import random
import cryptopalsmod.stringops as stringops
from cryptopalsmod.ciphers.aes_ecb import AES_ECB_random
import cryptopalsmod.bytestringops as bso

def profile_for(email_address):
    """Take a email_address(string) and cleans out meta characters before
    generating user details. Returns user encoded as a k=v string with data
    fields separated by an &"""

    email_address = stringops.remove_meta_chars(email_address, '=&')

    email_str = "email="+email_address
    userid_str = "userid=" + str(random.choice(range(0,10)))
    role_str = 'role=user'

    return email_str + '&' + userid_str + '&' + role_str

class challenge_cipher(AES_ECB_random):
    """A cipher designed specifially for this challenge. The encryption function
    takes a plaintext (string) and encodes it as an email address for a user 
    using the profile_for function before encrypting. The decryption validates
    and removes padding after decryption and returns the user profile decoded as
    a dictionary. 
    """

    def __init__(self):
        AES_ECB_random.__init__(self)

    def encrypt(self, plaintext):
        plaintext = profile_for(plaintext).encode()
        plaintext = bso.pad_by_multiple(plaintext, 16, extra_block=True)
        return AES_ECB_random.encrypt(self, plaintext)
    
    def decrypt(self, ciphertext):
        plaintext = AES_ECB_random.decrypt(self, ciphertext)
        plaintext = bso.remove_padding_pkcs7(plaintext)
        return stringops.kequalsv_to_dict(plaintext.decode())

def main():

    user_email = 'foo@bar.com'
    
    ''' encryption do not touch'''
    cipher = challenge_cipher()

    ciphertext = cipher.encrypt(user_email)

    """ Alter cipher text under here to create admin user"""
    newLastBytePlaintext = b'0000000000admin'+bytes(11*[11])
    newLastByteEncrypt = cipher.encrypt(newLastBytePlaintext.decode())[16:32]

    ciphertext = ciphertext[:-16] + newLastByteEncrypt
    
    user = cipher.decrypt(ciphertext)
    assert user['role'] == 'admin'
    

if __name__ == "__main__":
    main()