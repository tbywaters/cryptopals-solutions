import cryptopalsmod.bytestringops as bso

def padding_oracle_attack(ciphertext, IV, padding_oracle, blocklength):
    """Decrypts a ciphertext encrypted using AES_CBC with IV but an
    unknown secret key. Decryption uses a padding oracle which can take custom
    IV values but must have knowledge of the secret key. It assumes that the 
    padding oracle returns true if a ciphertext and IV satisfy correct padding
    (plaintext should pass bytestringops.remove_padding_pkcs7) and raises an
    exception otherwise.

    Args:
        ciphertext (bytes): encrypted using AES_CBC
        IV (bytes): IV used to encrypt ciphertext
        padding_oracle (function): takes as inputs ciphertext (bytes) and IV 
            (bytes). Returns true if when the ciphertext is decrypted that padding
            is valid and thows an exception if otherwise. This function should have
            knowledge of the secret key used to encrypt ciphertext. In particular,
            padding_oracle(ciphertext, IV) -> true
        blocklength: Length of blocks used in encrypting ciphertext
    """
    #Save the length of the original cipher text
    ciphertext_length = len(ciphertext)
    
    plaintext = b''
    
    while len(plaintext) < ciphertext_length:
        plaintext = padding_oracle_decrypt_last_block(ciphertext, IV, padding_oracle, blocklength) + plaintext
        #### Chop of the block of ciphertext which as been decrypted
        ciphertext = ciphertext[:-16]
    
    return plaintext

def padding_oracle_decrypt_last_block(ciphertext, IV, padding_oracle, blocklength):
    """Decrypts the last block of a ciphertext encrypted using AES_CBC with IV but an
    unknown secret key. Decryption uses a padding oracle which can take custom
    IV values but must have knowledge of the secret key. It assumes that the 
    padding oracle returns true if a ciphertext and IV satisfy correct padding
    (plaintext should pass bytestringops.remove_padding_pkcs7) and raises an
    exception otherwise

    Args:
        ciphertext (bytes): encrypted using AES_CBC
        IV (bytes): IV used to encrypt ciphertext
        padding_oracle (function): takes as inputs ciphertext (bytes) and IV 
            (bytes). Returns true if when the ciphertext is decrypted that padding
            is valid and thows an exception if otherwise. This function should have
            knowledge of the secret key used to encrypt ciphertext. In particular,
            padding_oracle(ciphertext, IV) -> true
        blocklength: Length of blocks used in encrypting ciphertext
    """
    decrypted = b''

    while len(decrypted) < 16:
        
        #depending on how long the cipher text is, we will alter it or the IV
        test_ciphertext = IV + ciphertext

        position_to_edit = blocklength + len(decrypted) + 1

        #During decryption, the last block of test_ciphertext will be decrypted
        #and then xor'd with the second last block. Alter the second last block
        #of test_ciphertext so that this almost has valid padding

        new_secondlast_block_ending = bso.FixedXOR(decrypted, bytes(len(decrypted)*[len(decrypted) + 1]))
        
        test_ciphertext = (test_ciphertext[:-position_to_edit + 1] 
                            + new_secondlast_block_ending 
                            + test_ciphertext[-blocklength:])

        #Change test_ciphertext[position_to_edit] untill the padding oracle gives
        #correct padding. Not changing the byte may also give correct padding, 
        #but we only consider this byte if it is the unique option.
        correct_choice = None
        fixed_byte = test_ciphertext[-position_to_edit]
        for byte in range(0,256):
            if byte == fixed_byte:
                pass
            else:
                test_ciphertext = (test_ciphertext[:-position_to_edit]
                                    + bytes([byte])
                                    + test_ciphertext[-position_to_edit+1:])
                
                try:
                    assert padding_oracle(test_ciphertext[blocklength:], IV=test_ciphertext[:blocklength])
                    correct_choice = byte
                    break
                except:
                    pass

        #If correct_choice has not been set, there is only one value which gives
        #correct value, the original test_ciphertext[-position_to_edit] which is
        #fixed_byte. This tells us something about tha padding of the plaintext
        #message.
        if correct_choice == None:
            correct_choice = fixed_byte
            print('berr')
        

        decrypted = bso.FixedXOR(bytes([correct_choice]), bytes([len(decrypted) + 1])) + decrypted

    #XOR decrypted with the appropriate ciphertext block to get plaintext message
    #as usual with cbc
    plaintext = bso.FixedXOR((IV + ciphertext)[-32:-16], decrypted) 

    return plaintext

def IV_equals_key(decrypt, ciphertext = None):
    """Obtains the IV from a cipher using it's decrypt function assuming that
    this function raises an exception if given a ciphertext that does not decrypt
    to valid ASCII and the message in the exception contains plaintext as the
    initial segment. Ciphertext is altered to to get the key and needs to be at
    least 48 bytes (Maybe not. What if we thow anything in there? should be fine)
    as long as padding is not checked.
    """

    #One of these values will give invalid ASCII
    for byte in range(0,256):
        new_ciphertext = ciphertext[:16] + bytes(16*[0]) + ciphertext[:16] + bytes(16*[byte]) + ciphertext[-32:]
        try:
            decrypt(new_ciphertext)
        except Exception as e:
            messed_up_plaintext = e.args[0]
            key = bso.FixedXOR(messed_up_plaintext[:16], messed_up_plaintext[32:48])
            break
    
    return key