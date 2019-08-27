

def fixed_nonce_attack(ciphertexts):
    """Takes a number of list of ciphertexts encrypted independently using the 
    same nonce and secret key. Decrypts by treating the ciphertexts as an XOR. 
    More accurate if there is more ciphertexts of longer length. May be 
    inaccurate at the end of the ciphertext if the number of ciphertexts at a
    given length is reduced.
    
    Args:
        ciphertexts (List<bytes>) : list of ciphertexts to be decrypted. The more
            the better

    returns:
        bytes : XORing this value with the cipherdects will give the estimated
            decryption
    """
    lengths = [len(ciphertext) for ciphertext in ciphertexts]
    lengths = sorted(list(set(lengths)))
    
    previous = 0
    key = b''
    for key_length in lengths:
        shortened_ciphertexts = [ciphertext[previous:key_length] for ciphertext in ciphertexts if len(ciphertext) > previous]
        joined_ciphertexts = b''.join(shortened_ciphertexts)

        key += xorattacks.repeatedXOR_attack_key(joined_ciphertexts, key_length - previous)
        
        previous = key_length
    
    return key