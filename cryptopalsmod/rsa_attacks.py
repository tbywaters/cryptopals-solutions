from cryptopalsmod import number_theory as nt

def hastad_attack(e, ciphertexts, public_keys):
    """The simplest version of hastads attack decrypts a message encrypted multiple
    times using different public keys. The number of encrypted ciphertexts required is 
    the value e (exponent public key) used in rsa encryption. The algorithm relies
    on the chinese remainder theorem.
    
    Args:
        e (int): the exponent used for rsa encryption, eg e = 3
        ciphertexts (list<int>): a list of length e of encryptions of the original message
        public_keys (list<int>): a list of length e of public keys used to encrypt the message
            to get the ciphertexts

    returns:
        int : the original message.
    raises:
        Exception('invalid arguements') if len(ciphertexts) != e or len(public_keys)!= e
    """
    if e != len(ciphertexts) or e != len(public_keys):
        raise Exception('invalid arguements')

    message_e_power = nt.chinese_remainder_theorem(ciphertexts, public_keys)

    return nt.newton_root(e, message_e_power)
    