from cryptopalsmod.hash import sha1


def sha1_keyed_mac_length_extension(hashtext, plaintext_to_add, original_msg_length):
    """Extends a sha1 hashed message.

    Args:
        hashtext (bytes): original hashtext to extend
        plaintext_to_add (bytes): plaintext to add to the hash
        original_msg_length (int): length of the text in bits (8* length in bytes) hashed to get hashtext
    
    return:
        bytes: sha1(original_plaintext + original_padding + plaintext_to_add) where
            sha1(original_plaintext) = hashtext
            original_padding is the padding added to original_plaintext in the sha1 algorithm
    """

    #The internal state of sha1 can be obtained from the hashtext
    bin_hashtext = ''.join(["{0:08b}".format(byte) for byte in hashtext])
    internal_state = list([int(bin_hashtext[i:i+32],2) for i in range(0,len(bin_hashtext),32)])

    #Calculate the new message legnth in bits and use it to obtain the correct padding
    message_length = original_msg_length + len(sha1.sha_padding(original_msg_length)) + 8*len(plaintext_to_add)
    padding = sha1.sha_padding(message_length)

    new_hashtext = sha1.SHA1(plaintext_to_add, initial_values=internal_state, custom_padding=padding)
    return new_hashtext