from cryptopalsmod.hash import sha1, md4
import struct


def sha1_keyed_mac_length_extension(hashtext, plaintext_to_add, original_msg_length):
    """Extends a sha1 hashed message.

    Args:
        hashtext (bytes): original hashtext to extend
        plaintext_to_add (bytes): plaintext to add to the hash
        original_msg_length (int): length of the text (num of bytes) hashed to get hashtext
    
    return:
        bytes: sha1(original_plaintext + original_padding + plaintext_to_add) where
            sha1(original_plaintext) = hashtext
            original_padding is the padding added to original_plaintext in the sha1 algorithm
    """

    #The internal state of sha1 can be obtained from the hashtext
    internal_state = list(struct.unpack('>IIIII', hashtext))
    #Calculate the new message legnth in bits and use it to obtain the correct padding
    message_length = original_msg_length + len(sha1.SHA1.padding(original_msg_length)) + len(plaintext_to_add)

    new_hashtext = sha1.SHA1(plaintext_to_add, initial_state=internal_state, message_length=message_length).digest()
    return new_hashtext

def md4_keyed_mac_length_extension(hashtext, plaintext_to_add, original_msg_length):
    """Extends a sha1 hashed message.
    Args:
        hashtext (bytes): original hashtext to extend
        plaintext_to_add (bytes): plaintext to add to the hash
        original_msg_length (int): length of the text (num of bytes) hashed to get hashtext
    
    return:
        bytes: md4(original_plaintext + original_padding + plaintext_to_add) where
            md4(original_plaintext) = hashtext
            original_padding is the padding added to original_plaintext in the md4 algorithm
    """

    #The internal state of sha1 can be obtained from the hashtext
    internal_state = list(struct.unpack('<IIII', hashtext))
    
    #Calculate the new message legnth in bits and use it to obtain the correct padding
    message_length = original_msg_length + len(md4.MD4.padding(original_msg_length)) + len(plaintext_to_add)

    new_hashtext = md4.MD4(plaintext_to_add, initial_state=internal_state, message_length=message_length).digest()
    return new_hashtext