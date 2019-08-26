""" A collection of functions which are used for attacking AES_ECB encryption
 when solving the cryptopals challenges"""
import secrets
import collections



def num_of_repeats(bytestring, blocklength = 16):
    """Creates a tally which counts every block of length blocklength in
    a bytes object which repeats

    Eg:
        (bytestring = b'BAAAAABBBBBBB', blocksize = 2) -> 5
        (bytestring = b'BAAAAABBBBBBB', blocksize = 3) -> 2
        (bytestring = b'BAAAAABBBBBBB', blocksize = 4) -> 0

    Args:
        bytestring (bytes): bytes object to look for repeats in
        blocklength (int) = 16: length of blocks
    Returns:
        int: tally of blocks which repeat
    """
    blocks = [bytestring[i:i+blocklength] for i in range(0, len(bytestring), blocklength)]
    repeat_counter = collections.Counter(blocks)
    
    repeats = 0
    for block in repeat_counter.keys():
        if repeat_counter[block] > 1:
            repeats += 1
    
    return repeats


def detect_ECB(ciphertext, blocklength = 16):
    """Takes an AES encrypted ciphertext and a block length and attempts to 
    determine if the encryption mode used was ECB by looking for repeated blocks
    of ciphertext. The function returns True if a repeated block is found,False
    otherwise"""

    blocks = [ciphertext[i:i+blockLength] for i in range(0, len(ciphertext), blockLength)]

    counter = collections.Counter(blocks)

    for block in counter.keys():
        if counter[block] > 1:
            return True

    return False

def determine_ECB_keylength(oracle):
    """Takes in an ECB oracle an encrypt method (written with 
    cryptopadmod.ciphers.aes_ecb.AES_ECB cipher in mind) and determines 
    the length of the key used for encryption. Assumes the oracle does not
    prepad the input
    
    Args:
        oracle (AES_ECB): an oracle which encripts with AES in ECB mord
    Returns 
        int: key length in bytes, either 16 or 32. Returns -1 if the test fails
    """
    key_lengths = [16, 32]
    for key_length in key_lengths:
        for byte in range(0,255):
        
            prefix = bytes(2*key_length*[byte])
            
            encryption = oracle.encrypt(prefix)
              
            if encryption[:key_length] != encryption[key_length:2*key_length]:
                break
            return key_length

    return -1

def first_block_which_repeats_pos(bytestring, blocklength = 16):
    """Takes a bytes obgect and returns the index to the first byte in a block 
    which repeats later in bytes. Default blocksize = 16. If there are no
    repeating blocks, returns len(bytestring)

    Eg:
        (bytestring = b'BAAAAABBBBBBB', blocksize = 2) -> 2
        (bytestring = b'BAAAAABBBBBBB', blocksize = 3) -> 6
        (bytestring = b'BAAAAABBBBBBB', blocksize = 4) -> 13

    Args:
        bytestring (bytes): bytes object to look for repeats in
        blocklength (int) = 16: length of blocks
    Returns:
        int: position for the first byte in the first block which repeats,
            length of bytestring if no such block exists.
    """

    blocks = [bytestring[i:i+blocklength] for i in range(0, len(bytestring), blocklength)]
    repeat_counter = collections.Counter(blocks)

    for index, block in enumerate(blocks):
        if repeat_counter[block] > 1:
            return index*16
    
    return len(bytestring)

def determine_prepad_length(oracle, blocklength = 16):
    #TODO: change function so that it does not fail if the prefix contains block repititions
    """Takes an AES_ECB oracle with a encrypt method that appends a fixed number of
    random bytes to a plaintext before encryption. Determines the number of bytes
    which are prefixed. Note: function will fail if the prefixed bytes contain a 
    block that appears twice.

    Args:
        oracle (cryptopalsmod.ciphers.aes_ecb.AES_ECB like object): oracle which
        encrypts using AES_ECB and has an encrypt method which does this
        blocklength (int): oracles ecb blocklength in bytes

    returns:
        int: number ogf bytes which the oracle prefixs to any plaintext, assuming
        this is a fixed number
    """ 
    junk_chars = 0
    initail_num_repeats = num_of_repeats(oracle.encrypt(b''), blocklength=blocklength)
    current_num_repeats = initail_num_repeats


    #Feed in constant characters of a fixed length until an extra repeated block is found
    while current_num_repeats <= initail_num_repeats:
        
        junk_chars += 1
        test_string = bytes(junk_chars * [secrets.choice(range(0,255))])
        ciphertext = oracle.encrypt(test_string)
        current_num_repeats = num_of_repeats(ciphertext, blocklength=blocklength) 
        first_repeat_pos = first_block_which_repeats_pos(ciphertext, blocklength=blocklength)

    #The number of repeated characters needed to create a repeated block should be at least 2*blocklength. 
    # Any extra is used to increase the size of the prefix until it is a multiple of the blocklength
    
    extra = junk_chars - 2*blocklength

    return first_repeat_pos - extra