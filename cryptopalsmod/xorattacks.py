"""A collection of functions used for atting XOR based encryptions. Used for
solving cryptopals challenges"""

import cryptopalsmod.bytestringops as bso
import itertools
import random

EnglishFreq = {'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}
#Frequencies of characters (lower case) in the english language


def EnglishScore(bytestring, normalise = False):
    """ Assigns a score to a bytes object which is higher if the characters
    match those found in the English language

    Args:
        bytestring (bytes): the bytes object to be evaluated
        normailse (bool) = False: If True, the final score is divided by the
        length of bytestring as longer inputs are likely to have a higher score.

    returns:
        float: sum of frequencies of each character. frequencies obtained
        form EnglishFreq.
    """

    score = 0
    for byte in bytestring:

        #EnglishFreq only contains lower case keys
        character = chr(byte).lower()
        score += EnglishFreq.get(character, 0)
    
    if normalise:
        score = score/len(bytestring)

    return score

def xor_singlebyte_key_attack(bytestring):
    """Attemts to decrypt an English plaintext which has been encrypted using
    a single byte XOR to produce bytestring. This attack iterates through all 
    possible 256 single byte keys and assigns a score via EnglishScore. Yields 
    a dictionary with dictionary keys 'key' and 'decryption' in order
    of likeliness
    
    Args:
        bytestring (bytes): the bytes object to be decrypted

    Yields:
        dict: a dict of ('key':(bytes) most likely key,'score':(float) a score assigned
        to the decryption based on english chareter frequency, 
        'decryption':(bytes)decryption from key)
    """

    results = []

    for key in range(0,256):
        scoreDict = {}
        
        key = bytes([key])
        scoreDict['key'] = key
        
        decryption = bso.repeatedXOR(bytestring, key)
        scoreDict['score'] = EnglishScore(decryption)
        scoreDict['decryption'] = decryption

        
        results.append(scoreDict)
    
    #sort results based on score
    results = sorted(results, key=lambda val: val['score'], reverse=True)

    for result in results:
        yield result

def estimate_keylength(ciphertext, max_key_length = 40, num_of_pairs = -1):
    """Estimates the key length in a repeated XOR ciphertext using the 
    hamming distance between blocks. Yields key lengths in order of likeliness.

    Args:
        ciphertext (bytes): the ciphertext encrypted using a repeated xor for
        which we are estimating the key length

        max_key_length = 40 (int): the highest key length to test
        
        num_of_pairs = -1 (int): the number of pairs of blocks to calculate the
        hamming distance on. If less than or equal to -1, al possible pairs are
        used. This may be ineffiecent and unncessary for large  ciphertexts
        
    yields:
        int: length of the key
    """ 

    keys_and_distances = []
    for key_length in range(2, max_key_length + 1):
        
        #segment the ciphertext into blocks the size of the possible key_length
        blocks = [ciphertext[i: i+key_length] for i in range(0, len(ciphertext), key_length)]

        #Pair up blocks and then calculate distances. If num_of_pairs > 1, 
        # use only a random selecion of pairs. 

        pairs = list(itertools.combinations(blocks, 2))
        
        if num_of_pairs > -1:
            pairs = random.choices(pairs, k=num_of_pairs)
        
        #divide hamming distances by key_length since large blacks are likely
        #have larger hammin distances
        distances = [bso.HammingDistance(pair[0], pair[1])/(key_length) for pair in pairs]
        score = sum(distances)/len(distances)

        keys_and_distances.append({'key_length':key_length, 'score':score})

    #Sort and convert keys into a list without the score
    keys_and_distances = sorted(keys_and_distances, key=lambda val: val['score'])
    key_lengths = [key_and_distance['key_length'] for key_and_distance in keys_and_distances]

    for key_length in key_lengths:
        yield key_length

def repeatedXOR_attack_key(ciphertext, key_length):
    """Takes a ciphertext encrypted using a repeated XOR and a keylength and
    attempts and computes the most likely key using xor_singlebyte_key_attack
    
    Args:
        ciphertext (bytes): ciphertext encrypted using a repeated XOR
        key_length (int): key length to use for decryption

    returns:
        bytes: most likely key of length key_length
    """

    #split the ciphertext into bytes which, if the key_length is correct, have
    #been ecrypted using the same same byte
    transpose = bso.transpose_by_blocklength(ciphertext, key_length)

    key = b''
    for row in transpose:
        key += next(xor_singlebyte_key_attack(row))['key']
    
    return key

def repeatedXOR_attack(ciphertext, max_key_length = 40):
    """Takes a ciphertext encrypted using a repeated XOR and
    attempts to decrypt by estimating the key length using estimate_keylength
    and using this estimate to decrypt using repeatedXOR_attack_key. 
    yields a dictionary with the key and decryption in order of likliness of 
    key length
    
    Args:
        ciphertext (bytes): ciphertext encrypted using a repeated XOR
        max_key_length = 40 (int): the highest key length to test

    Yields:
        dict: a dict of ('key':most likely key (bytes), 'decryption': decryption
        based on the key (bytes))    
    """

    key_lengths = estimate_keylength(ciphertext, max_key_length)

    for key_length in key_lengths:
        key = repeatedXOR_attack_key(ciphertext, key_length)
        decryption = bso.repeatedXOR(ciphertext, key)
        yield {'key':key, 'decryption':decryption}


    