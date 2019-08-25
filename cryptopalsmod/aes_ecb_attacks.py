import collections

def detect_ECB(ciphertext, blockLength = 16):
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



