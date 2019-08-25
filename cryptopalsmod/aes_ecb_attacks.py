import collections

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