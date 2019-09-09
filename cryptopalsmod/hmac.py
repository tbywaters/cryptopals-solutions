from cryptopalsmod import bytestringops as bso

def hmac(key, message, hash_function, blocksize, outputsize):
    """Implementation of HMAC based on wikipedia pseudocode

    Args:
        key (bytes)
        message (bytes)
        hash_function (function object): hash function which accepts bytes and returns
            hased bytes as bytes object.
        blocksize (int): size of blocks (in bytes) used in the hash function
        outputsize (int): length of output (in bytes) given by the hash function

    return:
        bytes: MAC

    """
    if len(key) > blocksize:
        key = hash_function(key)

    if len(key) < blocksize:
        key += bytes(blocksize - len(key))

    o_key_pad = bso.FixedXOR(key, bytes(blocksize*[0x5c]))
    i_key_pad = bso.FixedXOR(key, bytes(blocksize*[0x36]))

    return hash_function(o_key_pad + hash_function(i_key_pad + message))