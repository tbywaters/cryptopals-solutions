""" A collection of functions which are used for manipulating bytes when
solving the cryptopals challenges"""

import base64
import bitarray

def hex_to_bytes(hex_string):
    """Converts a encoded string of hex values to a bytes object
    
    Args: 
        hex_string(str): a string in hex

    returns:
        bytes: converted hex_string
    """
    return bytes.fromhex(hex_string)

def bytes_to_64(byte_string):
    """ Converts a bytes like object to a base64 string
    
    Args: 
        byte_string(bytes): bytes to be converted

    returns:
        str: string in base 64 from byte_string
    """ 
    return base64.b64encode(byte_string).decode()

def hex_to_64(hex_string):
    """Converts a string of hex to a string in base 64

    Args: 
        hex_string(str): a string in hex

    returns:
        str: string in base 64 from byte_string
    """
    return bytes_to_64(hex_to_bytes(hex_string))

def bytes_to_hex(byte_string):
    """Converts a bytes object to a string in hex

    Args: 
        byte_string(bytes): bytes object to be converted

    returns:
        str: string in hex from byte_string
    """
    return byte_string.hex()

def FixedXOR(bytestring1, bytestring2):
    """Takes two byte like objects of equal lengths and returns a bytearray of
     the XOR
     
     Args:
        bytestring1(bytes): argument of XOR
        bytestring2(bytes): argument of XOR, equal length to bytestring1

    returns:
        bytes: bytewise XOR of bytesting1 and bytestring2
     """

    #test if the inputs have equal lengths. Could be removed but is stipulated
    #in one of the cryptopals challenges
    assert len(bytestring1) == len(bytestring2)

    output = bytes([byte1^byte2 for (byte1, byte2) in zip(bytestring1, bytestring2)])

    return output

def repeatedXOR(bytestring1, bytestring2):
    """Takes two bytestrings and XORs them bytewise repeating the bytes or the smaller bytestring
    eg
    repeatedXOR(b'longerbytes', b'short') will return the FixedXOR of b'longerbytes' and b'shortshorts'
    repeatedXOR(b'short', b'longerbytes') will produce the same output
     
    Args:
        bytestring1(bytes): argument of XOR
        bytestring2(bytes): argument of XOR

    returns:
        bytes: bytewise XOR of bytesting1 and bytestring2, repeating characters
            from the shorter input if necessary        
    """

    # Swap the inputs so that bytestring1 is the longer of the two
    if len(bytestring2) > len(bytestring1):

        temp = bytestring1
        bytestring1 = bytestring2
        bytestring2 = temp
        
    output = b''

    for index, byte in enumerate(bytestring1):
        output += bytes([byte ^ bytestring2[index % len(bytestring2)]])
    
    return output

def zipXOR(bytestring1, bytestring2):
    """Takes two bytes like objects of and returns a bytes object of
    the XOR, shortening the longer of the two inputs.
     
     Args:
        bytestring1(bytes): argument of XOR
        bytestring2(bytes): argument of XOR

    returns:
        bytes: bytewise XOR of bytesting1 and bytestring2
    """
    return bytes([byte1^byte2 for (byte1, byte2) in zip(bytestring1, bytestring2)])
    
def bytes_to_bits(bytestring):
    """Takes a bytes like object and returns a bitarray
    
    Args:
        bytestring(bytes): bytes to be converted

    returns:
        bitarray: bitarray obtains from the bytestring
    """

    bits = bitarray.bitarray()
    bits.frombytes(bytestring)

    return bits


def HammingDistance(bytestring1, bytestring2):
    """Computes the Hamming distance between two bytes objects AFTER converting
    them into sequences of bits. Hamming distance is the number of positions 
    where the sequences differ. If the bytes are of different length, the 
    larger is shortened via the zip function.
    
    Args:
        bytestring1(bytes): argument of distance
        bytestring2(bytes): argument of distance

    returns:
        bytes: hamming distance between the bytestring1 and bytestring2

    """
  
    # Convert bytes to bits
    bitstring1 = bytes_to_bits(bytestring1)
    bitstring2 = bytes_to_bits(bytestring2)

    distance = 0
    for (bit1, bit2) in zip(bitstring1, bitstring2):
        if bit1 != bit2:
            distance += 1

    return distance
    
def transpose_by_blocklength(bytestring, blocklength):
    """Splits a bytes object into a list of bytes objects as follows:
    the ith element of the list will contain the ith element of the input, plus
    byte at position i + blocklength, plus the byte at position
    i + 2*blocklength etc...

    Alternatively, this can be viewed as transposing the martrix that is built
    using blocks of length blocklenght as rows. The function returns the rows 
    of the transposed matrix as bytes objects

    Args:
        bytestring (bytes): the bytes object to be spit
        blocklength (int): the length of the blocks

    returns:
        list: a list of bytes
    """

    transpose = []
    for remainder in range(0, blocklength):
        increment = 0
        row = b''
        while increment*blocklength + remainder < len(bytestring):
            character = bytes([bytestring[increment*blocklength + remainder]])
            row += character
            increment += 1
        
        transpose.append(row)
    
    return transpose

def pad_pkcs7(bytestring, desired_length):
    """Pads a bytes object until it is the desired length using PKCS#7 padding
    scheme. The desired length must not over 255 more than the length of the
    bytestring for the padding scheme to work. If otherwise thows an assertion
    error.

    Args:
        bytestring (bytes): bytes object to be padded
        desired_length (int): the desired length of the padded bytestring

    returns:
        bytes: the padded bytestring, has length desired_length
    """
    #If the bytestring is longer than the desired length, there is no padding 
    #to be done.
    if len(bytestring) >= desired_length:
        return bytestring

    assert desired_length - len(bytestring) <= 255

    extra_padding_length = desired_length - len(bytestring)

    extra_padding = bytes(extra_padding_length*[extra_padding_length])

    return bytestring + extra_padding

def pad_by_multiple(bytestring, padding_multiple, extra_block = False):
    """Pads a bytes object until its length is a multiple of padding_multiple
    using pad_pkcs7 (PKCS#6). If extra_block = True, then there is always some
    padding done, even if it means adding an extra block of length 
    padding_mutiple.

    Args:
        bytestring(bytes): bytes object to be padded
        padding_multiple(int): number to which the length of padded bytes is to 
            be a multiple of
        extra_block = False (bool): if set to True, some padding will be done,
            even if it means adding an extra block of only padding to the 
            message

    returns:
        bytes: padded bytestring
    """

    block_num = 0
    while block_num*padding_multiple < len(bytestring):
        block_num += 1

    desired_length = block_num*padding_multiple

    if extra_block and desired_length == len(bytestring):
        desired_length += padding_multiple

    return pad_pkcs7(bytestring, desired_length)

def remove_padding_pkcs7(bytestring):
    """Determines wether a string has been padded correctly using PKCS#7. A
    message that has not been padded it unlikely to have valid padding. If
    the massage has been padded correctly, removes the padding. Otherwise thows
    an exception"""

    last_byte = bytestring[-1]
    invalid_padding_error = Exception('Invalid padding')
    
    if last_byte > len(bytestring):
        raise invalid_padding_error
    
    padding = bytestring[-last_byte:]
    for byte in padding:
        if byte != bytestring[-1]:
            raise invalid_padding_error

    return bytestring[:-last_byte]

def int_to_bytes(number):
    """Converts a number to a bytes object with as small a length as possible
    """

    start_length = 1
    while True:
        try:
            return number.to_bytes(start_length, byteorder='big')
        except OverflowError:
            start_length += 1

def byte_len(number):
    
    return (number.bit_length() + 7)//8
    

