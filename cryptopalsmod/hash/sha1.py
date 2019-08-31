import hashlib
def _preprocess(message):
    #Formating b'' seems finicky. Working with normal strings instead.    
    message_bit_string = ''.join([format(byte, '08b') for byte in message])
    
    ml = len(message_bit_string)

    #We need to pad the message such that the legnth in bits is 448 mod 512. 
    #Padding is a 11 followed by 0's.
    
    # Add the 1     
    message_bit_string += '1'

    #Calculate the number of 0 bits required and add to message
    num_zeros = (448 - (len(message_bit_string) % 512)) % 512

    message_bit_string += num_zeros*'0'

    #add the length of the original message as a 64 bits 
    message_bit_string += format(ml, '064b')
    
    assert len(message_bit_string) % 512 == 0

    return message_bit_string

def left_rotate(x, n, w):
    return ((x<< n & (2 ** w - 1)) | (x >> w - n))


def SHA1(message):
    """Implementation o SHA1 based in wikipedias pseudocode.
    
    Args:
        message (bytes): message/date to be hashed
    Returns:
        bytes: hased message

    """

    #Initialise
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    #Preprocessing
    processed_message = _preprocess(message)

    chunks = [processed_message[i: i + 512] for i in range(0, len(message), 521)]

    #Process each chunk
    for chunk in chunks:

        smaller_chunks = [int(chunk[i:i+32],2) for i in range(0, len(chunk), 32)]

        assert len(smaller_chunks) == 16

        while len(smaller_chunks) < 80:
            new_chunk = smaller_chunks[-3] ^ smaller_chunks[-8] ^ smaller_chunks[-14] ^ smaller_chunks[-16]

            new_chunk = left_rotate(new_chunk, 1, 32)
            
            smaller_chunks.append(new_chunk)

        a,b,c,d,e = h[0],h[1],h[2],h[3],h[4]

        for index in range(0, 80):
            if 0<= index < 20:
                f = (b & c) ^ ((~b) & d)
                k = 0x5A827999

            if 20<= index <40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1

            if 40 <= index < 60:
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC

            if 60 <= index < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5, 32) + f + e + k + smaller_chunks[index]) % 2**32
            e = d
            d = c
            c = left_rotate(b, 30, 32)
            b = a
            a = temp

        h[0] = (h[0] + a) % 2**32
        h[1] = (h[1] + b) % 2**32
        h[2] = (h[2] + c) % 2**32
        h[3] = (h[3] + d) % 2**32
        h[4] = (h[4] + e) % 2**32

    #Return the hash in big-endian bytes
    h = [x.to_bytes(4,'big') for x in h]

    return b''.join(h)
    
def sha1_key_msg_MAC(key, message):
    return SHA1(key + message)
    
def main():
    assert SHA1(b'abc') == hashlib.sha1(b'abc').digest()

if __name__ == '__main__':
    main()