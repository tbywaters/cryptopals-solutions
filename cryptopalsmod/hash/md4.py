from cryptopalsmod.hash import sha1
import struct

class MD4(object):
    """Implementation of md4. Allows for the user
    to also do message extensions by allowing custom initial values and custom
    padding.
    
    Args (__init__):
        message (bytes): message/date to be hashed
        initial_values (list <int>) = None: Values used for the internal state of the 
        algorithm. If set to None, default values are used. 
        message_length (int) = -1, If set to a positive integer, allows the user
        of the function to control the padding.
        custom_padding (str): string in binary. padding to use. Must be valid or 
        assertion error will be raised.
    
    use self.digest() to returns bytes of hash

    """
    # Auxillary function used in processing
    @staticmethod
    def auxF(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def auxG(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def auxH(x, y, z):
        return x ^ y ^ z

    def __init__(self, message, initial_state = None, message_length = None):
        if initial_state == None:
            self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        else:
            self.h = initial_state
            assert len(initial_state) == 4
        
        if message_length == None:
            message_length = len(message)

        #pads the message according to speifications. Brak into 64 bit chunks
        #for individual processing
        message += self.padding(message_length)
        chunks = [message[i:i + 64] for i in range(0, len(message), 64)]
        
        for chunk in chunks:
            self.process(chunk)


    @staticmethod
    def padding(message_length):
        padding = b'\x80'

        #Calculate the number of 0 bits required and add to message
        num_zeros = (56 - ((message_length + 1) % 64)) % 64

        padding += bytes(num_zeros)

        #add the length of the original message as a 64 bits little endian 
        padding += struct.pack('<Q', message_length*8)
    
        assert (message_length + len(padding)) % 64 == 0

        return padding

    def process(self, chunk):
        smaller_chunks = list(struct.unpack('<' + 'I' * 16, chunk))

        A, B, C, D = self.h[0], self.h[1], self.h[2], self.h[3]

        #Round 1
        for i in range(0, 16):
            k = i
            if i % 4 == 0:
                A = sha1.left_rotate((A + self.auxF(B,C,D) + smaller_chunks[k]) % 2**32, 3, 32)
            elif i % 4 == 1:
                D = sha1.left_rotate((D + self.auxF(A,B,C) + smaller_chunks[k]) % 2**32, 7, 32)
            elif i % 4 == 2:
                C = sha1.left_rotate((C + self.auxF(D,A,B) + smaller_chunks[k]) % 2**32, 11, 32)
            elif i % 4 == 3:
                B = sha1.left_rotate((B + self.auxF(C,D,A) + smaller_chunks[k]) % 2**32, 19, 32)

        #round 2
        k_values = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i in range(0, 16):
            k = k_values[i]
            if i % 4 == 0:
                A = sha1.left_rotate((A + self.auxG(B,C,D) + smaller_chunks[k] + 0x5A827999) % 2**32, 3, 32)
            elif i % 4 == 1:
                D = sha1.left_rotate((D + self.auxG(A,B,C) + smaller_chunks[k]+ 0x5A827999) % 2**32, 5, 32)
            elif i % 4 == 2:
                C = sha1.left_rotate((C + self.auxG(D,A,B) + smaller_chunks[k] + 0x5A827999) % 2**32, 9, 32)
            elif i % 4 == 3:
                B = sha1.left_rotate((B + self.auxG(C,D,A) + smaller_chunks[k] + 0x5A827999) % 2**32, 13, 32)

        #round 3
        k_values = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(0, 16):
            k = k_values[i]
            if i % 4 == 0:
                A = sha1.left_rotate((A + self.auxH(B,C,D) + smaller_chunks[k] + 0x6ED9EBA1) % 2**32, 3, 32)
            elif i % 4 == 1:
                D = sha1.left_rotate((D + self.auxH(A,B,C) + smaller_chunks[k] + 0X6ED9EBA1) % 2**32, 9, 32)
            elif i % 4 == 2:
                C = sha1.left_rotate((C + self.auxH(D,A,B) + smaller_chunks[k] + 0X6ED9EBA1) % 2**32, 11, 32)
            elif i % 4 == 3:
                B = sha1.left_rotate((B + self.auxH(C,D,A) + smaller_chunks[k] + 0X6ED9EBA1) % 2**32, 15, 32)

        self.h[0] = (self.h[0] + A)%2**32
        self.h[1] = (self.h[1] + B)%2**32
        self.h[2] = (self.h[2] + C)%2**32
        self.h[3] = (self.h[3] + D)%2**32
    
    def digest(self):
        return struct.pack('<IIII', self.h[0], self.h[1], self.h[2], self.h[3])
