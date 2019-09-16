import hashlib
import struct

def left_rotate(x, n, w):
    return ((x<< n & (2 ** w - 1)) | (x >> w - n))

class SHA1(object):
    """Implementation of SHA1. Allows for the user
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

    def __init__(self, message, initial_state = None, message_length = None):
        
        if initial_state == None:
            self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        else:
            self.h = initial_state
            assert len(initial_state) == 5
        
        if message_length == None:
            message_length = len(message)

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

        #add the length of the original message as a 64 bits 
        padding += struct.pack('>Q', message_length*8)
    
        assert (message_length + len(padding)) % 64 == 0

        return padding

    def process(self, chunk):
        words = list(struct.unpack('>' + 'I'*16, chunk))

        while len(words) < 80:
            new_chunk = words[-3] ^ words[-8] ^ words[-14] ^ words[-16]

            new_chunk = left_rotate(new_chunk, 1, 32)
            
            words.append(new_chunk)

        a, b, c, d, e = self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]

        for index in range(0, 80):
            if 0<= index < 20:
                f = (b & c) ^ ((~b) & d)
                k = 0x5A827999

            if 20<= index < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1

            if 40 <= index < 60:
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC

            if 60 <= index < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (left_rotate(a, 5, 32) + f + e + k + words[index]) % 2**32
            e = d
            d = c
            c = left_rotate(b, 30, 32)
            b = a
            a = temp

        self.h[0] = (self.h[0] + a) % 2**32
        self.h[1] = (self.h[1] + b) % 2**32
        self.h[2] = (self.h[2] + c) % 2**32
        self.h[3] = (self.h[3] + d) % 2**32
        self.h[4] = (self.h[4] + e) % 2**32

    def digest(self):
        return struct.pack('>IIIII', self.h[0], self.h[1], self.h[2], self.h[3], self.h[4])
    def hexdigest(self):
        return self.digest().hex()

def main():
    
    assert SHA1(b'abc').hexdigest() == hashlib.sha1(b'abc').hexdigest()

if __name__ == '__main__':
    main()