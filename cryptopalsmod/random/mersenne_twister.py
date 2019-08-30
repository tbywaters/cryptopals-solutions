
#TODO: Possibly belongs somewhere else
def lowest_bits(number, number_of_bits):
    ones = (1 << number_of_bits) - 1
    return number & ones

class MT19937:
    """"32 bit merrsenne twister 19937, based on pseudocode and variable values 
    found on wikipedia"""
    #A lot of constants

    _W, _N, _M, _R = 32, 624, 397, 31
    _A = 0x9908B0DF
    _U, _D = 11, 0xFFFFFFFF
    _S, _B = 7, 0x9D2C5680
    _T, _C = 15, 0xEFC60000
    _L = 18
    _LOWER_MASK = (1 << _R) - 1
    _UPPER_MASK = lowest_bits(~_LOWER_MASK, _W)

    def __init__(self, seed):
        """seed ia a 32 bit integer"""

        f = 1812433253

        self.MT = [seed]
        for i in range(1, self._N):
            self.MT.append(lowest_bits(f * (self.MT[i-1] ^ (self.MT[i-1] >> (self._W - 2))) + i, self._W))
        
        self.index = self._N
    
    def extract_number(self):

        if self.index >= self._N:
            self._twist()
        
        y = self.MT[self.index]
        y = y ^ ((y >> self._U) & self._D)
        y = y ^ ((y << self._S) & self._B)
        y = y ^ ((y << self._T) & self._C)
        y = y ^ (y >> self._L)
        
        self.index += 1

        return lowest_bits(y, self._W)

    def _twist(self):
        for i in range(0, self._N):
            x = (self.MT[i] & self._UPPER_MASK) + (self.MT[(i + 1) % self._N] & self._LOWER_MASK)
            
            xA = x >> 1
            
            if x % 2 != 0:
                xA = xA ^ self._A
            
            self.MT[i] = self.MT[(i + self._M) % self._N] ^ xA
        
        self.index = 0

