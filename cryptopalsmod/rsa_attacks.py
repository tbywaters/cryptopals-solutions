from cryptopalsmod import number_theory as nt
import math
from cryptopalsmod import bytestringops as bso

def ceil_division(numerator, denominator):
    return (numerator + denominator - 1)//denominator

def floor_division(numerator, denominator):
    return numerator//denominator

def hastad_attack(e, ciphertexts, public_keys):
    """The simplest version of hastads attack decrypts a message encrypted multiple
    times using different public keys. The number of encrypted ciphertexts required is 
    the value e (exponent public key) used in rsa encryption. The algorithm relies
    on the chinese remainder theorem.
    
    Args:
        e (int): the exponent used for rsa encryption, eg e = 3
        ciphertexts (list<int>): a list of length e of encryptions of the original message
        public_keys (list<int>): a list of length e of public keys used to encrypt the message
            to get the ciphertexts

    returns:
        int : the original message.
    raises:
        Exception('invalid arguements') if len(ciphertexts) != e or len(public_keys)!= e
    """
    if e != len(ciphertexts) or e != len(public_keys):
        raise Exception('invalid arguements')

    message_e_power = nt.chinese_remainder_theorem(ciphertexts, public_keys)

    return nt.newton_root(e, message_e_power)

def parity_oracle_attack(ciphertext, e, modulus, parity_oracle):
    """Cracks an rsa ciphertext using a parity oracle

    Args:
        cipehertext (int): encrypted plaintext for decryption
        e (int): public exponent used in rsa
        moduls (int): Modulus used by rsa encryption
        parity_oracle (function): fucntion which decrypts the ciphertext and
            returns true if the ciphertext is even, false otherwise
    returns:
        int: decrypted ciphertext
    """
    lower_bound = 0
    upper_bound = modulus

    while lower_bound != upper_bound:
        
        ciphertext = (nt.modexp(2, e, modulus)*ciphertext)        
        difference = upper_bound - lower_bound

        if difference % 2 == 1:
            difference += 1

        if parity_oracle(ciphertext):
            upper_bound = upper_bound - difference//2
        
        else:
            lower_bound = lower_bound + difference//2
        
        #Uncomment for hollywood style hacking
        #print(upper_bound)

    return upper_bound

class Bleichenbacher():

    def __init__(self, ciphertext, e, modulus, padding_oracle):
        """
        Cracks an rsa ciphertext using a padding oracle. Correct padding is when
        decrypted message is unpacked into byte lenght of modulus bytes, the first
        byte is 0 and second is 2. See Bleichenbacher's 98 paper for details on
        the attack.
        
        Args:
            cipehertext (int): encrypted plaintext for decryption. Assumes the
                original plaintext was correctly padded.
            e (int): public exponent used in rsa
            moduls (int): Modulus used by rsa encryption
            padding_oracle (function): fucntion which decrypts the ciphertext and
                returns true if the padding is correct, false otherwise
        
        returns:
            int: decrypted ciphertext
        """
        
        self.c = ciphertext
        self.e = e
        self.mod = modulus
        self.oracle = padding_oracle
        self.B = 2**(8*(bso.byte_len(modulus) - 2))
        self.M = [(2*self.B, 3*self.B - 1)]
        self.i = 1
        self.s = ceil_division(self.mod, 3*self.B) - 1
        assert self.oracle(ciphertext)


    def run(self):

        result = 0
        while result == 0:

            if self.i == 1 or len(self.M) > 1:
                self.step2b()

            else:
                self.step2c()

            self.step3()
            result = self.step4()
            
        return result
    
    def step2b(self):
     
        s_start = self.s + 1
        
        while not self.oracle((self.c * nt.modexp(s_start, self.e, self.mod)) % self.mod):
            s_start += 1
        
        self.s = s_start
        
    def step2c(self):

        a, b = self.M[0]
        
        r = ceil_division(2 * (b * self.s - 2 * self.B), self.mod)
        
        for _ in range(0, 1000):
            #We expect to find a value every 3 iterations of r. 1000 should be 
            #overkill
            
            test_s = ceil_division(2 * self.B + r * self.mod, b)
            upper_bound = ceil_division(3 * self.B + r * self.mod, a)


            while test_s < upper_bound:
        
                if self.oracle((self.c * nt.modexp(test_s, self.e, self.mod)) % self.mod):
        
                    self.s = test_s
                    return

                test_s += 1
                
            r += 1
        raise Exception('Error, r,s pair not found in step 2c')

    def step3(self):

        new_ranges = []

        for a, b in self.M:

            r = ceil_division(a * self.s - 3 * self.B + 1, self.mod)
            upperbound = floor_division(b * self.s - 2 * self.B, self.mod)

            while r <= upperbound:
                
                temp = ceil_division(2 * self.B + r * self.mod, self.s)
                new_range_lower = max(a, temp)
                
                temp = floor_division(3 * self.B + r * self.mod - 1, self.s)
                new_range_upper = min(b, temp)

                if new_range_upper >= new_range_lower:
                    new_ranges.append((new_range_lower, new_range_upper))
                else:
                    raise Exception('Error, lowerbound greater than upper')
                
                r += 1

        assert len(new_ranges) >= 1
        self.M = new_ranges
        
    def step4(self):

        if len(self.M) == 1:

            if self.M[0][0] == self.M[0][1]:

                return (self.M[0][0] * nt.invmod(1, self.mod)) % self.mod

        self.i += 1
        return 0