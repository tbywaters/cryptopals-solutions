import time
from cryptopalsmod.random.mersenne_twister import MT19937
from cryptopalsmod.ciphers.mt_cipher import MTCipher


def test_recent_timestamps(output, output_number = 1, max_seconds_to_check = 5000, start_time = None):
    """Tests if the seed for a mersenne twister (32 bit) was a recent time stamp
    given an output. Raises an exception if seed is not found

    Args:
        output (int): output from the original
        output_nmber (int) = 1: the index of the output, ie if given the second
        random number from the mersenne twister, set output_number=2
        max_seconds_to_check (int) = 5000: how far back in time to check
        start_time (int) = None: Optionally set the time to start the search, if
        not set, function uses the current time. 

    returns:
        int: the seed of the generator
    """

    if start_time == None:
        start_time = int(time.time())

    for seconds_back in range(0, max_seconds_to_check):
        test_seed = start_time - seconds_back
        mt = MT19937(test_seed)

        outputs = []
        while len(outputs) < output_number:
            outputs.append(mt.extract_number())
        
        if outputs[-1] == output:
            return test_seed
        
    raise Exception('seed not found')

def lowest_bits(number, number_of_bits):
    """Returns the num_of_bits lowest bits of an integer number"""
    ones = (1 << number_of_bits) - 1
    return number & ones


def invert_xor_and_rightshift(value, shiftamount):
    """ Inverts the operation value ^ (value >> shiftamount)

    Args:
        value (int)
        shiftamount (int)

    returns: 
        int

    """
    bitlength = value.bit_length()
    
    answer = value

    blocks = 0

    while blocks*shiftamount < bitlength:

        temp = segment_bits(answer, blocks*shiftamount, (blocks + 1)*shiftamount)
        temp = temp >> shiftamount      
        answer = answer ^ temp
      
        blocks += 1

    return answer

def segment_bits(number, a, b):
    
    bitlength = number.bit_length()
    if b <= bitlength:
        number = (number >> (bitlength - b)) << (bitlength - b)
    if a <= bitlength:
        number = lowest_bits(number, bitlength - a)
    return number
    
def xor_and_rightshift(number, shiftamount):
    return number ^ (number >> shiftamount)

def xor_and_leftshift(number, shiftamount, and_number):
    return number ^ ((number << shiftamount) & and_number)

def invert_xor_and_leftshift(value, shiftamount, and_number):
    """Inverts value = x ^ ((x << shiftamount) & and_number) assumeing the last
    shiftamount bits of and_number are 0"""
    
    blocks = 0
    bitlength = value.bit_length()
    
    while value >> (blocks)*shiftamount != 0:

        chunk = segment_bits(value, value.bit_length() - (blocks + 1)*shiftamount, value.bit_length() - blocks*shiftamount)
        chunk = chunk << shiftamount
       

        and_segment = segment_bits(and_number, 
                            and_number.bit_length() - (blocks+2)*shiftamount, 
                            and_number.bit_length() - (blocks+1)*shiftamount)
       
        temp = chunk & and_segment
       
        value = value ^ temp

        
        blocks += 1

    return value

def untemper(number):
    """Takes a number recieved from a mersenne twister 32 bit with usual constants
    and reverse the tempering process to produce the value in the state"""
    U = 11
    S, B = 7, 0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18

    number = invert_xor_and_rightshift(number, L)
    number = invert_xor_and_leftshift(number, T, C)
    number = invert_xor_and_leftshift(number, S, B)
    # For 32 bit, the value D = 0xFFFFFFFF (pseudocode wikipedia) has no effect
    # on the end result since number & D = number
    number = invert_xor_and_rightshift(number, U)

    return number

def clone_mersenne_twister(tempered_state):
    """Takes the first 624 outputs of a mersenne twister (32 bit) and returns a
    mersenne_twister.MT19937 object which is a clone of the original twister
    after outputing the 624 numbers

    Args:
        tempered_state (list<int>): the first 624 outputs of a mersenne twister
    return:
        mersenne_twister.MT19937
    """
    state = [untemper(random_num) for random_num in tempered_state]

    new_twister = MT19937(1)
    new_twister.MT = state

    return new_twister

def brute_attack(ciphertext, known_plaintext, key_values = None):
    """Brute force attack MTCipher. Requires a known chunk plaintext. The more
    the better. Returns the seed.

    Note: There is more than one way to build a keystream cipher using MT. This
    function uses mt_cipher.

    Args:
        ciphertext (bytes): ciphertext encrypted by cipher
        known_plaintext (bytes): know plaintext
        key_values (list<int>) = None. List of key values to check. If None, is
        set to range(1, 2**32)
    
    Returns:
        int: seed used to generate the cipher
    
    raises: Exception('Seed not found') if no matching seed is found
    """
    
    if key_values == None:
        key_values = range(1, 2**32)

    for seed in key_values:
        mt_cipher = MTCipher(seed)
        
        test_plaintext = mt_cipher.decrypt(ciphertext)

        if known_plaintext in test_plaintext:
            return seed
        
    raise Exception('Seed not found')
