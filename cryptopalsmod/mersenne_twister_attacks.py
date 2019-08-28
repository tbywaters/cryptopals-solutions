import time
from cryptopalsmod.random.mersenne_twister import MT19937

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
