from cryptopalsmod.random.mersenne_twister import MT19937
from cryptopalsmod import mersenne_twister_attacks as mt_attacks
import time
import random

def challenge_setup():
    wait = random.randint(40, 1000)

    time.sleep(wait)
    
    timestamp = int(time.time())
    mt = MT19937(timestamp)
    rand = mt.extract_number()

    wait = random.randint(40, 1000)
    return timestamp, rand

def main():
    timestamp, rand = challenge_setup()
    
    test_time = mt_attacks.test_recent_timestamps(rand)

    assert timestamp == test_time


if __name__ == "__main__":
    main()