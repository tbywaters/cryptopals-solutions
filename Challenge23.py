from cryptopalsmod.random.mersenne_twister import MT19937
from cryptopalsmod import mersenne_twister_attacks as mt_attacks
import time

def main():
    
    random_twister = MT19937(int(time.time()))


    outputs = []
    while len(outputs) < 624:
        outputs.append(random_twister.extract_number())

    clone_twister = mt_attacks.clone_mersenne_twister(outputs)

    for count in range(0, 10000):
        assert random_twister.extract_number() == clone_twister.extract_number()

    return

if __name__ == "__main__":
    main()