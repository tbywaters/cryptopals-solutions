from cryptopalsmod.random.mersenne_twister import MT19937
import cryptopalsmod.bytestringops as bso
import random


def main():
    mt = MT19937(1000)
    print(mt.extract_number())

if __name__ == "__main__":

    main()