from cryptopalsmod.hash.sha1 import SHA1
import itertools
from cryptopalsmod.dsa_attacks import DSAattacks

def laod_chalenge_data():

    sig_dicts = []
    with open('44.txt') as file:
        message_line = file.readline()
        while len(message_line)>0:

            sig = {}

            sig['msg'] = message_line[5:-1].encode()
            sig['s'] = int(file.readline()[3:-1])
            sig['r'] = int(file.readline()[3:-1])
            sig['m'] = file.readline()[3:-1]

            sig_dicts.append(sig)

            message_line = file.readline()

    return sig_dicts

def main():
    sig_dicts = laod_chalenge_data()

    #create an iterator of signature pairs 
    sig_pairs = itertools.combinations(sig_dicts, 2)

    attacker = DSAattacks(SHA1)
    for pair in sig_pairs:
        secret_key = attacker.key_from_double_signing(*pair)
        if secret_key > 0:
            break

    assert SHA1(hex(secret_key)[2:].encode()).hexdigest() == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
    

if __name__ == "__main__":
    main()
    