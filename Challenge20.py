import base64
import collections
import cryptopalsmod.xorattacks as xorattacks
import cryptopalsmod.bytestringops as bso


def load_challenge_ciphertexts():
    
    ciphertexts = []

    with open('19.txt') as file:
        for line in file:
            ciphertexts.append(base64.b64decode(line))

    return ciphertexts


def main():

    ciphertexts = load_challenge_ciphertexts()
    
    lengths = [len(ciphertext) for ciphertext in ciphertexts]
    lengths = sorted(list(set(lengths)))
    
    previous = 0
    key = b''
    for key_length in lengths:
        shortened_ciphertexts = [ciphertext[previous:key_length] for ciphertext in ciphertexts if len(ciphertext) > previous]
        joined_ciphertexts = b''.join(shortened_ciphertexts)

        key += xorattacks.repeatedXOR_attack_key(joined_ciphertexts, key_length - previous)
        
        previous = key_length
    
    for ciphertext in ciphertexts:
        print(bso.zipXOR(key, ciphertext)) 

if __name__ == "__main__":
    main()