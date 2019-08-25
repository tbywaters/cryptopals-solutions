import cryptopalsmod.xorattacks as xorattacks
import cryptopalsmod.bytestringops as bso

def main(): 


    #Load in the cipher texts from the file
    ciphertexts = []
    with open('4.txt') as file:
        for line in file:
            ciphertexts.append(bso.hex_to_bytes(line))

    results = []
    for ciphertext in ciphertexts:
        results.append(next(xorattacks.xor_singlebyte_key_attack(ciphertext)))

    results = sorted(results, key=lambda val: val['score'], reverse=True)
    
    assert results[0]['decryption'] == b'Now that the party is jumping\n'
        
    return


if __name__ == "__main__":
    main()