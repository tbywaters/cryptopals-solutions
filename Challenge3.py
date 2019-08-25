import cryptopalsmod.xorattacks as xorattacks
import cryptopalsmod.bytestringops as bso

def main():
    #input hex from challenge
    hex_in = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    ciphertext = bso.hex_to_bytes(hex_in)

    result = next(xorattacks.xor_singlebyte_key_attack(ciphertext))

    assert result['decryption'] == b"Cooking MC's like a pound of bacon"
    
if __name__ == "__main__":
    main()