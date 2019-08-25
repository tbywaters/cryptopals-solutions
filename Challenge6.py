import cryptopalsmod.bytestringops as bso 
import cryptopalsmod.xorattacks as xorattacks
import base64
import S1C6

def loadChallengeFile(): 
    with open('6.txt') as file:
        b64 = file.read()
    
    return base64.b64decode(b64)

def main():
    
    assert bso.HammingDistance(b'this is a test', b'wokka wokka!!!') == 37

    ciphertext = loadChallengeFile()

    possible_decryptions = xorattacks.repeatedXOR_attack(ciphertext)
    key_plaintext = next(possible_decryptions)
    
    assert key_plaintext['key'] == b'Terminator X: Bring the noise'
    return


if __name__ == "__main__":
    main()