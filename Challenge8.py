import cryptopalsmod.aes_ecb_attacks as ecb_attacks 

def load_challenge_file():
    
    ciphertextList = []
    
    with open('8.txt') as file:
        for line in file:
            ciphertextList.append(bytes.fromhex(line))
    
    return ciphertextList

def main():
    ciphertextList = load_challenge_file()

    ECB_encrypted = []
    for index, ciphertext in enumerate(ciphertextList):
        if ecb_attacks.detect_ECB(ciphertext):
            ECB_encrypted.append({'pos':index, 'ciphertext':ciphertext})

    assert len(ECB_encrypted) == 1
    assert ECB_encrypted[0]['pos'] == 132

if __name__ == "__main__":
    main()