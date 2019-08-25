import cryptopalsmod.bytestringops as bso 

def main():
    
    test = b'YELLOW SUBMARINE'

    assert bso.pad_pkcs7(test, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'

if __name__ == "__main__":
    main()