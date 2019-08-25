import cryptopalsmod.bytestringops as bso

def main():
    hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64_str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert bso.hex_to_64(hex_str) == b64_str

if __name__ == "__main__":
    main()