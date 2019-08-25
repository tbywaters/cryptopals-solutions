import cryptopalsmod.bytestringops as bso 


def main():
    """ Input and outputs in hex as given by the challenge"""
    hex_in_1 = '1c0111001f010100061a024b53535009181c'
    hex_in_2 = '686974207468652062756c6c277320657965'
    hex_out = '746865206b696420646f6e277420706c6179'
    
    """Convert hex to bytes for XOR"""
    bytes_in_1 = bso.hex_to_bytes(hex_in_1)
    bytes_in_2 = bso.hex_to_bytes(hex_in_2)

    XOR = bso.FixedXOR(bytes_in_1, bytes_in_2)

    """Don't miss out on the 90's rap reference"""
    print(XOR)

    """Check results"""
    assert bso.bytes_to_hex(XOR) == hex_out

if __name__ == "__main__":
    main()
