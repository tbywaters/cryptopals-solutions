import cryptopalsmod.bytestringops as bso 

def main():
    tests = [b"ICE ICE BABY\x04\x04\x04\x04", b"ICE ICE BABY\x05\x05\x05\x05", b"ICE ICE BABY\x01\x02\x04\x04"]

    for test in tests:
        try:
            depadded = bso.remove_padding_pkcs7(test)
            assert depadded == b'ICE ICE BABY'
        except Exception as e:
            assert test in [b"ICE ICE BABY\x05\x05\x05\x05", b"ICE ICE BABY\x01\x02\x04\x04"]

            
if __name__ == "__main__":
    main()