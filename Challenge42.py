from cryptopalsmod.ciphers import dsa
from hashlib import sha256
import cryptopalsmod.number_theory as nt

def main():
    
    #verify the dsa algorithm works
    verify = dsa.DSAVerify()
    signatory = dsa.DSASignatory()
    verify.recv_public_key(*signatory.send_public_key())

    message = b'hi mum'
    sig = signatory.sign_message(message)
    assert verify.bad_verify_message(message, sig)

    fake_sig = fake_signature(message)
    assert verify.bad_verify_message(message, fake_sig)

def fake_signature(message):

    msg_hash = sha256(message).hexdigest()

    'Add the necessary staring sting and hash to the fake signature'
    fake_signature = '0001ffff' + msg_hash
    
    #Add 0's to account for the error in calculating the integer square root
    while len(fake_signature)/2 < 128:
        fake_signature  = fake_signature + '00'
     
    fake_signature = int(fake_signature, 16)
    return nt.newton_root(3, fake_signature)

if __name__ == '__main__':
    main()