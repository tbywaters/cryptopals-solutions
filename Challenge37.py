import requests
from hashlib import sha256
from cryptopalsmod.hmac import hmac
import cryptopalsmod.bytestringops as bso

def main():
    
    
    # Server sends base, prime and k

    data = requests.get('http://127.0.0.1:5000/').json()
    prime, base, k =  data['prime'], data['base'], data['k']

    # Client and server exchange public keys, but the server sends 0 as its public
    #key. 

    email = b'foo@bar.com'.decode()

    #Test a few bad public keys which are all 0 mod prime. These allow us to 
    #login without knowing the password
    for bad_public_key in [0, prime, prime**2, 4*prime]:

        server_response = requests.post('http://127.0.0.1:5000/', data={'email':email, 'dhA':bad_public_key}).json()

        #We only need the salt, not the secret key. Convert to bytes to calculate
        #our bogus hmac
        salt = bso.int_to_bytes(server_response['salt'])

        # Hmac is calculated by the client and sent to the server. 
        K = sha256(bso.int_to_bytes(0)).digest()
        bogus_hmac = bso.bytes_to_hex(hmac(K, salt, lambda val: sha256(val).digest(), 64, 32))

        print(requests.post('http://127.0.0.1:5000/', data={'HMAC':bogus_hmac}).text)
    

if __name__ == '__main__':
    main()