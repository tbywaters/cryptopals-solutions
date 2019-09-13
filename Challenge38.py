"""Challenge 38 of cryptopals is an implementation of a simplified SRP which
is susceptable to a dictionary attack. To run, first run Challenge38_server.py
"""

from cryptopalsmod.srp import simplified_srpclient, simplified_srpserver
import requests
from cryptopalsmod.number_theory import NIST_PRIME, modexp
from cryptopalsmod import bytestringops as bso
from hashlib import sha256
import json
from cryptopalsmod.hmac import hmac

def main():

    #To work, user data needs to match user data in Challenge38_server.py
    user_data = (b'foo@bar.com', b'password')

    #Test that the simplified SRP works as expected when used legitimately
    legitimate_server_response = test_server(user_data, 'http://127.0.0.1:5000/')
    assert legitimate_server_response.status_code == 200

    #Now connect with a fake server which has no knowledge of the password. Always
    #returns a response with code 200 if the client gives the correct data
    fake_server_response = test_server(user_data, 'http://127.0.0.1:5000/badserver')
    assert fake_server_response.status_code == 200

    #Now that the client has used the fake server, we can perform a dictionary
    #attack.
    decrypted_password = dictattack()

    assert decrypted_password == user_data[1]

def dictattack():

    #Load the parameters needed to calculate the hmac for each trial password
    with open('Challenge38_hash_storage.txt', 'r') as file:
        params = json.load(file)

    #hmac is stored as a hex sting
    params['HMAC'] = bso.hex_to_bytes(params['HMAC'])

    #The dictionary attack usea a function that takes the test pasword 
    #as an argument and returns True/False depending on if it matchs. 
    verify = lambda test_password: test_hmac(test_password,
                                                params['salt'],
                                                params['u'],
                                                params['client_public_key'],
                                                params['secret_key'],
                                                params['base'], 
                                                params['HMAC'])

    #Open the file with english words and test if ech is the password
    with open('words_alpha.txt', 'br') as word_list:
        for test_password in word_list:
            test_password = test_password[:-2]
            if verify(test_password):
                return test_password
    
    raise Exception('Password not in dictionary')
        
        

def test_hmac(password, salt, u, client_public_key, secret_key, base, real_hmac, prime = NIST_PRIME):
        """
        Takes in all variables used by the server in simple SRP and calculates 
        the hmac. Tests if the calculated hmac matches the true hmac.
        Args: 
            password (bytes): user password
            salt (int): salt used in SRP. Should be random
            u (int): u used in SRP. Should be random
            client_public_key (int): clients public key
            secret_key (int): servers secret key
            base (int): base used in diffie hellman
        returns:
            bool: True if simple srp claculation matches hmac given, false otherwise
        """
        salt = bso.int_to_bytes(salt)
        x = int(sha256(salt + password).hexdigest(), 16)
        v = modexp(base, x, prime)

        S = modexp(client_public_key * modexp(v, u, prime), secret_key, prime)
        
        hmac_key = sha256(bso.int_to_bytes(S)).digest()
        
        calc_hmac = hmac(hmac_key, salt, lambda val:sha256(val).digest(), 64, 32)
        
        if real_hmac == calc_hmac:
            return True
        return False


def test_server(user_data, address):
    """Simulates an exhange between an SRP client and server where client is at
    the web arddress address. Assumes the server is like the one in 
    Challenge38_server.py

    Ars:
        user_data (bytes, bytes): tuple of users email and users password in 
            bytes
        address (string): web address to simulate server.

    returns:
        requests with status code 200 if the verification was succesful, 400 
            otherwise
    """ 
    client = simplified_srpclient.SimplifiedSRPClient_HTTP(user_data)

    # Server sends base, prime and k

    data = requests.get(address).json()
    client.recv_public_params(data['prime'], data['base'])

    # Client and server exchange public keys

    email, client_public_key = client.send_dh_public_key()

    server_response = requests.post(address, data={'email':email, 'dhA':client_public_key}).json()
    client.recv_dh_public_key(server_response['salt'], server_response['key'], server_response['u'])

    # Hmac is calculated by the client and sent to the server
    hmac = client.calculate_hmac()
    return requests.post(address, data={'HMAC':hmac})

if __name__ == "__main__":
    main()