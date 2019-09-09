from cryptopalsmod.srp import srpclient
import requests


def main():
    user_data = (b'foo@bar.com', b'passwordabc')

    client = srpclient.SRPClient_HTTP(user_data)

    # Server sends base, prime and k

    data = requests.get('http://127.0.0.1:5000/').json()
    client.recv_public_params(data['prime'], data['base'], data['k'])

    # Client and server exchange public keys

    email, client_public_key = client.send_dh_public_key()
    server_response = requests.post('http://127.0.0.1:5000/', data={'email':email, 'dhA':client_public_key}).json()

    client.recv_dh_public_key(server_response['salt'], server_response['key'])

    # Hmac is calculated by the client and sent to the server
    hmac = client.calculate_hmac()
    assert requests.post('http://127.0.0.1:5000/', data={'HMAC':hmac}).status_code == 200
    

if __name__ == '__main__':
    main()