"""Server implementation of a simplified and flawed SRP as well as a malicious
server which pretends to run simplified srp but instead stores the HMAC for cracking.
For the simulation to work, user_data needs to match user_data in Challenge38.py"""

from flask import Flask
from flask_restful import Resource, Api, reqparse
import cryptopalsmod.bytestringops as bso
from cryptopalsmod.srp.simplified_srpserver import SimplifiedSRPServer_HTTP
from cryptopalsmod.srp.malicious_srp import MaliciousSRPServer_HTTP

app = Flask(__name__)
api = Api(app)

user_data = (b'foo@bar.com', b'abdominohysterectomy')

parser = reqparse.RequestParser()
parser.add_argument('email')
parser.add_argument('dhA', type = int)
parser.add_argument('HMAC')

backend = SimplifiedSRPServer_HTTP(user_data)

class SimplifiedSRP_server(Resource):
    """A server which handles the connection for SRP verification. Bytes are
    assumed to be sent as hex string, and integers as ints.
    """
    def post(self):
        args = parser.parse_args()
        #determine which part of the algorithm to be completed from the arguments
        # in the request 
        if args['email']:
            if args['dhA'] == None:
                backend.reset_keys()
                return 'Not all necessary arguements in request', 400
            
            backend.recv_dh_public_key(args['email'], args['dhA'])
            salt, key, u = backend.send_dh_public_key()
            return {'salt':salt, 'key':key, 'u':u}
            
        elif args['HMAC']:
            if backend.client_public_key == 0:
                backend.reset_keys()
                return 'Cannot verify HMAC without exchanging public keys', 400
            return backend.verify_hmac(args['HMAC'])

        
        #If either of the above, return error
        backend.reset_keys()
        return 'Necessary arguements not given', 400

    def get(self):
        prime, base = backend.send_public_params()
        return {'prime':prime, 'base':base}

malicious_backend = MaliciousSRPServer_HTTP()
class MaliciousSimplifiedSRPServer(Resource):
    """A server which handles the connection for fake SRP verification. Bytes are
    assumed to be sent as hex string, and integers as ints.
    """
    def post(self):
        args = parser.parse_args()
        #determine which part of the algorithm to be completed from the arguments
        # in the request 
        if args['email']:
            if args['dhA'] == None:
                print('res')
                malicious_backend.reset_keys()
                return 'Not all necessary arguements in request', 400
            
            malicious_backend.recv_dh_public_key(args['email'], args['dhA'])
            salt, key, u = malicious_backend.send_dh_public_key()
            return {'salt':salt, 'key':key, 'u':u}
            
        elif args['HMAC']:
            if malicious_backend.client_public_key == 0:
                print('res')
                malicious_backend.reset_keys()
                return 'Cannot verify HMAC without exchanging public keys', 400
            return malicious_backend.verify_hmac(args['HMAC'])

        
        #If either of the above, return error
        print('res')
        malicious_backend.reset_keys()
        return 'Necessary arguements not given', 400

    def get(self):
        prime, base = malicious_backend.send_public_params()
        return {'prime':prime, 'base':base}


        
api.add_resource(SimplifiedSRP_server, '/')
api.add_resource(MaliciousSimplifiedSRPServer, '/badserver')

if __name__ == '__main__':
    app.run(debug=True)