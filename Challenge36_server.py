"""Server implementation of SRP."""

from flask import Flask
from flask_restful import Resource, Api, reqparse
import cryptopalsmod.bytestringops as bso
from cryptopalsmod.srp.srpserver import SRPServer_HTTP

app = Flask(__name__)
api = Api(app)

user_data = (b'foo@bar.com', b'passwordabc')

parser = reqparse.RequestParser()
parser.add_argument('email')
parser.add_argument('dhA', type = int)
parser.add_argument('HMAC')

backend = SRPServer_HTTP(user_data)

class SRP_server(Resource):
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
            salt, key = backend.send_dh_public_key()
            return {'salt':salt, 'key':key}
            
        elif args['HMAC']:
            if backend.client_public_key == 0:
                backend.reset_keys()
                return 'Cannot verify HMAC without exchanging public keys', 400
            return backend.verify_hmac(args['HMAC'])

        
        #If either of the above, return error
        backend.reset_keys()

        return 'Necessary arguements not given', 400

    def get(self):
        prime, base, k = backend.send_public_params()
        return {'prime':prime, 'base':base, 'k':k}
        
api.add_resource(SRP_server, '/')

if __name__ == '__main__':
    app.run(debug=True)