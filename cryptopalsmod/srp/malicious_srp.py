import json
from cryptopalsmod.srp.simplified_srpserver import SimplifiedSRPServer
from cryptopalsmod.number_theory import NIST_PRIME
import secrets
from cryptopalsmod import bytestringops as bso

class MaliciousSRPServer(SimplifiedSRPServer):
    """Serever doesn't actually compute the SRP check, instead returns positive
    and stores values for password cracking"""

    def __init__(self, prime = NIST_PRIME, base = 2):
        """Initialises with required information

        Args:
            prime (int): prime used for dh
            base (int): base used for dh
        """
        self.prime = prime
        self.base = base
        
        self.salt = secrets.randbelow(2**32)

        self.reset_keys()
        
    def reset_keys(self):
        """Reset secret and public keys to a random/0/empty value."""

        self.secret_key = secrets.randbelow(self.prime)

        #Values to be entered later are initialised/reset as 0
        self.client_public_key = 0
        self.public_key = 0
        self.u = 0
        self.user_email = b''

    def recv_dh_public_key(self, submitted_email, client_public_key):
        """Stores the public key sent and email sent by client
        Args:
            submitted_email(bytes): email address of user
            client_public_key (int): public key given by client for SRP
        """
        self.client_public_key = client_public_key
        self.user_email = submitted_email
        return

    def verify_hmac(self, recv_hmac, filename = 'Challenge38_hash_storage.txt'):
        """
        Simulates final SRP verification but instead of doing the verification,
        stores recv_hmac and necessary values for cracking.    

        Args:
            recv_hmac (bytes): hmac computed bytes he client
        Returns:
            string, int: 'OK', 200
                        
        """

        #Create a dict with all of the data for storage
        data = {}
        data['HMAC'] = bso.bytes_to_hex(recv_hmac)
        data['base'] = self.base
        data[ 'u'] = self.u
        data['client_public_key'] = self.client_public_key
        data['salt'] = self.salt
        data['secret_key'] = self.secret_key

        with open(filename, 'w') as file:
            json.dump(data, file)

        return 'OK', 200


class MaliciousSRPServer_HTTP(MaliciousSRPServer):
    """Same as MaliciousSRPserver but arguments and return values are converted
     to and from bytes for use with a http server. Observe that __init__ remains
    unchanged and so username and password need to be given as bytes objects"""

    def recv_dh_public_key(self, submitted_email, client_public_key):
        """Stores the public key sent by the clients. Also verifies that the email
        is a match.
        Args:
            submitted_email(string): email address of user
            client_public_key (int): public key given by client for SRP
        """
        submitted_email = submitted_email.encode()
        MaliciousSRPServer.recv_dh_public_key(self, submitted_email, client_public_key)

        return

    def verify_hmac(self, recv_hmac):
        """
        Recieves and stores hmac. Returns positive verification    

        Args:
            recv_hmac (string): hmac computed by the client as a string in hex
        Returns:
            'OK', 200 
        """
 
        recv_hmac = bso.hex_to_bytes(recv_hmac)
        return MaliciousSRPServer.verify_hmac(self, recv_hmac)
