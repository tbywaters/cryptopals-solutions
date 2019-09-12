from cryptopalsmod.number_theory import NIST_PRIME, modexp
import secrets
from cryptopalsmod.hmac import hmac
from hashlib import sha256
import cryptopalsmod.bytestringops as bso

class SimplifiedSRPServer():
    """Implementation of SRP verification"""

    def __init__(self, user_data, prime = NIST_PRIME, base = 2):
        """Initialises with required information

        Args:
            prime (int): prime used for dh
            base (int): base used for dh
            k (int): used to disuise password hash in public key
            userdata (tuple(bytes, bytes)): tuple of (user email, user password)
        """
        self.prime = prime
        self.base = base

        #The following simulates adding a new user to a user database. Plaintext
        #password is not stored.

        self.salt = secrets.randbelow(2**32)
        self.user_email = user_data[0]
        self.v = self._password_computation(user_data[1])

        #in implementation, user_email, v and salt could be stored in a data 
        # base and retrieved when the user sends their email

        self.reset_keys()
        
    def reset_keys(self):
        """Reset sectret and public keys to a random/0 value."""

        self.secret_key = secrets.randbelow(self.prime)

        #Values to be entered later are initialised/reset as 0
        self.client_public_key = 0
        self.public_key = 0
        self.u = 0

    def send_public_params(self):
        """Sends the public parameters to the client

        returns:
            int: prime used in SRP
            int: base used in SRP
        """
        return self.prime, self.base

    def _password_computation(self, user_password):
        """Computes a hash of the users password for storing and later computations

        Args: 
            user_password (bytes): users password

        Returns:
            hashed version of the password which is used in SRP
        """

        #Salt needs to be converted to bytes for use in the hash
        salt_bytes = bso.int_to_bytes(self.salt)
        
        #password is padded with salt (a random int) and hased to be used as
        #an exponent. This same calculation is also done by the client.

        password_exponent = sha256(salt_bytes + user_password).hexdigest()
        password_exponent = int(password_exponent, 16)

        return modexp(self.base, password_exponent, self.prime)
       
    def send_dh_public_key(self):
        """Calculates and returns the SRP public key
        
        Returns:
            salt (int): random integer below the agreed upon prime
            public_key (int): public key generated by the server for SRP
            int: used in SRP calculation
        """

        #key calculaton
        self.public_key = modexp(self.base, self.secret_key, self.prime)
        self.u = int.from_bytes(secrets.token_bytes(8), 'big')

        return self.salt, self.public_key, self.u

    def recv_dh_public_key(self, submitted_email, client_public_key):
        """Stores the public key sent by the clients. Also verifies that the email
        is a match.
        Args:
            submitted_email(bytes): email address of user
            client_public_key (int): public key given by client for SRP
        """

        #Check that the emails match. In an actual implementation, this function
        #could retreive the hashed password (see _password_computation()) using
        # the email as the database key

        if submitted_email != self.user_email:
            return 'Emails do not match', 400

        self.client_public_key = client_public_key
        return

    def verify_hmac(self, recv_hmac):
        """
        Final SRP verification. Computes the hmac which depends depends on the
        salt and password but also on a Diffie Hellmen shared key. Equates with
        the hamc submitted by the client
    

        Args:
            recv_hmac (bytes): hmac computed byt he client
        Returns:
            string, int: 'OK', 200 if the verification is successful
                        'Nope', 400 if the verification is unsuccessful
        """
 
        S = modexp(self.client_public_key * modexp(self.v, self.u, self.prime), self.secret_key, self.prime)
        
        hmac_key = sha256(bso.int_to_bytes(S)).digest()
        
        salt_bytes = bso.int_to_bytes(self.salt)
        
        calc_hmac = hmac(hmac_key, salt_bytes, lambda val:sha256(val).digest(), 64, 32)
        
        if recv_hmac == calc_hmac:
            return 'OK', 200
        return 'Nope', 400


class SimplifiedSRPServer_HTTP(SimplifiedSRPServer):
    """Same as SRPserver but arguement and return values are converted to and 
    from bytes for use with a http server. Observe that __init__ remains unchanged
    and so username and password need to be given as bytes objects"""

    def recv_dh_public_key(self, submitted_email, client_public_key):
        """Stores the public key sent by the clients. Also verifies that the email
        is a match.
        Args:
            submitted_email(string): email address of user
            client_public_key (int): public key given by client for SRP
        """

        #Check that the emails match. In an actual implementation, this function
        #could retreive the hashed password (see _password_computation()) using
        # the email as the database key

        if submitted_email != self.user_email.decode():
            return 'Emails do not match', 400

        self.client_public_key = client_public_key
        return

    def verify_hmac(self, recv_hmac):
        """
        Final SRP verification. Computes the hmac which depends depends on the
        salt and password but also on a Diffie Hellmen shared key. Equates with
        the hamc submitted by the client
    

        Args:
            recv_hmac (string): hmac computed by the client as a string in hex
        Returns:
            string, int: 'OK', 200 if the verification is successful
                        'Nope', 400 if the verification is unsuccessful
        """
 
        recv_hmac = bso.hex_to_bytes(recv_hmac)
        return SimplifiedSRPServer.verify_hmac(self, recv_hmac)