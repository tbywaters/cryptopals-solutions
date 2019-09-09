
from cryptopalsmod.number_theory import NIST_PRIME, modexp
import secrets
from cryptopalsmod.hmac import hmac
from hashlib import sha256
import cryptopalsmod.bytestringops as bso


class SRPClient():
    """Implementation of a client validitating their password using SRP"""

    def __init__(self, user_data):
        """Initialises with required information

        Args:
            prime (int): prime used for dh
            base (int): base used for dh
            k (int): used to disuise password hash in public key
            userdata (tuple(bytes, bytes)): tuple of (user email, user password)
        """

        self.user_email = user_data[0]
        self.user_password = user_data[1]

        #Values (ints) to be entered later are initialised as 0
        self.server_public_key = 0
        self.public_key = 0
        self.prime = 0
        self.base = 0
        self.k = 0
        self.salt = 0
        self.secret_key = 0
    
    def recv_public_params(self, prime, base, k):
        """Saves Diffie Hellman paramaters which are usually sent by the client.
        Then randomly chooese a secret key.

        Args:
            prime (int): prime used in SRP
            base (int): base used in SRP
            k (int): k-value used in SRP
        """

        self.prime = prime
        self.base = base
        self.k = k

        #With prime now decided upon, we can compute the secret key
        self._set_secret_key()

    def _set_secret_key(self):
        """Sets the secret key after checking that prime is nonzero. Throws
        an exception if prime has not been set"""

        if self.prime <= 0:
            raise Exception('Prime has either not been set or is invalid (<=0)')

        self.secret_key = secrets.randbelow(self.prime)
        return


    def send_dh_public_key(self):
        """Calculates and returns the SRP public key and user email
        
        Returns:
            bytes, int: a tuple of user email (bytes) and the clients secret key (int)
        """
        self.public_key = modexp(self.base, self.secret_key, self.prime)
        return self.user_email, self.public_key

    def recv_dh_public_key(self, salt, server_public_key):
        """Taks as an input the salt and public key from the server

        Args:
            salt (int): random salt decided on by the server
            server_public_key (int): SRP public key calculated byt the server
        """
        #saves arguments
        self.server_public_key = server_public_key
        self.salt = salt
        
        return

    def calculate_hmac(self):
        """Calculates the hmac and returns it. If the password is correct, it
        it should match the hmac calculated byt the server.
        
        returns:
            bytes: hmac depending on password, salt and server and client keys
        
        """
        u = sha256(bso.int_to_bytes(self.public_key) + bso.int_to_bytes(self.server_public_key)).hexdigest()
        u = int(u, 16)

        #conver salt to bytes for hashing
        salt_bytes = bso.int_to_bytes(self.salt)
        
        password_exp = sha256(salt_bytes + self.user_password).hexdigest()
        password_exp = int(password_exp, 16)
        
        
        #Calculating the key for hmac
        S_base = (self.server_public_key - self.k * modexp(self.base, password_exp, self.prime)) % self.prime
        S_exponent = (self.secret_key + u * password_exp) % self.prime
        S = modexp(S_base, S_exponent, self.prime)
        
        hmac_key = sha256(bso.int_to_bytes(S)).digest()

        calc_hmac = hmac(hmac_key, salt_bytes, lambda val:sha256(val).digest(), 64, 32)
        
        return calc_hmac

class SRPClient_HTTP(SRPClient):
    """Same as SRPserver but arguement and return values are converted to and 
    from bytes for use with a http server. Observe that __init__ remains unchanged
    and so username and password need to be given as bytes objects
    """
    def send_dh_public_key(self):
        """Calculates and returns the SRP public key and user email
        
        Returns:
            string, int: a tuple of user email and the clients secret key (int)
        """
        
        self.public_key = modexp(self.base, self.secret_key, self.prime)
        
        return self.user_email.decode(), self.public_key

    def calculate_hmac(self):
        """Calculates the hmac and returns it. If the password is correct, it
        it should match the hmac calculated byt the server.
        
        returns:
            string: hmac encoded as a hex string depending on password, salt 
            and server and client keys
        """

        return bso.bytes_to_hex(SRPClient.calculate_hmac(self))


