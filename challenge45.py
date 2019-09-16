from cryptopalsmod.ciphers import dsa
from cryptopalsmod.hash.sha1 import SHA1
import secrets
import cryptopalsmod.number_theory as nt

class ChallengeDSAUser(dsa.DSAUser):
    """Current implementation of dsa does not allow for r = 0. This one does so
    it can be exploited"""
    def sign_message(self, message):
 
        r = s = 0
 
    
        k = secrets.randbelow(self.q)
 
        r = nt.modexp(self.g, k, self.p) % self.q
 
        k_inv = nt.invmod(k, self.q)
 
        msg_hash = int(self.hash(message).hexdigest(), 16)
        s = (k_inv * (msg_hash + self.secret_key * r)) % self.q
        
        return self.public_key, r, s
    
    def verify(self, message, public_key, r, s):
    
        s_inv = nt.invmod(s, self.q)
        
        msg_hash = int(self.hash(message).hexdigest(), 16)
        exp1 = msg_hash * s_inv % self.q
        
        exp2 = r * s_inv % self.q
        
        v = ((nt.modexp(self.g, exp1, self.p) * nt.modexp(public_key, exp2, self.p)) % self.p) % self.q

        return v == r

def main():

    server = ChallengeDSAUser(SHA1)
    client = ChallengeDSAUser(SHA1)

    #malicious g parameter
    server.g = client.g = 0
    server.key_generation()
    client.key_generation()


    message = b'henlo'
    signature = server.sign_message(message)

    assert client.verify(message, *signature)
    assert signature[0] == 0
    assert signature[1] == 0

    #since g = 0, any signature will have r = 0 and secret key = 0
    #  but worse still, any signature with r = 0 will verify any message

    new_message = secrets.token_bytes(21)

    assert client.verify(new_message, *signature)

    #new malicious g value
    server.g = client.g = server.p + 1
    server.key_generation()
    client.key_generation()

    signature = server.sign_message(message)
    assert signature[0] == signature[1] == 1
    assert client.verify(message, *signature)

    #we can construct a magic signature for a given public key and any message
    #choose a random public key

    public_key = secrets.randbelow(server.p)
    
    z = 3 #a magic number (not actually magic in this case, any z will do)

    r = nt.modexp(public_key, z, server.p) % server.q

    s = (r * nt.invmod(z, server.q)) % server.q

    assert client.verify(new_message, public_key, r, s)



if __name__ == "__main__":
    main()