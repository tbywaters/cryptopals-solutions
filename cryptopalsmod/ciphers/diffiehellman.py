import cryptopalsmod.number_theory as numbers

class DiffieHellman:
    """Implementation of diffiehellman. Secret ke is optional on initialistion 
    but must be set before generating a public or shared key
    """
    def __init__(self, prime, base, secret_key = None):
        self.prime = prime
        self.base = base
        self.secret_key = secret_key

    def set_secret_key(self, secret_key):
        self.secret_key = secret_key

    def gen_public_key(self):
        if self.secret_key == None:
            raise Exception('Need to set secret key before calculating public key')
        self.public_key = numbers.modexp(self.base, self.secret_key, self.prime)
        return self.public_key

    def gen_shared_key(self, public_key):
        if self.secret_key == None:
            raise Exception('Need to set secret key before calculating shared key')
        return numbers.modexp(public_key, self.secret_key, self.prime)
        