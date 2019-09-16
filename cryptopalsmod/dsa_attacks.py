from cryptopalsmod import number_theory as nt


class DSAattacks():
    """This class contains fucntions used for cracking bad implementations of dsa.
    p, q and g are preset but the hash function can be specified on initalisation
    """
    def __init__(self, hash_func):

        self.p = int("""800000000000000089e1855218a0e7dac38136ffafa72eda7
                        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
                        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
                        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
                        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
                        1a584471bb1""".replace('\n', '').replace(' ', ''), 16)
 
        self.q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
 
        self.g = int("""5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
                        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
                        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
                        0f5b64c36b625a097f1651fe775323556fe00b3608c887892
                        878480e99041be601a62166ca6894bdd41a7054ec89f756ba
                        9fc95302291""".replace('\n', '').replace(' ', ''), 16)

        self.hash = hash_func

    def secret_key_from_nonce(self, message, nonce, r, s):
        """
        Given a signature, nonce and message, calculates the secret key"""
        numerator = (s*nonce - int(self.hash(message).hexdigest(), 16)) % self.q
        
        r_inv = nt.invmod(r, self.q)
        
        return (numerator * r_inv) % self.q


    def brute_force_attack_on_nonce(self, message, r, s, max_nonce = None):
        """attempts to discover nonce from a message with signature via brute
        force"""
        #If an upper bounc is not set, tess all possible choices
        if max_nonce == None:
            max_nonce = self.q

        for nonce in range(0, max_nonce):
            
            test_sec_key = self.test_nonce(nonce, message, r, s)
            
            if test_sec_key > 0:
                return test_sec_key
 
        raise Exception('Nonce not found')


    def test_nonce(self, nonce, message, r, s):
        """Tests is a nonce gives the desired signature for a message"""

        message_int = int(self.hash(message).hexdigest(), 16)

        test_r = nt.modexp(self.g, nonce, self.p) % self.q

            #Don't test s if r does not match
            
        if test_r == r:
            secret_key = self.secret_key_from_nonce(message, nonce, r, s)
        
            nonce_inv = nt.invmod(nonce, self.q)

            test_s = (nonce_inv * (message_int + secret_key * r)) % self.q
            
            if test_s == s:
                return secret_key
        
        return 0
    
    def key_from_double_signing(self, msg_dict1, msg_dict2):
        """Tries to calculate the nonce from a pair of messages that were encoded
        from the same key. If the nonce is correct, returns the secret key

        Args:
            msg_dict1 (dict): a distionary with fields
                'msg' (bytes): the message which has been signed
                'r' (int): the r value in the signature
                's' (int): the s value in the signature
            msg_dict2 (dict): see msg_dict1

        returns 
            int: secret key used for signing
        """
        nonce = self.nonce_from_double_signing(msg_dict1['msg'], msg_dict1['s'],
                                                msg_dict2['msg'], msg_dict2['s'])
        
        return self.test_nonce(nonce, msg_dict1['msg'], msg_dict1['r'], msg_dict1['s'])

    def nonce_from_double_signing(self, message1, s1, message2, s2):
        """Computes the nonce from two message signed witht the same nonce"""

        msg_hash1 = int(self.hash(message1).hexdigest(), 16) 
        msg_hash2 = int(self.hash(message2).hexdigest(), 16)

        numerator = (msg_hash1 - msg_hash2) % self.q

        denominator = nt.invmod((s1 - s2) % self.q, self.q)

        return (numerator * denominator) % self.q 