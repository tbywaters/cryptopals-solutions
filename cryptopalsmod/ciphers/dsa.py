from cryptopalsmod.ciphers import rsa
from hashlib import sha256
import struct
from cryptopalsmod import bytestringops as bso


SHA256_asn1 = '3031300D060960864801650304020105000420'

class DSASignatory(rsa.RSAServer):
    """Gives capability to sign a message using RSA. Only uses SHA256 for 
    hashing"""
    
    def sign_message(self, message):
        """generates a rsa signature for a message
        Args: 
            message (bytes): message to be signed
        Returns:
            int: signature of the message
        """
        formatted_message = self.format_message(message)
        signature = rsa.RSAServer.decrypt(self, formatted_message)
        return signature

    def format_message(self, message):
        """Formats a message for signing"""
 
        #hash the message and add the correct ans1 rep fro sha256
        message_hash = sha256(message).hexdigest()

        #Add the coorect padding until the signature block is 128 bytes long

        sig_block = '00' + SHA256_asn1 + message_hash
        while len(sig_block)/2 < 128 - 2:
            sig_block = 'FF' + sig_block
        sig_block = '0001' + sig_block

        return int(sig_block, 16)

class DSAVerify(rsa.RSAClient):
    def bad_verify_message(self, message, signature):
        """Verifies a signature by decrypting and checking the signature (in hex)
        starts with '0001ff' and contains the correct ans1 for sha16 and hash
        of the message

        Agrs:
            message (bytes): message which has been signed
            signature (int): supposed signratur for the message
        Returns:
            bool: True if the signature passes the verification
        raises:
            Exception('Signiture is invalid'): if the signature does not pass validation
        
        message_hash = sha256(message).hexdigest()
        signature = rsa.RSAClient.encrypt(self, signature)

        signature = bso.bytes_to_hex(signature.to_bytes(128, 'big'))
        invalid_signature = Exception('Signiture is invalid')
        
        if signature[:6] != '0001ff':
            raise invalid_signature

        if not signature.find('ff00' + message_hash): 
            raise invalid_signature

        return True
