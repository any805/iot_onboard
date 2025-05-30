from charm.schemes.pksig.pksig_ecdsa import ECDSA
from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import secp256k1

class ECDSASig:
    def __init__(self, curve=secp256k1):
        self.group = ECGroup(curve)
        self.ecdsa = ECDSA(self.group)
        self.pk = None
        self.sk = None

    def keygen(self):
        '''Generate ECDSA public and private keys.'''
        self.pk, self.sk = self.ecdsa.keygen(0)
        return self.pk, self.sk

    def sign(self, message):
        '''Sign a message with the private key.'''
        if self.pk is None or self.sk is None:
            raise ValueError("Keys not generated. Call keygen() first.")
        return self.ecdsa.sign(self.pk, self.sk, message)

    def verify(self, message, signature):
        '''Verify a signature with the public key.'''
        if self.pk is None:
            raise ValueError("Public key not set. Call keygen() first.")
        return self.ecdsa.verify(self.pk, signature, message)
