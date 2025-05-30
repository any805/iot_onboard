from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import secp256k1
from charm.core.math.elliptic_curve import getGenerator

"""
This implementation uses SECG curve secp256k1 by default.
Messages are padded to 28 bytes before encoding to curve points.

If switching to a different curve:
1. Import the new curve from charm.toolbox.eccurve
2. Pass the new curve to ECElGamal constructor
3. Adjust padding length in encode() method if needed - the required length depends on the curve's field size
"""

class ECElGamal:
    def __init__(self, curve=secp256k1):
        self.group = ECGroup(curve)
        # Use the standard generator of the curve
        self.g = getGenerator(self.group.ec_group)

    def keygen(self):
        '''Key Generation:
        - g: standard generator of the curve ∈ E(F_p)
        - x: random private key ∈ Z_q
        - Q: public key = xG'''
        x = self.group.random(ZR)
        Q = self.g ** x
        sk = x
        pk = (self.g, Q)
        return (pk, sk)

    def encode(self, msg_bytes):
        # Pad message to 28 bytes for secp256k1
        msg_padded = msg_bytes.ljust(28, b'\0')
        return self.group.encode(msg_padded)

    def decode(self, g_elem):
        # Decode point back to byte string
        msg_padded = self.group.decode(g_elem)
        return msg_padded.rstrip(b'\0')

    def encrypt(self, pk, msg_bytes):
        '''Encryption (EC group notation):
        - m: message encoded as point ∈ E(F_p)
        - k: random ephemeral key ∈ Z_q
        - C1 = kG
        - S = kQ
        - C2 = m + S  # EC group addition
        '''
        g, Q = pk
        m = self.encode(msg_bytes)
        k = self.group.random(ZR)
        C1 = g ** k
        S = Q ** k  # Shared secret point
        C2 = m * S  # EC group addition (m + S)
        return (C1, C2)

    def decrypt(self, sk, pk, ciphertext):
        '''Decryption (EC group notation):
        - S' = xC1 = x(kG) = kxG = kQ
        - M = C2 - S' = (m + S) - S = m  # EC group subtraction
        '''
        g, Q = pk
        C1, C2 = ciphertext
        x = sk
        S = C1 ** x  # Recover shared secret
        M = C2 / S   # EC group subtraction (C2 - S)
        return self.decode(M)
