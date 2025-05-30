from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.core.math.elliptic_curve import elliptic_curve, getGenerator
from charm.toolbox.eccurve import secp256k1
from charm.core.math.integer import integer

class SchnorrZKP:
    """
    Non-interactive Schnorr Zero-Knowledge Proof for key rerandomization in signature schemes.
    Proves knowledge of sk and r such that:
    1. pk = sk * G
    2. pk' = pk + r * G
    """
    def __init__(self, curve=secp256k1):
        self.group = ECGroup(curve)
        self.G = getGenerator(self.group.ec_group)  # Standard generator point
        self.pk = None
        self.sk = None
        self.pk_prime = None
        self.r = None

    def keygen(self):
        """Generate original key pair (sk, pk)"""
        self.sk = self.group.random(ZR)  # sk \in Z_q
        self.pk = self.G ** self.sk      # pk = sk * G
        return (self.G, self.pk, self.sk)  # Return G along with pk and sk

    def rerandomize(self, r=None):
        """Rerandomize key pair using random r"""
        if self.pk is None or self.sk is None:
            raise ValueError("Keys not generated. Call keygen() first.")
            
        if r is None:
            r = self.group.random(ZR)  # r \in Z_q
        self.r = r
        rG = self.G ** r  # First compute r * G
        self.pk_prime = self.pk * rG  # Then multiply pk and rG
        return (self.G, self.pk_prime, self.r)  # Return G along with pk' and r

    def prove(self):
        """
        Generate proof π = (A, B, d1, d2) that proves knowledge of sk and r
        """
        if self.pk is None or self.sk is None or self.pk_prime is None or self.r is None:
            raise ValueError("Keys not generated or rerandomized. Call keygen() and rerandomize() first.")

        # 1. Choose random blinding factors
        a = self.group.random(ZR)  # a \in_R Z_q
        b = self.group.random(ZR)  # b \in_R Z_q
        
        # 2. Compute commitments
        A = self.G ** a  # A = a * G
        B = self.G ** b  # B = b * G
        
        # 3. Compute challenge using Fiat-Shamir
        c = self.group.hash((self.G, self.pk, self.pk_prime, A, B))
        
        # 4. Compute responses
        d1 = a + c * self.r  # d1 = a + c * r
        d2 = b + c * self.sk  # d2 = b + c * sk
        
        return (A, B, d1, d2)

    def verify(self, proof):
        """
        Verify proof π = (A, B, d1, d2)
        Returns True if proof is valid, False otherwise
        """
        if self.pk is None or self.pk_prime is None:
            raise ValueError("Keys not generated or rerandomized. Call keygen() and rerandomize() first.")

        A, B, d1, d2 = proof
        
        # 1. Recompute challenge
        c = self.group.hash((self.G, self.pk, self.pk_prime, A, B))
        
        # 2. Verify responses
        # Check 1: d1 * G == A * (pk' / pk)^c
        lhs1 = self.G ** d1
        pk_diff = self.pk_prime / self.pk  # First compute pk' / pk
        rhs1 = A * (pk_diff ** c)  # Then multiply by c and add A
        check1 = lhs1 == rhs1
        
        # Check 2: d2 * G == B * pk^c
        lhs2 = self.G ** d2
        rhs2 = B * (self.pk ** c)
        check2 = lhs2 == rhs2
        
        return check1 and check2

