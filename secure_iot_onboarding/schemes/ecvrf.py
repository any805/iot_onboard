from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import secp256k1
from charm.core.math.elliptic_curve import getGenerator
import hashlib

"""
Minimal EC-VRF implementation for server-to-host randomness transfer.
Uses secp256k1 curve and SHA-256 hash function.

The implementation provides:
1. Key generation
2. Proof generation (server side)
3. Proof verification and randomness extraction (host side)
"""

class ECVRF:
    def __init__(self, curve=secp256k1):
        """Initialize EC-VRF with secp256k1 curve"""
        self.group = ECGroup(curve)
        try:
            self.B = getGenerator(self.group.ec_group)  # Standard generator
            self.q = self.group.order()    # Prime order
            self.hLen = 32                 # SHA-256 output length
        except Exception as e:
            raise ValueError(f"Failed to initialize EC-VRF: {str(e)}")
        
    def safe_point_op(self, op, *args):
        """Safely perform point operations with error handling"""
        try:
            result = op(*args)
            return result
        except Exception as e:
            raise ValueError(f"Point operation failed: {str(e)}")
        
    def keygen(self):
        """Generate VRF key pair"""
        try:
            # Generate private key
            sk = self.group.random(ZR)
            # Compute public key
            pk = self.safe_point_op(lambda: self.B ** sk)
            return pk, sk
        except Exception as e:
            raise ValueError(f"Key generation failed: {str(e)}")
    
    def encode_to_curve(self, alpha):
        """Hash input to curve point using try-and-increment method"""
        ctr = 0
        while True:
            ctr_bytes = ctr.to_bytes(1, 'big')
            hash_input = b'ECVRF' + alpha + ctr_bytes
            hash_output = hashlib.sha256(hash_input).digest()
            try:
                # Use group's hash method
                H = self.group.hash(hash_output, G)
                # Check if point is valid using coordinates
                if self.group.coordinates(H) is not None:
                    return H
            except:
                pass
            ctr += 1
            if ctr > 255:
                raise Exception("Failed to encode to curve")
    
    def nonce_generation(self, sk, h):
        """Generate nonce for proof generation"""
        try:
            # Use RFC 8032 style nonce generation
            hashed_sk = hashlib.sha256(self.group.serialize(sk)).digest()
            truncated_sk = hashed_sk[:32]  # Use first 32 bytes
            k_string = hashlib.sha256(truncated_sk + self.group.serialize(h)).digest()
            k = int.from_bytes(k_string, 'big') % self.q  # Use big-endian and ensure in q range
            return k
        except Exception as e:
            raise ValueError(f"Nonce generation failed: {str(e)}")
    
    def hash_points(self, *points):
        """Hash multiple points to a challenge value"""
        try:
            point_bytes = b''
            for point in points:
                if self.group.coordinates(point) is None:
                    raise ValueError("Invalid point in hash_points")
                point_bytes += self.group.serialize(point)
            return int.from_bytes(hashlib.sha256(point_bytes).digest(), 'big') % self.q
        except Exception as e:
            raise ValueError(f"Point hashing failed: {str(e)}")
    
    def prove(self, sk, alpha):
        """Generate VRF proof"""
        try:
            # 1. Encode input to curve point
            H = self.encode_to_curve(alpha)
            if self.group.coordinates(H) is None:
                raise ValueError("Invalid point after encoding")
            
            # 2. Compute gamma = sk * H
            gamma = self.safe_point_op(lambda: H ** sk)
            if self.group.coordinates(gamma) is None:
                raise ValueError("Invalid point after gamma computation")
            
            # 3. Generate random nonce k
            k = self.nonce_generation(sk, H)
            
            # 4. Compute k*G and k*H
            kG = self.safe_point_op(lambda: self.B ** k)
            kH = self.safe_point_op(lambda: H ** k)
            if self.group.coordinates(kG) is None or self.group.coordinates(kH) is None:
                raise ValueError("Invalid point after k computation")
            
            # 5. Compute challenge value c
            c = self.hash_points(H, gamma, kG, kH)
            
            # 6. Compute s = k + c*sk
            s = (k + c * sk) % self.q
            
            return (gamma, c, s)
        except Exception as e:
            raise ValueError(f"Proof generation failed: {str(e)}")
    
    def verify(self, pk, alpha, proof):
        """Verify VRF proof"""
        try:
            gamma, c, s = proof
            
            # 1. Encode input to curve point
            H = self.encode_to_curve(alpha)
            if self.group.coordinates(H) is None:
                return False, None
            
            # 2. Compute s*G and s*H
            sG = self.safe_point_op(lambda: self.B ** s)
            sH = self.safe_point_op(lambda: H ** s)
            if self.group.coordinates(sG) is None or self.group.coordinates(sH) is None:
                return False, None
            
            # 3. Compute c*pk and c*gamma
            cpk = self.safe_point_op(lambda: pk ** c)
            cgamma = self.safe_point_op(lambda: gamma ** c)
            if self.group.coordinates(cpk) is None or self.group.coordinates(cgamma) is None:
                return False, None
            
            # 4. Compute U = s*G - c*pk
            U = self.safe_point_op(lambda: sG / cpk)
            if self.group.coordinates(U) is None:
                return False, None
            
            # 5. Compute V = s*H - c*gamma
            V = self.safe_point_op(lambda: sH / cgamma)
            if self.group.coordinates(V) is None:
                return False, None
            
            # 6. Compute challenge value c'
            cp = self.hash_points(H, gamma, U, V)
            
            # 7. Verify c == c'
            if c != cp:
                return False, None
                
            # 8. Compute randomness
            randomness = hashlib.sha256(self.group.serialize(gamma)).digest()
            return True, randomness
        except Exception as e:
            return False, None