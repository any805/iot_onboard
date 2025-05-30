"""
Privacy Enhanced Scheme - Onboarding Phase Implementation
Measures computation time and communication costs for each role
"""

import time
import json
import hashlib
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from secure_iot_onboarding.schemes.bbs import BBSGroupSig
from secure_iot_onboarding.schemes.ec_elgamel import ECElGamal
from secure_iot_onboarding.schemes.ecdsa import ECDSASig
from secure_iot_onboarding.schemes.ecvrf import ECVRF
from secure_iot_onboarding.schemes.schnorr_zkp import SchnorrZKP
from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import secp256k1

class PrivacyEnhancedOnboardingPhase:
    def __init__(self):
        self.group = ECGroup(secp256k1)
        
        # Pre-generate keys for consistent measurements
        # BBS group signature (uses MNT224 internally)
        self.bbs = BBSGroupSig()
        self.gpk, self.gmsk, self.gsk = self.bbs.keygen(100)  # 100 hosts
        
        # Host has a member key gsk[h] and pseudonym w
        self.host_gsk = self.gsk[0]  # First member key for host
        # Pre-generate pseudonym w (not counted in computation)
        self.host_w = self.group.hash(str(0).encode(), ZR)
        
        # ElGamal encryption for pseudonym encryption
        self.elgamal = ECElGamal()
        self.pk_a, self.sk_a = self.elgamal.keygen()  # Auth server's encryption keys
        
        # ECDSA for authentication server signatures
        self.auth_sig = ECDSASig()
        self.pk_auth, self.sk_auth = self.auth_sig.keygen()
        
        # Beacon/VRF
        self.beacon = ECVRF()
        self.beacon_pk, self.beacon_sk = self.beacon.keygen()
        
        # Pre-generate beacon randomness for verification
        self.alpha = b"test_epoch_12345"
        self.proof = self.beacon.prove(self.beacon_sk, self.alpha)
        _, self.randomness_bytes = self.beacon.verify(self.beacon_pk, self.alpha, self.proof)
        
        # Pre-generate randomness r as ZR element (not counted in computation)
        self.r = self.group.random(ZR)
        
    def measure_host_onboarding(self, iterations=1000):
        """Measure Host onboarding phase computation"""
        total_time = 0
        communication_size = 0
        
        for _ in range(iterations):
            start_time = time.time()
            
            # Host operations (to generate one token):
            # 1. Run BN.Verify to verify the beacon (r, proof)
            is_valid, randomness = self.beacon.verify(self.beacon_pk, self.alpha, self.proof)
            
            # 2. Run S.KeyGen to generate key for guest
            guest_sig = ECDSASig()
            pk_g, sk_g = guest_sig.keygen()
            
            # 3. Compute σ = GS.Sign to sign pk_g and r
            # BBS signs a concatenated message
            message = self.group.serialize(pk_g['y'])[:28] + self.group.serialize(self.r)[:28]
            sigma = self.bbs.sign(0, message)  # Using host index 0
            
            # 4. Run E.Enc to encrypt pseudonym w and randomness r
            # Combine w and r into a single message for encryption
            w_r_combined = self.group.serialize(self.host_w)[:14] + self.group.serialize(self.r)[:14]
            C = self.elgamal.encrypt(self.pk_a, w_r_combined)
            
            # 5. Generate token (JSON format)
            # Note: Token generation formatting is not counted as cryptographic operation
            
            total_time += time.time() - start_time
            
            # Measure communication size on first iteration
            if communication_size == 0:
                # Serialize BBS signature components
                # ShortSig returns: T1, T2, T3, c, s_alpha, s_beta, s_x, s_delta1, s_delta2
                sigma_serialized = {
                    'T1': self.bbs.group.serialize(sigma['T1']).decode('latin-1'),
                    'T2': self.bbs.group.serialize(sigma['T2']).decode('latin-1'),
                    'T3': self.bbs.group.serialize(sigma['T3']).decode('latin-1'),
                    'c': self.bbs.group.serialize(sigma['c']).decode('latin-1'),
                    's_alpha': self.bbs.group.serialize(sigma['s_alpha']).decode('latin-1'),
                    's_beta': self.bbs.group.serialize(sigma['s_beta']).decode('latin-1'),
                    's_x': self.bbs.group.serialize(sigma['s_x']).decode('latin-1'),
                    's_delta1': self.bbs.group.serialize(sigma['s_delta1']).decode('latin-1'),
                    's_delta2': self.bbs.group.serialize(sigma['s_delta2']).decode('latin-1')
                }
                
                # Serialize ciphertext C - it's a tuple (C1, C2)
                C_serialized = {
                    'c1': self.group.serialize(C[0]).decode('latin-1'),
                    'c2': self.group.serialize(C[1]).decode('latin-1')
                }
                
                # Serialize gpk - it's a dictionary with multiple components
                gpk_serialized = {}
                for key, value in self.gpk.items():
                    gpk_serialized[key] = self.bbs.group.serialize(value).decode('latin-1')
                
                token = {
                    "sigma": sigma_serialized,
                    "C": C_serialized,
                    "r": str(self.r),
                    "pk_g": {
                        "g": str(pk_g['g']),
                        "y": str(pk_g['y'])
                    },
                    "gpk": gpk_serialized,
                    "link": "https://example.com/guest/config"
                }
                token_json = json.dumps(token)
                
                # Size of token sent to guest
                token_size = len(token_json.encode())
                # Size of private key sent separately
                sk_g_size = len(self.group.serialize(sk_g))
                communication_size = token_size + sk_g_size
        
        avg_time = total_time / iterations
        return avg_time * 1000, communication_size  # Convert to ms
    
    def measure_server_onboarding(self, iterations=1000):
        """Measure Server onboarding phase computation"""
        # Pre-generate sample data for verification
        guest_sig = ECDSASig()
        pk_g, sk_g = guest_sig.keygen()
        
        # Create sample token components
        message = self.group.serialize(pk_g['y'])[:28] + self.group.serialize(self.r)[:28]
        sigma = self.bbs.sign(0, message)  # Using host index 0
        
        # Encrypt pseudonym and randomness
        w_r_combined = self.group.serialize(self.host_w)[:14] + self.group.serialize(self.r)[:14]
        C = self.elgamal.encrypt(self.pk_a, w_r_combined)
        
        # Create sample ZKP for re-randomization
        zkp = SchnorrZKP()
        zkp.sk = sk_g
        zkp.pk = pk_g['y']
        zkp.rerandomize()
        pi = zkp.prove()
        
        total_time = 0
        communication_size = 0
        
        for _ in range(iterations):
            start_time = time.time()
            
            # Server operations:
            # 1. Run BN.Eval to generate (r, proof)
            proof_new = self.beacon.prove(self.beacon_sk, self.alpha)
            
            # 2. Run BN.Verify to verify randomness (r, proof)
            is_valid, r_new = self.beacon.verify(self.beacon_pk, self.alpha, proof_new)
            
            # To verify the token:
            # 3. Run GS.Verify to verify signature σ
            is_valid_sig = self.bbs.verify(message, sigma)
            
            # 4. Run E.Dec to obtain r' and w'
            decrypted = self.elgamal.decrypt(self.sk_a, self.pk_a, C)
            # Extract w' and r' from decrypted message
            # w' = decrypted[:14], r' = decrypted[14:28]
            
            # 5. Check r' = r (comparison skipped in timing)
            # 6. Check w' is not revoked (skipped as per instructions)
            
            # 7. Run S.Sign to sign pass if token is valid
            if is_valid_sig:
                pass_msg = b"PASS_GRANTED"
                delta = self.auth_sig.sign(pass_msg)
            
            # 8. Run ZKP.Verify to verify the re-randomization proof π (for guest)
            is_valid_zkp = zkp.verify(pi)
            
            total_time += time.time() - start_time
            
            # Measure communication size on first iteration
            if communication_size == 0:
                # Size of beacon sent to host
                randomness_size = 32  # SHA-256 output from VRF
                gamma, c, s = proof_new
                proof_size = (len(self.beacon.group.serialize(gamma)) + 
                             len(self.beacon.group.serialize(c)) + 
                             len(self.beacon.group.serialize(s)))
                beacon_size = randomness_size + proof_size
                
                # Size of pass (delta) sent to guest
                pass_size = len(self.group.serialize(delta['r'])) + len(self.group.serialize(delta['s']))
                communication_size = beacon_size + pass_size
        
        avg_time = total_time / iterations
        return avg_time * 1000, communication_size  # Convert to ms
    
    def measure_guest_onboarding(self, iterations=1000):
        """Measure Guest onboarding phase computation"""
        # Pre-generate guest keys
        guest_sig = ECDSASig()
        pk_g, sk_g = guest_sig.keygen()
        
        total_time = 0
        communication_size = 0
        
        for _ in range(iterations):
            start_time = time.time()
            
            # Guest operations:
            # Note: Download and install configuration, verify signature δ (S.Verify) on pass
            # is skipped as per instructions
            
            # 1. Run re-rand.apply to re-randomize the private and public key pair
            zkp = SchnorrZKP()
            zkp.sk = sk_g
            zkp.pk = pk_g['y']
            G_new, pk_g_prime, r_used = zkp.rerandomize()
            
            # 2. Run ZKP.Prove to generate proof π for re-rand
            pi = zkp.prove()
            
            total_time += time.time() - start_time
            
            # Measure communication size on first iteration
            if communication_size == 0:
                # Size of updated public key and proof sent to server
                pk_prime_size = len(self.group.serialize(pk_g_prime))
                pi_size = (len(self.group.serialize(pi[0])) + 
                          len(self.group.serialize(pi[1])) +
                          len(self.group.serialize(pi[2])) +
                          len(self.group.serialize(pi[3])))
                communication_size = pk_prime_size + pi_size
        
        avg_time = total_time / iterations
        return avg_time * 1000, communication_size  # Convert to ms
    
    def run_measurements(self):
        """Run all measurements and display results"""
        print("=" * 60)
        print("PRIVACY ENHANCED SCHEME - ONBOARDING PHASE MEASUREMENTS")
        print("=" * 60)
        print(f"Number of hosts: 100")
        print(f"Running {1000} iterations for each measurement...\n")
        
        # Measure computation costs
        print("Measuring Host onboarding...")
        host_time, host_to_guest_comm = self.measure_host_onboarding()
        
        print("Measuring Server onboarding...")
        server_time, server_comm = self.measure_server_onboarding()
        
        print("Measuring Guest onboarding...")
        guest_time, guest_to_server_comm = self.measure_guest_onboarding()
        
        # Display computation cost results
        print("\n" + "=" * 60)
        print("COMPUTATION COST (ONBOARDING PHASE)")
        print("=" * 60)
        print(f"{'Role':<10} {'Computation (ms)':<20}")
        print("-" * 30)
        print(f"{'Guest':<10} {guest_time:<20.3f}")
        print(f"{'Host':<10} {host_time:<20.3f}")
        print(f"{'Server':<10} {server_time:<20.3f}")
        
        # Calculate communication costs
        # Note: Some values are estimates based on typical sizes
        host_to_server = 150  # Host registration with privacy (estimate)
        server_to_host = server_comm  # Beacon data
        
        # Display communication cost results
        print("\n" + "=" * 60)
        print("COMMUNICATION COST (ONBOARDING PHASE)")
        print("=" * 60)
        print(f"{'Channel':<25} {'Size (bytes)':<20}")
        print("-" * 45)
        print(f"{'Host ↔ Guest':<25} {host_to_guest_comm:<20}")
        print(f"{'Host ↔ Server':<25} {host_to_server + server_to_host:<20}")
        print(f"{'Guest ↔ Server':<25} {guest_to_server_comm:<20}")
        print("=" * 60)
        
        return {
            'computation': {
                'guest': guest_time,
                'host': host_time,
                'server': server_time
            },
            'communication': {
                'host_guest': host_to_guest_comm,
                'host_server': host_to_server + server_to_host,
                'guest_server': guest_to_server_comm
            }
        }

if __name__ == "__main__":
    onboarding = PrivacyEnhancedOnboardingPhase()
    results = onboarding.run_measurements()
    
    # Additional formatted output for LaTeX tables
    print("\n\n" + "=" * 60)
    print("FORMATTED OUTPUT FOR LATEX TABLES")
    print("=" * 60)
    
    # Table 2: Computation Cost Comparison in Onboarding Phase
    print("\nTable: Computation Cost Comparison in Onboarding Phase")
    print("\nScheme with Privacy:")
    print(f"Guest  & {results['computation']['guest']:.3f}")
    print(f"Host   & {results['computation']['host']:.3f}")
    print(f"Server & {results['computation']['server']:.3f}")
    
    # Table 3: Communication Cost Comparison in Onboarding Phase
    print("\n\nTable: Communication Cost Comparison in Onboarding Phase")
    print("\nScheme with Privacy:")
    print(f"Host ↔ Guest   & {results['communication']['host_guest']}")
    print(f"Host ↔ Server  & {results['communication']['host_server']}")
    print(f"Guest ↔ Server & {results['communication']['guest_server']}")
    print("\n" + "=" * 60)
