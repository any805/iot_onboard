"""
Nonprivate Scheme - Onboarding Phase Implementation
Measures computation time and communication costs for each role
"""

import time
import json
import hashlib
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from secure_iot_onboarding.schemes.ecdsa import ECDSASig
from secure_iot_onboarding.schemes.ecvrf import ECVRF
from secure_iot_onboarding.schemes.schnorr_zkp import SchnorrZKP
from charm.toolbox.ecgroup import ECGroup, ZR
from charm.toolbox.eccurve import secp256k1

class NonprivateOnboardingPhase:
    def __init__(self):
        self.group = ECGroup(secp256k1)
        
        # Pre-generate keys for consistent measurements
        # Host keys
        self.host_sig = ECDSASig()
        self.pk_h, self.sk_h = self.host_sig.keygen()
        
        # Server keys
        self.auth_sig = ECDSASig()
        self.pk_a, self.sk_a = self.auth_sig.keygen()
        
        # Beacon/VRF
        self.beacon = ECVRF()
        self.beacon_pk, self.beacon_sk = self.beacon.keygen()
        
        # Pre-generate beacon randomness
        self.alpha = b"test_epoch_12345"
        self.proof = self.beacon.prove(self.beacon_sk, self.alpha)
        _, self.randomness_bytes = self.beacon.verify(self.beacon_pk, self.alpha, self.proof)
        
        # Convert randomness bytes to a ZR element for use in signatures
        self.r = self.group.random(ZR)  # Use a proper random element for signing
        
    def measure_host_onboarding(self, iterations=1000):
        """Measure Host onboarding phase computation"""
        total_time = 0
        communication_size = 0
        
        for _ in range(iterations):
            start_time = time.time()
            
            # 1. Run BN.Verify to verify the beacon (r, proof)
            is_valid, randomness = self.beacon.verify(self.beacon_pk, self.alpha, self.proof)
            
            # 2. Run S.KeyGen to generate key for guest
            guest_sig = ECDSASig()
            pk_g, sk_g = guest_sig.keygen()
            
            # 3. Compute σ = S.Sign to sign pk_g and r
            message = str(pk_g['g']) + str(pk_g['y']) + str(self.r)
            hashed_msg = hashlib.sha256(message.encode()).digest()
            sigma = self.host_sig.sign(hashed_msg)
            
            # 4. Generate token (JSON format)
            token = {
                "sigma": {
                    "r": str(sigma['r']), 
                    "s": str(sigma['s'])
                },
                "r": str(self.r),
                "pk_g": {
                    "g": str(pk_g['g']),
                    "y": str(pk_g['y'])
                },
                "pk_h": {
                    "g": str(self.pk_h['g']),
                    "y": str(self.pk_h['y'])
                },
                "link": "https://example.com/guest/config"
            }
            token_json = json.dumps(token)
            
            total_time += time.time() - start_time
            
            # Measure communication size on first iteration
            if communication_size == 0:
                # Size of token sent to guest
                token_size = len(token_json.encode())
                # Size of private key sent separately
                sk_g_size = len(self.group.serialize(sk_g))
                communication_size = token_size + sk_g_size
        
        avg_time = total_time / iterations
        return avg_time * 1000, communication_size  # Convert to ms
    
    def measure_server_onboarding(self, iterations=1000):
        """Measure Server onboarding phase computation"""
        # Pre-generate a sample token and ZKP for testing
        guest_sig = ECDSASig()
        pk_g, sk_g = guest_sig.keygen()
        
        # Create sample token
        message = str(pk_g['g']) + str(pk_g['y']) + str(self.r)
        hashed_msg = hashlib.sha256(message.encode()).digest()
        sigma = self.host_sig.sign(hashed_msg)
        
        # Create sample ZKP
        zkp = SchnorrZKP()
        zkp.keygen()
        zkp.rerandomize()
        pi = zkp.prove()
        
        total_time = 0
        communication_size = 0
        
        for _ in range(iterations):
            start_time = time.time()
            
            # 1. Run BN.Eval to generate (r, proof)
            proof_new = self.beacon.prove(self.beacon_sk, self.alpha)
            
            # 2. Run BN.Verify to verify randomness
            is_valid, r_new = self.beacon.verify(self.beacon_pk, self.alpha, proof_new)
            
            # 3. Run S.Verify to verify signature σ
            is_valid_sig = self.host_sig.verify(hashed_msg, sigma)
            
            # 4. Run S.Sign to sign pass if token is valid
            if is_valid_sig:
                pass_msg = b"PASS_GRANTED"
                delta = self.auth_sig.sign(pass_msg)
            
            # 5. Run ZKP.Verify to verify the re-randomization proof
            is_valid_zkp = zkp.verify(pi)
            
            total_time += time.time() - start_time
            
            # Measure communication size on first iteration
            if communication_size == 0:
                # Size of beacon sent to host
                # Send the randomness bytes (32 bytes) and proof
                randomness_size = 32  # SHA-256 output from VRF
                gamma, c, s = proof_new
                proof_size = (len(self.beacon.group.serialize(gamma)) + 
                             len(self.beacon.group.serialize(c)) + 
                             len(self.beacon.group.serialize(s)))
                beacon_size = randomness_size + proof_size
                
                # Size of pass sent to guest
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
            
            # 1. Run re-rand.apply to re-randomize the key pair
            zkp = SchnorrZKP()
            zkp.sk = sk_g
            zkp.pk = pk_g['y']
            # zkp.G is already set in __init__ using getGenerator
            G_new, pk_g_prime, r_used = zkp.rerandomize()
            
            # 2. Run ZKP.Prove to generate proof π
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
        print("NONPRIVATE SCHEME - ONBOARDING PHASE MEASUREMENTS")
        print("=" * 60)
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
        host_to_server = 100  # Host registration (estimate)
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
    onboarding = NonprivateOnboardingPhase()
    results = onboarding.run_measurements()
    
    # Additional formatted output for LaTeX tables
    print("\n\n" + "=" * 60)
    print("FORMATTED OUTPUT FOR LATEX TABLES")
    print("=" * 60)
    
    # Table 2: Computation Cost Comparison in Onboarding Phase
    print("\nTable: Computation Cost Comparison in Onboarding Phase")
    print("\nScheme without Privacy:")
    print(f"Guest  & {results['computation']['guest']:.3f}")
    print(f"Host   & {results['computation']['host']:.3f}")
    print(f"Server & {results['computation']['server']:.3f}")
    
    # Table 3: Communication Cost Comparison in Onboarding Phase
    print("\n\nTable: Communication Cost Comparison in Onboarding Phase")
    print("\nScheme without Privacy:")
    print(f"Host ↔ Guest   & {results['communication']['host_guest']}")
    print(f"Host ↔ Server  & {results['communication']['host_server']}")
    print(f"Guest ↔ Server & {results['communication']['guest_server']}")
    print("\n" + "=" * 60)
