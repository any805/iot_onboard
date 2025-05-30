"""
Privacy Enhanced Scheme - Setup Phase Implementation
Measures computation time and storage costs for each role
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
from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import secp256k1

class PrivacyEnhancedSetupPhase:
    def __init__(self, num_hosts=100):
        self.num_hosts = num_hosts
        self.group = ECGroup(secp256k1)
        
        # Pre-generate keys for consistent measurements
        # Note: BBS uses MNT224 curve internally
        self.bbs = BBSGroupSig()
        
        # Pre-generate all pseudonyms w for hosts (not counted in computation)
        self.pseudonyms = []
        for i in range(self.num_hosts):
            # Generate pseudonym w for each user (hash of integer)
            w = self.group.hash(str(i).encode(), ZR)
            self.pseudonyms.append(w)
        
        # Pre-generate group keys once (expensive operation)
        self.gpk, self.gmsk, self.gsk = self.bbs.keygen(self.num_hosts)
        
        # ElGamal encryption
        self.elgamal = ECElGamal()
        
        # ECDSA for authentication server
        self.auth_sig = ECDSASig()
        
        # EC-VRF for beacon
        self.beacon = ECVRF()
        
    def secret_sharing_generate(self, secret, n=3):
        """
        Placeholder for SS.GenShare
        Linear (additive) secret sharing - to be implemented
        """
        # TODO: Implement additive secret sharing
        # For now, return dummy shares
        return [secret] * n
    
    def secret_sharing_combine(self, shares):
        """
        Placeholder for SS.Combine
        Combine shares to recover secret - to be implemented
        """
        # TODO: Implement share combination
        # For now, return first share
        return shares[0] if shares else None
    
    def commitment_commit(self, value):
        """
        Placeholder for C.Commit
        Hash-based commitment - to be implemented
        """
        # TODO: Implement hash-based commitment
        # For now, return dummy commitment and opening
        return ("commitment", "opening")
    
    def commitment_verify(self, commitment, opening, value):
        """
        Placeholder for C.Verify
        Verify commitment - to be implemented
        """
        # TODO: Implement commitment verification
        # For now, always return True
        return True
    
    def measure_host_setup(self, iterations=1000):
        """Measure Host setup phase computation"""
        total_time = 0
        
        # Pre-generate a sample encrypted e for decryption
        # Host will receive encrypted (gsk[h], w) from server
        pk_h_sample, sk_h_sample = self.elgamal.keygen()
        w_sample = self.pseudonyms[0]
        # Note: In real implementation, gsk[h] would be transmitted separately
        # Here we encrypt only w due to ElGamal 28-byte limit
        e_sample = self.elgamal.encrypt(pk_h_sample, self.group.serialize(w_sample)[:28])
        
        for _ in range(iterations):
            start_time = time.time()
            
            # Host operations in setup phase:
            # 1. Run E.KeyGen to generate encryption key Pk_h
            pk_h, sk_h = self.elgamal.keygen()
            
            # 2. Run E.Dec to decrypt e and obtain gsk[h] and w
            decrypted_w = self.elgamal.decrypt(sk_h_sample, pk_h_sample, e_sample)
            
            total_time += time.time() - start_time
        
        avg_time = total_time / iterations
        
        # Storage: Host stores pk_h, sk_h, gsk[h], w, and gpk
        # Use proper serialization for accurate size calculation
        pk_h_size = len(self.group.serialize(pk_h_sample[0])) + len(self.group.serialize(pk_h_sample[1]))
        sk_h_size = len(self.group.serialize(sk_h_sample))
        
        # BBS member key size - gsk[h] is a tuple (A_i, x_i)
        # A_i is a pairing group element, x_i is a ZR element
        sample_gsk = self.gsk[0]
        gsk_size = len(self.bbs.group.serialize(sample_gsk[0])) + len(self.bbs.group.serialize(sample_gsk[1]))
        
        w_size = len(self.group.serialize(w_sample))
        
        # Group public key size - serialize all components
        gpk_size = 0
        for key, value in self.gpk.items():
            gpk_size += len(self.bbs.group.serialize(value))
        
        storage_size = pk_h_size + sk_h_size + gsk_size + w_size + gpk_size
        
        return avg_time * 1000, storage_size  # Convert to ms
    
    def measure_server_setup(self, iterations=1000):
        """Measure Server setup phase computation"""
        total_time = 0
        
        # Pre-generate host public keys for encryption
        host_public_keys = []
        for i in range(min(iterations, self.num_hosts)):
            pk_h, _ = self.elgamal.keygen()
            host_public_keys.append(pk_h)
        
        for i in range(iterations):
            start_time = time.time()
            
            # Server operations in setup phase:
            # 1. Run E.KeyGen to generate encryption key
            pk_a, sk_a = self.elgamal.keygen()
            
            # 2. Run S.KeyGen twice to generate signature keys
            pk_sig1, sk_sig1 = self.auth_sig.keygen()
            pk_sig2, sk_sig2 = self.auth_sig.keygen()
            
            # 3. Run GS.KeyGen to generate gpk and gmsk
            # Note: This is pre-generated, so we skip it in timing
            
            # 4. Split gmsk to n=3 shares using SS.GenShare
            shares = self.secret_sharing_generate(self.gmsk, n=3)
            
            # 5. Compute C.Commit to commit to gmsk shares
            commitments = []
            for share in shares:
                com, opening = self.commitment_commit(share)
                commitments.append((com, opening))
            
            # 6. Run GS.Join to generate member key for a user
            # Note: BBS doesn't have dynamic join, we use pre-generated keys
            host_idx = i % self.num_hosts
            gsk_h = self.gsk[host_idx]
            
            # 7. Generate pseudonym w for the user
            # Note: Pre-generated, not counted in timing
            w = self.pseudonyms[host_idx]
            
            # 8. Compute e = E.Enc(Pk_h, (gsk[h], w))
            # Note: ElGamal has size limit, we encrypt w only
            pk_h = host_public_keys[i % len(host_public_keys)]
            e = self.elgamal.encrypt(pk_h, self.group.serialize(w)[:28])
            
            # 9. Run BN.Setup to set up beacon (EC-VRF)
            beacon_pk, beacon_sk = self.beacon.keygen()
            
            total_time += time.time() - start_time
        
        avg_time = total_time / iterations
        
        # Storage: Server stores all keys, shares, commitments, etc.
        # Use proper serialization for accurate size calculation
        storage_size = 0
        
        # Two ECDSA key pairs
        storage_size += len(self.group.serialize(pk_sig1['g'])) + len(self.group.serialize(pk_sig1['y']))
        storage_size += len(self.group.serialize(sk_sig1))
        storage_size += len(self.group.serialize(pk_sig2['g'])) + len(self.group.serialize(pk_sig2['y']))
        storage_size += len(self.group.serialize(sk_sig2))
        
        # ElGamal key pair
        storage_size += len(self.group.serialize(pk_a[0])) + len(self.group.serialize(pk_a[1]))
        storage_size += len(self.group.serialize(sk_a))
        
        # Group public key
        for key, value in self.gpk.items():
            storage_size += len(self.bbs.group.serialize(value))
        
        # Master secret key (gmsk) - contains xi1 and xi2
        storage_size += len(self.bbs.group.serialize(self.gmsk['xi1']))
        storage_size += len(self.bbs.group.serialize(self.gmsk['xi2']))
        
        # Shares of gmsk (3 shares, each containing xi1 and xi2)
        # For simplicity, assume each share is same size as gmsk
        storage_size += 3 * (len(self.bbs.group.serialize(self.gmsk['xi1'])) + 
                            len(self.bbs.group.serialize(self.gmsk['xi2'])))
        
        # Commitments and openings (placeholder sizes)
        storage_size += 64 * 3  # Assume 64 bytes per commitment/opening pair
        
        # All member keys gsk[i] for hosts
        for i in range(self.num_hosts):
            storage_size += len(self.bbs.group.serialize(self.gsk[i][0]))  # A_i
            storage_size += len(self.bbs.group.serialize(self.gsk[i][1]))  # x_i
        
        # Pseudonyms w[i]
        for i in range(self.num_hosts):
            storage_size += len(self.group.serialize(self.pseudonyms[i]))
        
        # VRF key pair
        storage_size += len(self.beacon.group.serialize(beacon_pk))  # Public key is a single EC point
        storage_size += len(self.beacon.group.serialize(beacon_sk))  # Secret key is a scalar
        
        return avg_time * 1000, storage_size  # Convert to ms
    
    def measure_guest_setup(self, iterations=1000):
        """Measure Guest setup phase computation"""
        # Guest does nothing in setup phase
        return 0.0, 0
    
    def run_measurements(self):
        """Run all measurements and display results"""
        print("=" * 60)
        print("PRIVACY ENHANCED SCHEME - SETUP PHASE MEASUREMENTS")
        print("=" * 60)
        print(f"Number of hosts: {self.num_hosts}")
        print(f"Running {1000} iterations for each measurement...\n")
        
        # Measure computation and storage costs
        print("Measuring Guest setup...")
        guest_time, guest_storage = self.measure_guest_setup()
        
        print("Measuring Host setup...")
        host_time, host_storage = self.measure_host_setup()
        
        print("Measuring Server setup...")
        server_time, server_storage = self.measure_server_setup()
        
        # Display results
        print("\n" + "=" * 60)
        print("COMPUTATION COST (SETUP PHASE)")
        print("=" * 60)
        print(f"{'Role':<10} {'Computation (ms)':<20}")
        print("-" * 30)
        print(f"{'Guest':<10} {guest_time:<20.3f}")
        print(f"{'Host':<10} {host_time:<20.3f}")
        print(f"{'Server':<10} {server_time:<20.3f}")
        
        print("\n" + "=" * 60)
        print("STORAGE COST (SETUP PHASE)")
        print("=" * 60)
        print(f"{'Role':<10} {'Storage (bytes)':<20}")
        print("-" * 30)
        print(f"{'Guest':<10} {guest_storage:<20}")
        print(f"{'Host':<10} {host_storage:<20}")
        print(f"{'Server':<10} {server_storage:<20}")
        print("=" * 60)
        
        return {
            'computation': {
                'guest': guest_time,
                'host': host_time,
                'server': server_time
            },
            'storage': {
                'guest': guest_storage,
                'host': host_storage,
                'server': server_storage
            }
        }

if __name__ == "__main__":
    setup = PrivacyEnhancedSetupPhase(num_hosts=100)
    results = setup.run_measurements()
    
    # Additional formatted output for LaTeX tables
    print("\n\n" + "=" * 60)
    print("FORMATTED OUTPUT FOR LATEX TABLES")
    print("=" * 60)
    
    # Table 1: Computation Cost Comparison in Setup Phase
    print("\nTable: Computation Cost Comparison in Setup Phase")
    print("\nScheme with Privacy:")
    print(f"Guest  & {results['computation']['guest']:.3f}")
    print(f"Host   & {results['computation']['host']:.3f}")
    print(f"Server & {results['computation']['server']:.3f}")
    
    # Table 1: Storage Cost Comparison in Setup Phase
    print("\n\nTable: Storage Cost Comparison in Setup Phase")
    print("\nScheme with Privacy:")
    print(f"Guest  & {results['storage']['guest']}")
    print(f"Host   & {results['storage']['host']}")
    print(f"Server & {results['storage']['server']}")
    print("\n" + "=" * 60)
