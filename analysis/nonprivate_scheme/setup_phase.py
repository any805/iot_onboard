"""
Nonprivate Scheme - Setup Phase Implementation
Measures computation time and storage requirements for each role
"""

import time
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from secure_iot_onboarding.schemes.ecdsa import ECDSASig
from secure_iot_onboarding.schemes.ecvrf import ECVRF
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import secp256k1

class NonprivateSetupPhase:
    def __init__(self):
        self.group = ECGroup(secp256k1)
        
    def measure_host_setup(self, iterations=1000):
        """Measure Host setup phase: Generate ECDSA key pair"""
        # Storage measurements
        storage_size = 0
        
        # Timing measurements
        total_time = 0
        
        for _ in range(iterations):
            start_time = time.time()
            
            # Host: Run S.KeyGen to generate signature key pair
            host_sig = ECDSASig()
            pk_h, sk_h = host_sig.keygen()
            
            total_time += time.time() - start_time
            
            # Measure storage on first iteration
            if storage_size == 0:
                # Public key storage: g + y (2 EC points)
                pk_h_size = len(self.group.serialize(pk_h['g'])) + len(self.group.serialize(pk_h['y']))
                # Private key storage: 1 scalar
                sk_h_size = len(self.group.serialize(sk_h))
                storage_size = pk_h_size + sk_h_size
        
        avg_time = total_time / iterations
        return avg_time * 1000, storage_size  # Convert to ms
    
    def measure_guest_setup(self, iterations=1000):
        """Measure Guest setup phase: Does nothing"""
        # Guest does nothing in setup phase
        return 0.0, 0
    
    def measure_server_setup(self, iterations=1000):
        """Measure Server setup phase: Generate 2 ECDSA pairs + VRF setup"""
        # Storage measurements
        storage_size = 0
        
        # Timing measurements
        total_time = 0
        
        for _ in range(iterations):
            start_time = time.time()
            
            # Server: Run S.KeyGen twice for signature keys
            auth_sig = ECDSASig()
            pk_a, sk_a = auth_sig.keygen()
            
            mgmt_sig = ECDSASig()
            pk_m, sk_m = mgmt_sig.keygen()
            
            # Server: Run BN.Setup to set up beacon (EC-VRF)
            beacon = ECVRF()
            beacon_pk, beacon_sk = beacon.keygen()
            
            total_time += time.time() - start_time
            
            # Measure storage on first iteration
            if storage_size == 0:
                # Auth server keys
                pk_a_size = len(self.group.serialize(pk_a['g'])) + len(self.group.serialize(pk_a['y']))
                sk_a_size = len(self.group.serialize(sk_a))
                
                # Management server keys
                pk_m_size = len(self.group.serialize(pk_m['g'])) + len(self.group.serialize(pk_m['y']))
                sk_m_size = len(self.group.serialize(sk_m))
                
                # Beacon (VRF) keys
                beacon_pk_size = len(self.group.serialize(beacon_pk))
                beacon_sk_size = len(self.group.serialize(beacon_sk))
                
                storage_size = (pk_a_size + sk_a_size + 
                               pk_m_size + sk_m_size + 
                               beacon_pk_size + beacon_sk_size)
        
        avg_time = total_time / iterations
        return avg_time * 1000, storage_size  # Convert to ms
    
    def run_measurements(self):
        """Run all measurements and display results"""
        print("=" * 60)
        print("NONPRIVATE SCHEME - SETUP PHASE MEASUREMENTS")
        print("=" * 60)
        print(f"Running {1000} iterations for each measurement...\n")
        
        # Measure each role
        print("Measuring Host setup...")
        host_time, host_storage = self.measure_host_setup()
        
        print("Measuring Guest setup...")
        guest_time, guest_storage = self.measure_guest_setup()
        
        print("Measuring Server setup...")
        server_time, server_storage = self.measure_server_setup()
        
        # Display results in table format
        print("\n" + "=" * 60)
        print("SETUP PHASE RESULTS")
        print("=" * 60)
        print(f"{'Role':<10} {'Computation (ms)':<20} {'Storage (bytes)':<20}")
        print("-" * 50)
        print(f"{'Guest':<10} {guest_time:<20.3f} {guest_storage:<20}")
        print(f"{'Host':<10} {host_time:<20.3f} {host_storage:<20}")
        print(f"{'Server':<10} {server_time:<20.3f} {server_storage:<20}")
        print("=" * 60)
        
        return {
            'guest': {'time': guest_time, 'storage': guest_storage},
            'host': {'time': host_time, 'storage': host_storage},
            'server': {'time': server_time, 'storage': server_storage}
        }

if __name__ == "__main__":
    setup = NonprivateSetupPhase()
    results = setup.run_measurements()
    
    # Additional formatted output for LaTeX tables
    print("\n\n" + "=" * 60)
    print("FORMATTED OUTPUT FOR LATEX TABLE")
    print("=" * 60)
    print("\nTable: Computation and Storage Cost Comparison in Setup Phase")
    print("\nScheme w/o Privacy:")
    print(f"Guest  & {results['guest']['time']:.3f} & {results['guest']['storage']}")
    print(f"Host   & {results['host']['time']:.3f} & {results['host']['storage']}")
    print(f"Server & {results['server']['time']:.3f} & {results['server']['storage']}")
    print("\n" + "=" * 60)
