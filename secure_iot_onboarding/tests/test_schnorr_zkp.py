import pytest
from secure_iot_onboarding.schemes.schnorr_zkp import SchnorrZKP
from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import secp256k1

@pytest.fixture
def zkp():
    return SchnorrZKP(curve=secp256k1)

def test_init(zkp):
    """Test initialization"""
    assert zkp.group is not None
    assert zkp.G is not None
    assert zkp.pk is None
    assert zkp.sk is None
    assert zkp.pk_prime is None
    assert zkp.r is None

def test_keygen(zkp):
    """Test key generation"""
    G, pk, sk = zkp.keygen()
    assert G is not None
    assert pk is not None
    assert sk is not None
    assert pk == zkp.G ** sk

def test_rerandomize(zkp):
    """Test key rerandomization"""
    # Generate original key pair
    G, pk, sk = zkp.keygen()
    
    # Rerandomize with specific r
    r = zkp.group.random(ZR)
    G_prime, pk_prime, r_used = zkp.rerandomize(r)
    
    # Verify r was used correctly
    assert r_used == r
    assert pk_prime == pk * (G ** r)  # Changed from pk + (G ** r)

def test_prove(zkp):
    """Test proof generation"""
    # Generate and rerandomize keys
    G, pk, sk = zkp.keygen()
    G_prime, pk_prime, r = zkp.rerandomize()
    
    # Generate proof
    proof = zkp.prove()
    assert len(proof) == 4
    A, B, d1, d2 = proof
    assert A is not None
    assert B is not None
    assert d1 is not None
    assert d2 is not None

def test_prove_and_verify(zkp):
    """Test proof generation and verification"""
    # Generate and rerandomize keys
    G, pk, sk = zkp.keygen()
    G_prime, pk_prime, r = zkp.rerandomize()
    
    # Generate proof
    proof = zkp.prove()
    A, B, d1, d2 = proof
    
    # Verify proof
    assert zkp.verify(proof)
    
    # Verify proof components
    c = zkp.group.hash((G, pk, pk_prime, A, B))
    assert G ** d1 == A * ((pk_prime / pk) ** c)  # Changed from A + (c * (pk_prime - pk))
    assert G ** d2 == B * (pk ** c)  # Changed from B + (c * pk)

def test_verify_invalid_proof(zkp):
    """Test verification of invalid proof"""
    # Generate and rerandomize keys
    G, pk, sk = zkp.keygen()
    G_prime, pk_prime, r = zkp.rerandomize()
    
    # Generate valid proof
    proof = zkp.prove()
    A, B, d1, d2 = proof
    
    # Modify proof to make it invalid
    invalid_proof = (A, B, d1 + 1, d2)  # Change d1
    
    # Verify that invalid proof fails
    assert not zkp.verify(invalid_proof)

def test_verify_fail_wrong_sk(zkp):
    """Test verification fails with wrong sk"""
    # Generate and rerandomize keys
    G, pk, sk = zkp.keygen()
    G_prime, pk_prime, r = zkp.rerandomize()
    
    # Generate proof with wrong sk
    zkp.sk = zkp.group.random(ZR)  # Change sk
    proof = zkp.prove()
    
    # Verification should fail
    assert not zkp.verify(proof)

def test_verify_fail_wrong_r(zkp):
    """Test verification fails with wrong r"""
    # Generate and rerandomize keys
    G, pk, sk = zkp.keygen()
    G_prime, pk_prime, r = zkp.rerandomize()
    
    # Generate proof with wrong r
    zkp.r = zkp.group.random(ZR)  # Change r
    proof = zkp.prove()
    
    # Verification should fail
    assert not zkp.verify(proof)

def test_verify_fail_tampered_proof(zkp):
    """Test verification fails with tampered proof"""
    # Generate and rerandomize keys
    G, pk, sk = zkp.keygen()
    G_prime, pk_prime, r = zkp.rerandomize()
    
    # Generate valid proof
    proof = zkp.prove()
    A, B, d1, d2 = proof
    
    # Tamper with proof components
    tampered_proofs = [
        (A, B, d1 + 1, d2),  # Tamper with d1
        (A, B, d1, d2 + 1),  # Tamper with d2
        (A, G ** zkp.group.random(ZR), d1, d2),  # Tamper with B
        (G ** zkp.group.random(ZR), B, d1, d2),  # Tamper with A
    ]
    
    # All tampered proofs should fail verification
    for tampered_proof in tampered_proofs:
        assert not zkp.verify(tampered_proof)
