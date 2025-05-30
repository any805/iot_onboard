import pytest
from secure_iot_onboarding.schemes.ecvrf import ECVRF

@pytest.fixture
def vrf():
    """Create a VRF instance for testing"""
    return ECVRF()

def test_keygen(vrf):
    """Test key generation"""
    pk, sk = vrf.keygen()
    assert pk is not None
    assert sk is not None
    # Check if public key is valid
    try:
        vrf.group.coordinates(pk)
    except:
        pytest.fail("Generated invalid public key")

def test_prove(vrf):
    """Test proof generation"""
    pk, sk = vrf.keygen()
    alpha = b"test input"
    proof = vrf.prove(sk, alpha)
    assert proof is not None
    assert len(proof) == 3
    gamma, c, s = proof
    # Check if gamma is valid
    try:
        vrf.group.coordinates(gamma)
    except:
        pytest.fail("Generated invalid gamma point")

def test_verify_valid_proof(vrf):
    """Test verification of valid proof"""
    pk, sk = vrf.keygen()
    alpha = b"test input"
    proof = vrf.prove(sk, alpha)
    valid, randomness = vrf.verify(pk, alpha, proof)
    assert valid
    assert randomness is not None
    assert len(randomness) == 32  # SHA-256 output length

def test_verify_invalid_proof(vrf):
    """Test verification of invalid proof"""
    pk, sk = vrf.keygen()
    alpha = b"test input"
    proof = vrf.prove(sk, alpha)
    # Modify proof to make it invalid
    gamma, c, s = proof
    invalid_proof = (gamma, c, s + 1)  # Modify s value
    valid, randomness = vrf.verify(pk, alpha, invalid_proof)
    assert not valid
    assert randomness is None

def test_verify_wrong_input(vrf):
    """Test verification with wrong input"""
    pk, sk = vrf.keygen()
    alpha = b"test input"
    proof = vrf.prove(sk, alpha)
    wrong_alpha = b"wrong input"
    valid, randomness = vrf.verify(pk, wrong_alpha, proof)
    assert not valid
    assert randomness is None

def test_verify_wrong_key(vrf):
    """Test verification with wrong public key"""
    pk1, sk1 = vrf.keygen()
    pk2, sk2 = vrf.keygen()  # Generate different key pair
    alpha = b"test input"
    proof = vrf.prove(sk1, alpha)
    valid, randomness = vrf.verify(pk2, alpha, proof)  # Use wrong public key
    assert not valid
    assert randomness is None

def test_randomness_uniqueness(vrf):
    """Test that different inputs produce different randomness"""
    pk, sk = vrf.keygen()
    alpha1 = b"input 1"
    alpha2 = b"input 2"
    _, randomness1 = vrf.verify(pk, alpha1, vrf.prove(sk, alpha1))
    _, randomness2 = vrf.verify(pk, alpha2, vrf.prove(sk, alpha2))
    assert randomness1 != randomness2

def test_randomness_consistency(vrf):
    """Test that same input produces same randomness"""
    pk, sk = vrf.keygen()
    alpha = b"test input"
    _, randomness1 = vrf.verify(pk, alpha, vrf.prove(sk, alpha))
    _, randomness2 = vrf.verify(pk, alpha, vrf.prove(sk, alpha))
    assert randomness1 == randomness2

def test_encode_to_curve(vrf):
    """Test point encoding to curve"""
    alpha = b"test input"
    H = vrf.encode_to_curve(alpha)
    # Check if H is valid
    try:
        vrf.group.coordinates(H)
    except:
        pytest.fail("Generated invalid point on curve")
