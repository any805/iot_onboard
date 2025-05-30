import pytest
from secure_iot_onboarding.schemes.ecdsa import ECDSASig
from charm.toolbox.eccurve import secp256k1

@pytest.fixture
def ecdsa():
    ecdsa = ECDSASig(curve=secp256k1)
    ecdsa.keygen()
    return ecdsa

def test_sign_and_verify(ecdsa):
    message = "Hello, ECDSA!"
    signature = ecdsa.sign(message)
    assert ecdsa.verify(message, signature)

def test_verify_fail(ecdsa):
    message = "Hello, ECDSA!"
    signature = ecdsa.sign(message)
    tampered_signature = signature.copy()
    # Tamper with the 'r' value in the signature
    tampered_signature['r'] = ecdsa.group.random()  # random ZR element
    assert not ecdsa.verify(message, tampered_signature)
