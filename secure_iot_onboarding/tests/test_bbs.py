import pytest
from secure_iot_onboarding.schemes.bbs import BBSGroupSig
from charm.toolbox.pairinggroup import ZR


@pytest.fixture
def bbs():
    bbs = BBSGroupSig()
    bbs.keygen(3)
    return bbs

def test_sign_and_verify(bbs):
    user_idx = 1
    message = "Hello, BBS Group Signature!"
    signature = bbs.sign(user_idx, message)
    assert bbs.verify(message, signature)

def test_verify_fail(bbs):
    user_idx = 1
    message = "Hello, BBS Group Signature!"
    signature = bbs.sign(user_idx, message)
    tampered_signature = signature.copy()
    # Randomly tamper with the challenge field
    tampered_signature['c'] = bbs.group.random(ZR)
    assert not bbs.verify(message, tampered_signature)