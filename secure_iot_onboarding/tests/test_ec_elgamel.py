import pytest
from secure_iot_onboarding.schemes.ec_elgamel import ECElGamal
from charm.toolbox.eccurve import secp256k1

@pytest.fixture
def ec_elgamal():
    return ECElGamal(curve=secp256k1)

def test_basic_encryption(ec_elgamal):
    pk, sk = ec_elgamal.keygen()
    message = b"Hello, EC ElGamal!"  # 18 bytes
    ciphertext = ec_elgamal.encrypt(pk, message)
    decrypted = ec_elgamal.decrypt(sk, pk, ciphertext)
    assert decrypted == message

def test_different_messages(ec_elgamal):
    pk, sk = ec_elgamal.keygen()
    messages = [
        b"Short",           # 5 bytes
        b"A" * 27,         # 27 bytes
        b"B" * 28          # 28 bytes
    ]
    for msg in messages:
        ciphertext = ec_elgamal.encrypt(pk, msg)
        decrypted = ec_elgamal.decrypt(sk, pk, ciphertext)
        assert decrypted == msg

def test_different_key_pairs(ec_elgamal):
    pk1, sk1 = ec_elgamal.keygen()
    pk2, sk2 = ec_elgamal.keygen()
    message = b"Test diff keys"  # 13 bytes
    ciphertext = ec_elgamal.encrypt(pk1, message)
    # Should decrypt correctly with correct key
    decrypted = ec_elgamal.decrypt(sk1, pk1, ciphertext)
    assert decrypted == message
    # Should not decrypt correctly with wrong key
    wrong_decrypted = ec_elgamal.decrypt(sk2, pk2, ciphertext)
    assert wrong_decrypted != message 