import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from toywallet.keys import KeyPair, generate_private_key
from toywallet.tx import Transaction, memo_hash


@pytest.fixture
def alice():
    return KeyPair(generate_private_key(), "course-testnet")


@pytest.fixture
def bob():
    return KeyPair(generate_private_key(), "course-testnet")


@pytest.fixture
def fixed_alice():
    return KeyPair(ec.derive_private_key(1, ec.SECP256K1()), "course-testnet")


@pytest.fixture
def fixed_bob():
    return KeyPair(ec.derive_private_key(2, ec.SECP256K1()), "course-testnet")


@pytest.fixture
def tx(alice, bob):
    return Transaction(1, "course-testnet", alice.address, bob.address, 1_250_000, 7, memo_hash("rent"))
