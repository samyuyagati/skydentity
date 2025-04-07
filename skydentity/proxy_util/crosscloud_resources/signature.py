from collections import namedtuple

from Crypto.PublicKey import RSA

KeyPair = namedtuple("KeyPair", ["public_key", "private_key"])


def generate_vm_keypair() -> KeyPair:
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()

    return KeyPair(public_key=public_key, private_key=private_key)
