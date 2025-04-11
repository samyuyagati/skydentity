import base64
import json
from dataclasses import dataclass

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


@dataclass
class KeyPair:
    public_key: RSA.RsaKey
    private_key: RSA.RsaKey


def generate_vm_keypair() -> KeyPair:
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()

    return KeyPair(public_key=public_key, private_key=private_key)


def export_key(key: RSA.RsaKey) -> str:
    """
    Standardized export key function for RSA keys.

    Returns the key exported as a PEM format.
    The string can be encoded into bytes as required.
    """
    return key.export_key(format="PEM").decode("utf-8")


@dataclass
class SignatureContent:
    vm_id: str
    source_cloud: str
    dest_cloud: str
    timestamp: str

    def to_dict(self):
        return {
            "vm_id": self.vm_id,
            "source_cloud": self.source_cloud,
            "dest_cloud": self.dest_cloud,
            "timestamp": self.timestamp,
        }


def validate_signature(
    base64_signature: bytes,
    signature_content: SignatureContent,
    public_key_bytes: bytes,
) -> bool:
    public_key = RSA.import_key(public_key_bytes)

    # serialize and hash the intended signature content
    signature_content_bytes = json.dumps(
        signature_content.to_dict(), sort_keys=True
    ).encode("utf-8")
    signature_content_hash = SHA256.new(signature_content_bytes)

    # b64-decode the signature
    signature = base64.b64decode(base64_signature)

    try:
        pkcs1_15.new(public_key).verify(signature_content_hash, signature)
    except ValueError:
        # invalid signature
        return False

    # verification passed; valid signature
    return True
