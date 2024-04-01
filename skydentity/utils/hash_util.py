from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def hash_public_key(public_key) -> str:
    """
    Hashes a public key bitstring.
    :param public_key: The public key to hash.
    :return: The hashed public key.
    """
    return SHA256.new(data=public_key).hexdigest()

def hash_public_key_from_file(public_key_file: str) -> str:
    """
    Hashes a public key from a file.
    :param public_key: The path of the public key file to hash.
    :return: The hashed public key.
    """
    with open(public_key_file, "rb") as f:
        data = f.read()
        public_key = RSA.import_key(data)
        print("Public key from file:", public_key.export_key())
        public_key_bytes = public_key.export_key()
        return hash_public_key(public_key_bytes)
        #return SHA256.new(data=public_key_bytes).hexdigest()