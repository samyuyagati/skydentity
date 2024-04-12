from Crypto.PublicKey import RSA

private_key = RSA.generate(3072)
with open("keys/private.pem", "wb") as f:
    # Note: the private key is written in plaintext. This should be used only
    # for testing purposes. Your real private key should be password protected.
    data = private_key.export_key()
    f.write(data)
with open("keys/public.pem", "wb") as f:
    data = private_key.public_key().export_key()
    f.write(data)
