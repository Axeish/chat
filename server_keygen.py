from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

s_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend())

with open('server.private.key', 'w') as f:
    f.write(s_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))

with open('server.public.key', 'w') as f:
    f.write(s_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
