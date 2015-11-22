from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYCHAIN = {}


def connect():
    # client attempts to connect to server
    pass


def make_keys():
    # Client generates an in memory public/private key pair 
    # for this session (Kuser_priv, Kuser_pub) [RSA, 2048]
    KEYCHAIN['private'] = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    KEYCHAIN['public'] = KEYCHAIN['private'].public_key()


def handle_invite(*args):
    pass


def handle_message(*args):
    pass

# a handler for each valid message type received
handlers = {'INVITE': handle_invite, 'MESSAGE': handle_message, }


def main():
    make_keys()
    connect()


if __name__ == '__main__':
    main()
