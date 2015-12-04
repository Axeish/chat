import os
import sys
import logging
import socket
import json
from config import config
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as padding_asym

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


KEYCHAIN = {}
USERS = {}  # maps uid to User class


class User:
    def __init__(self):
        pass


def parse_private_key(pem_string):
    """
    loads a PEM format private key, not encrypted on disk.
    """
    return serialization.load_pem_private_key(
        pem_string,
        password=None,
        backend=default_backend())


def parse_public_key(pem_string):
    """
    wrapper method for parsing a pem formatted public key
    """
    return serialization.load_pem_public_key(pem_string, default_backend())


def load_server_keys():
    with open('server.public.key') as f:
        keystr = f.read()
        try:
            KEYCHAIN['public'] = parse_public_key(keystr)
        except:
            logger.error("Couldn't read private key from file: {}".format(e))

    with open('server.private.key') as f:
        keystr = f.read()
        try:
            KEYCHAIN['private'] = parse_private_key(keystr)
        except Exception as e:
            logger.error("Couldn't read private key from file: {}".format(e))


def handle_login(*args):
    """
    C -> S: ‘LOGIN’
    S -> C: DoS_cookie (unique cookie that C must possess to auth with S)
    [client prompts user for username (UN) and password (PWD)]
    C -> S: {UN, Nu, hash(PWD), Kuser_pub}Kserv_pub, DoS_cookie

    At this point, the server FIRST checks the IP/Port of C and the SYN COOKIE,
    It then should validate the username (check that user is registered and that the
    user is not already logged in, that the user is not on the "brown-list")
    Therafter the server will check the hash(SALT|PASSWORD) against the stored value.
    If all is well, it generates the Ksession symmetric AES key.

    S -> C: {Ksession, UN, Nu, Ns}Kuser_pub
    C -> S: Ksession{Ns}
    """
    logger.debug("[RECEIVED LOGIN]...")
    print args
    pass


def handle_logout(*args):
    logger.debug("[RECEIVED LOGOUT]...")
    print args
    pass


def handle_list(*args):
    logger.debug("[RECEIVED LIST]...")
    print args


def handle_connect(*args):
    logger.debug("[RECEIVED CONNECT]...")
    print args

# a handler for each valid message type
handlers = {
    'LOGIN': handle_login,
    'LOGOUT': handle_logout,
    'LIST': handle_list,
    'CONNECT': handle_connect,
}


def listen_and_serve():
    logger.debug("starting server...")

    while True:
        raw_msg, sender = _SOCK.recvfrom(_PORT)
        try:
            msg = json.loads(raw_msg)
            assert msg['type'] in handlers.keys()
        except AssertionError:
            logger.error("Invalid message type")
        except Exception as e:
            logger.error("Unable to parse message: {}".format(raw_msg))

        handler = handlers[msg.get('type')]
        handler(msg.get('body'), sender)


def network_init():
    global _PORT
    global _SOCK

    _PORT = config['server_port']

    _SOCK = socket.socket(type=socket.SOCK_DGRAM)
    _SOCK.bind(('', _PORT))

    logger.debug("server initialized on port {}".format(_PORT))


if __name__ == "__main__":
    load_server_keys()
    network_init()
    listen_and_serve()
