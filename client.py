from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import socket
import sys

ADDR_BOOK = {} # holds addr tuples for all comms

def init():
    global _SOCK, LISTENABLES, SADDR
    _SOCK = sock.socket(type=sock.SOCK_DGRAM)
    _SOCK.bind(('', 0))

    # eventually read from a config file:
    ADDR_BOOK['server'] = ('127.0.0.1', 33333)

    LISTENABLES = [sys.stdin, _SOCK]


def send_message_to(to_whom, kind, body, **kwargs):
    data = {'type': kind, 'body': body}
    _SOCK.sendto(json.dumps(data), ADDR_BOOK[to_whom])


def connect():
    # client attempts to connect to server
    """
    Client to Server LOGIN protocol handler
    """
    # need some identifying information here?
    send_message_to('server', 'LOGIN', {'hostname': 'cstiteler@127.0.0.1'})


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


def handle_socket_event():
    pass


def handle_stdin_event():
    _input = sys.stdin.readline()
    pass


def run():
    """
    loops forever, using a python 'select'
    to handle different events by listening on
    stdin AND the socket simultaneously
    """
    sys.stdout.write('+>')
    sys.stdout.flush()
    while True:
        reads, _, __ = select.select(LISTENABLES, [], [])
        for listenable in reads:
            if listenable == _SOCK:
                handle_socket_event()
            else:
                handle_stdin_event()

def main():
    init()
    make_keys()
    connect()
    run()

if __name__ == '__main__':
    main()
