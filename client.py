from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import socket as sock
import select
from config import config
from helpers import dump, load, nonce
import sys
import logging
import getpass

logging.basicConfig()
logger = logging.getLogger('chat-server')
logger.setLevel(logging.DEBUG)

ADDR_BOOK = {} # holds addr tuples for all comms
KEYCHAIN = {} # holds keys
BUF_SIZE = 2048
LOGIN = {}

def init():
    global _SOCK, LISTENABLES, SADDR
    _SOCK = sock.socket(type=sock.SOCK_DGRAM)
    _SOCK.bind(('', 0))

    # eventually read from a config file:
    ADDR_BOOK['server'] = (config['server_ip'], config['server_port'])

    LISTENABLES = [sys.stdin, _SOCK]


def send_data_to(data, addr):
    _SOCK.sendto(data, addr)


def connect():
    # client attempts to connect to server
    """
    Client to Server LOGIN protocol handler
    """
    msg = dump({
        'kind': 'LOGIN',
        'context': 'INIT',
    })
    # need some identifying information here?
    send_data_to(msg, ADDR_BOOK['server'])


def make_keys():
    # Client generates an in memory public/private key pair
    # for this session (Kuser_priv, Kuser_pub) [RSA, 2048]
    KEYCHAIN['private'] = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    KEYCHAIN['public'] = KEYCHAIN['private'].public_key()
    KEYCHAIN['public_bytes'] = KEYCHAIN['public'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)


def handle_invite(*args):
    pass


def handle_message(*args):
    pass

def get_login_submit_payload(msg):
    #{UN, Nu, hash(PWD), Kuser_pub}Kserv_pub
    username = raw_input('Username:')
    password = raw_input('Password:')
    return {
        "username": username,
        # obviously have to hash this.
        "password": password,
        "nonce_user": nonce(32),
        "public_key": KEYCHAIN['public_bytes']
    }

def handle_login_cookie(msg):
    # TODO: validate cookie message
    LOGIN['cookie'] = msg['cookie']

    # WE NEED TO SEND COOKIE, 

    resp = dump({
        'kind': 'LOGIN',
        'context': 'SUBMIT',
        'cookie': LOGIN['cookie'],
        'payload': get_login_submit_payload(msg)
    })

    send_data_to(resp, ADDR_BOOK['server'])

def handle_login_challenge():
    pass

# server inputs:
login_handlers = {
    'cookie': handle_login_cookie,
    'challenge': handle_login_challenge,
}

def login_handler(msg):
    ctx = msg.get('context')
    # TODO: VALIDATE CONTEXT!
    handler = login_handlers[ctx]
    handler(msg)

def logout_handler(msg):
    print "Goodbye..."
    # send logout ack to server?
    sys.exit(0)

def list_handler(msg):
    # validate for empty list or something..
    print msg.get('list')

def connect_handler(msg):
    pass


# a handler for each valid message type received
socket_handlers = {
    # inputs from other clients
    'INVITE': handle_invite,
    'MESSAGE': handle_message,
    # inputs from the server
    'LOGIN': login_handler,
    'LOGOUT': logout_handler,
    'LIST': list_handler,
    'CONNECT': connect_handler
}

def handle_socket_event():
    """
    handler function for socket events
    try's to load the message, else it
    prints an error
    """
    raw_msg = _SOCK.recv(BUF_SIZE)

    try:
        msg = load(raw_msg)
        logger.debug("RECD MESSAGE: {}".format(msg))
    except Exception as e:
        print "[ERROR]: {}".format(e)
    # TODO: VALIDATE MESSAGE HERE
    handler = socket_handlers[msg.get('kind')]
    handler(msg)


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
