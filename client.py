from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import socket as sock
import select
from config import config
from helpers import *
import sys
import logging
import atexit

logging.basicConfig()
logger = logging.getLogger('chat-client')
logger.setLevel(logging.DEBUG)

ADDR_BOOK = {}  # holds addr tuples for all comms
KEYCHAIN = {}  # holds keys
BUF_SIZE = 2048
LOGIN = {}
NONCE_SIZE = 16  # bytes


def init():
    global _SOCK, LISTENABLES, SADDR
    _SOCK = sock.socket(type=sock.SOCK_DGRAM)
    _SOCK.bind(('', 0))

    with open(config['server_pub_file']) as f:
        try:
            KEYCHAIN['server_pub'] = parse_public_key(f.read())
        except:
            logger.error("Couldn't read private key from file: {}".format(e))

    # eventually read from a config file:
    ADDR_BOOK['server'] = (config['server_ip'], config['server_port'])

    LISTENABLES = [sys.stdin, _SOCK]


def send_data_to(data, addr):
    _SOCK.sendto(data, addr)


def do_logout():
    # do_logout() triggered by sys.exit(0) ->
    # don't need to exit here.
    print "LOGGING OUT! GOODBYE!"


def connect():
    # client attempts to connect to server
    """
    Client to Server LOGIN protocol handler
    """
    # logout at exit
    atexit.register(do_logout)

    msg = jdump({'kind': 'LOGIN', 'context': 'INIT', })
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
    LOGIN['nonce'] = nonce(NONCE_SIZE)
    LOGIN['username'] = username
    return {
        "username": username,
        # obviously have to hash this.
        "password_hash": password,
        "nonce_user": LOGIN['nonce'],  #"public_key": KEYCHAIN['public_bytes']
    }


def handle_login_cookie(msg):
    # TODO: validate cookie message
    LOGIN['cookie'] = msg['cookie']

    # WE NEED TO SEND COOKIE,

    data = get_login_submit_payload(msg)
    payload = rsa_encrypt(KEYCHAIN['server_pub'], jdump(data))
    public_key = rsa_encrypt(KEYCHAIN['server_pub'], KEYCHAIN['public_bytes'])

    resp = jdump({
        'kind': 'LOGIN',
        'context': 'SUBMIT',
        'cookie': LOGIN['cookie'],
        'public_key': pdump(public_key),
        'payload': pdump(payload),
    })

    send_data_to(resp, ADDR_BOOK['server'])


def handle_login_challenge(msg):
    logger.debug("Rec'd Login Challenge")
    challenge = jload(rsa_decrypt(KEYCHAIN['private'], pload(msg['payload'])))

    logger.debug("CHALLENGE IS: {}".format(challenge))

    # TODO: CHECK THIS IF VALID CHALLENGE ->
    if challenge['user_nonce'] != LOGIN['nonce']:
        logger.debug("Invalid nonce in challenge")
        return

    if challenge['username'] != LOGIN['username']:
        logger.debug('Invalid username in challenge')
        return

    iv = msg['init_vector'].decode('base64')

    KEYCHAIN['init_vector'] = iv
    KEYCHAIN['session'] = challenge.get('session_key').decode('base64')

    # else we can respond to the challenge.
    logger.debug("SERVER NONCE RECEIVED: {}".format(
        challenge['server_nonce'].format('base64')))

    answer = aes_encrypt(KEYCHAIN['session'], iv, challenge['server_nonce'])

    resp = jdump({
        'kind': 'LOGIN',
        'context': 'RESPONSE',
        'cookie': LOGIN['cookie'],
        'payload': pdump(answer),
    })

    send_data_to(resp, ADDR_BOOK['server'])

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
    # If a server sends us a logout message
    # it should be because we requested a logout.
    logger.debug("RECEIVED LOGOUT MESSAGE...")

    enc_payload = msg.get('')
    enc_logout_resp = pload(msg['payload'])
    dec_logout_resp = jload(aes_decrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
                                enc_logout_resp))
    if dec_logout_resp.get('nonce_user') == LOGIN['nonce_user_logout']:
        # tell server we're logging out.

        answer = jdump({'nonce_user': LOGIN['nonce_user_logout']})

        payload = pdump(aes_encrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
            answer))

        resp = jdump({
            'kind': 'LOGOUT',
            'context': 'fin',
            'cookie': LOGIN['cookie'],
            'payload': payload,
        })
        send_data_to(resp, ADDR_BOOK['server'])

        # then do it.
        # the exit is caught by the atexit.register()
        # function, so we don't need to handle any cases here.
        sys.exit(0)
    else:
        logger.debug("Invalid logout nonce, not logging out")


def list_handler(msg):
    # validate the nonce we created when sending is good
    enc_list_resp = pload(msg['payload'])
    dec_list_resp = aes_decrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
                                enc_list_resp)
    list_response = jload(dec_list_resp)

    logger.debug("LIST RESPONE IS: {}".format(list_response))

    if list_response['nonce_user'] != LOGIN['nonce_user_list']:
        logger.debug("INVALID LIST RESPONSE!!")
        return

    user_list = list_response['list']
    print "Users currently logged in are: "
    for username in user_list:
        print username


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
        msg = jload(raw_msg)
        logger.debug("RECD MESSAGE: {}".format(msg))
    except Exception as e:
        print "[ERROR]: {}".format(e)
    # TODO: VALIDATE MESSAGE HERE
    handler = socket_handlers[msg.get('kind')]
    handler(msg)


def list_request(*args):
    # user requested a "LIST"
    # TODO VALIDATE CONNECTED, VALIDATE HAVE KEYS

    # create new LIST nonce to be checked on list receive
    # to guarantee freshness
    LOGIN['nonce_user_list'] = nonce(NONCE_SIZE)
    logger.debug("SETTING LIST NONCE: {}".format(LOGIN['nonce_user_list']))

    data = {
        'username': LOGIN['username'],
        'nonce_user': LOGIN['nonce_user_list'],
    }

    payload = aes_encrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
                          jdump(data))

    req = jdump({
        'kind': 'LIST',
        'cookie': LOGIN['cookie'],
        'payload': pdump(payload)
    })

    send_data_to(req, ADDR_BOOK['server'])


def logout_request(*args):
    # user requests to log out from server:

    # reset logout nonce
    LOGIN['nonce_user_logout'] = nonce(NONCE_SIZE)

    data = {
        'username': LOGIN['username'],
        'nonce_user': LOGIN['nonce_user_logout'],
    }

    payload = aes_encrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
                      jdump(data))

    req = jdump({
        'kind': 'LOGOUT',
        'context': 'init',
        'cookie': LOGIN['cookie'],
        'payload': pdump(payload),
    })

    send_data_to(req, ADDR_BOOK['server'])


def invite_request(*args):
    pass

# special messages from user and their handlers:
user_protocols = {
        '@LIST': list_request, 
        '@INVITE': invite_request, 
        '@LOGOUT': logout_request,
    }


def handle_stdin_event():
    text = sys.stdin.readline()
    if any(text.startswith(p) for p in user_protocols.keys()):
        handler = user_protocols[text.rstrip()]
        handler(text)
    else:
        logger.debug("[CHAT INPUT]: {}".format(text))


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
