from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import socket as sock
import select
from getpass import getpass
from config import config
from helpers import *
import sys
import logging
import atexit
from connection import Connection

logging.basicConfig()
logger = logging.getLogger('chat-client')
logger.setLevel(logging.INFO)

ADDR_BOOK = {}  # holds addr tuples for all comms
KEYCHAIN = {}  # holds keys
BUF_SIZE = 16384  # big enough for our largest json string obj.
MAX_MESSAGE_LENGTH = 256  # characters
LOGIN = {'connections': {}}
NONCE_SIZE = 16  # bytes
connected = False


def init():
    """
    initializes connection to socket, global vars, address book.
    """
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
    """
    wrapper for socket send
    """
    _SOCK.sendto(data, addr)


def do_logout():
    """
    do_logout() triggered by sys.exit(0) ->
    don't need to exit here.
    """
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
    KEYCHAIN['private'] = rsa.generate_private_key(public_exponent=65537,
                                                   key_size=2048,
                                                   backend=default_backend())
    KEYCHAIN['public'] = KEYCHAIN['private'].public_key()
    KEYCHAIN['public_bytes'] = public_bytes(KEYCHAIN['public'])


def get_login_submit_payload(msg):
    """
    generates payload to send for login
    """
    username = raw_input('Username:')
    password = getpass('Password:')
    LOGIN['nonce'] = nonce(NONCE_SIZE)
    LOGIN['username'] = username
    return {
        "username": username,
        "password_hash": password,
        "nonce_user": LOGIN['nonce'],
    }


def handle_login_cookie(msg):
    """
    responds to first message from server upon login request
    """
    try:
        LOGIN['cookie'] = msg['cookie']
    except:
        unknown_error()

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
    """
    responds to server challenge for login
    """
    challenge = jload(rsa_decrypt(KEYCHAIN['private'], pload(msg['payload'])))
    try:
        if challenge['user_nonce'] != LOGIN['nonce']:
            logger.debug("Invalid nonce in challenge")
            return

        if challenge['username'] != LOGIN['username']:
            logger.debug('Invalid username in challenge')
            return
    except:
        unknown_error()

    iv = msg['init_vector'].decode('base64')

    KEYCHAIN['init_vector'] = iv
    KEYCHAIN['session'] = challenge.get('session_key').decode('base64')

    answer = aes_encrypt(KEYCHAIN['session'], iv, challenge['server_nonce'])

    resp = jdump({
        'kind': 'LOGIN',
        'context': 'RESPONSE',
        'cookie': LOGIN['cookie'],
        'payload': pdump(answer),
    })

    send_data_to(resp, ADDR_BOOK['server'])


def handle_invite_init(msg):
    """
    receives the following from another client:
    where the ticket is a ticket to US encrypted with our session
    key from the server.
    """
    payload = msg.get('ticket')
    if not payload:
        return

    # try to decrypt the ticket
    try:
        enc_ticket = pload(payload)
        dec_ticket = aes_decrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
                                 enc_ticket)

        ticket = jload(dec_ticket)

        c = Connection.from_ticket(ticket, LOGIN['username'], _SOCK)
        logger.debug("adding potential connection to {}".format(c.to))
        LOGIN['connections'][c.to] = c
    except:
        unknown_error()

    if not c:
        logger.debug("Couldn't create connection from ticket")
        return
    logger.debug("Successfully made connection from ticket")

    c.respond_to_invite(KEYCHAIN['public_bytes'])


def handle_invite_confirm(msg):
    logger.debug("RECEIVED INVITE CONFIRM...")
    payload = msg.get('payload')
    dec_payload = rsa_decrypt(KEYCHAIN['private'], pload(payload))
    data = jload(dec_payload)

    data = jload(dec_payload)
    logger.debug("DATA IS: {}".format(data))

    to = str(data['to'].rstrip())

    logger.debug("CONNECTIONS ARE: {} TO IS: {}".format(
        LOGIN['connections'].keys(), to))

    c = LOGIN['connections'].get(to)
    if not c:
        unknown_error()
        return

    # setting c.public_key, since we as the inviter, we have to 
    # append it after we receive an invite confirm (public_bytes format)
    c.public_key = msg.get('pub_invitee')

    logger.debug("Set c.public_key as {}".format(c.public_key))

    iv_enc = msg.get('init_vector')

    result = c.confirm_connection(data, iv_enc)
    if result:
        print "Connected to {}. Type '@msg {}: Hello!' to say hi.".format(to,
                                                                          to)

def handle_invite_confirm_ack(msg):
    """
    handles invite ack from other client.
    """
    logger.debug("INVITE CONFIRM ACK RECEIVED...")
    data = pload(msg.get('payload'))
    # decrypt the nonce, look up connection by nonce
    # if it exists, mark it as confirmed
    for to, conn in LOGIN['connections'].items():
        try:
            value = aes_decrypt(conn.session_key, conn.iv, data)
            if value == conn.invitee_nonce:
                conn.confirmed = True
                logger.debug("confirming connection with {}".format(to))
                return
        except:
            logger.debug("confirm_ack not from {}".format(to))
            continue

# server inputs:
invite_handlers = {
    'init': handle_invite_init,
    'confirm': handle_invite_confirm,
    'confirm_ack': handle_invite_confirm_ack,
}


def invite_handler(msg):
    ctx = msg.get('context')
    # TODO: VALIDATE CONTEXT!
    handler = invite_handlers[ctx]
    handler(msg)


def message_handler(msg):
    """
    handler for 'MESSAGE' types on the wire.
    """
    payload = pload(msg.get('payload'))

    conns = [c for c in LOGIN['connections'].values()
            if c.confirmed and c.inviter_nonce == msg.get('inviter_nonce')]
    
    if len(conns) != 1:
        logger.debug("No connection to message")
        return

    conn = conns[0]

    try:
        data = jload(aes_decrypt(conn.session_key, conn.iv, payload))
    except:
        logger.debug("Invalid message from conn: {}".format(conn.to))
        return


    payload_hmac = pload(msg.get('payload_hmac'))
    #logger.debug("PAYLOAD HMAC IS: {}".format(payload_hmac))
    logger.debug("Payload is: {}".format(payload))

    if not check_hmac(parse_public_key(str(conn.public_key)), payload_hmac, bytes(msg.get('payload'))):
        logger.debug("Invalid HMAC for payload, ignoring message")
        return

    if data.get('sender') != conn.to:
        logger.debug("Invalid sender {}".format(data.get('sender')))
        return

    if not validate_client_ts(data.get('timestamp')):
        logger.debug("Timestamp bad on message from {}, ignoring.".format(
            data.get('sender')))
        return

    msg_body = data.get('message')
    print "{}: {}".format(data.get('sender'), msg_body)


def logout_handler(msg):
    # If a server sends us a logout message
    # it should be because we requested a logout.
    logger.debug("RECEIVED LOGOUT MESSAGE...")

    enc_payload = msg.get('')
    enc_logout_resp = pload(msg['payload'])
    dec_logout_resp = jload(aes_decrypt(KEYCHAIN['session'], KEYCHAIN[
        'init_vector'
    ], enc_logout_resp))
    if dec_logout_resp.get('nonce_user') == LOGIN['nonce_user_logout']:
        # tell server we're logging out.

        answer = jdump({'nonce_user': LOGIN['nonce_user_logout']})

        payload = pdump(aes_encrypt(KEYCHAIN['session'], KEYCHAIN[
            'init_vector'
        ], answer))

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
        if username == LOGIN['username']:
            username = "{} (You!)".format(username)
        print "- {}".format(username)

def handle_login_ack(msg):
    payload = pload(msg.get('payload'))
    data = aes_decrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'], payload)
    if data == LOGIN['nonce']:
        logger.debug("Log in confirmed.")
        print "Logged in!"
        print_help()
    else:
        print "There was an error logging into the server, please restart your client and try again"


# server inputs:
login_handlers = {
    'cookie': handle_login_cookie,
    'challenge': handle_login_challenge,
    'ack': handle_login_ack,
}


def login_handler(msg):
    ctx = msg.get('context')
    # TODO: VALIDATE CONTEXT!
    handler = login_handlers[ctx]
    handler(msg)


def connect_handler(msg):
    """
    Checks the connect message against our list of connections
    which include those in progress

    if valid, sends a ticket inviting the user
    """
    enc_conn_resp = pload(msg['payload'])
    dec_conn_resp = aes_decrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
                                enc_conn_resp)

    conn_response = jload(dec_conn_resp)

    to = str(conn_response.get('to').rstrip())
    if not to:
        logger.debug("INVALID 'to' in CONNECT, ignoring")
        return
    # look up connection in LOGIN['connections']
    connection = LOGIN['connections'][to]

    if not connection.validate(conn_response):
        logger.debug("Unable to validate connect request")
        return

    invitation = jdump({
        'kind': 'INVITE',
        'context': 'init',
        'ticket': connection.ticket,
    })

    connection.invite(invitation)


def invite_request(line):
    """
    User is requesting to talk to a user in the list.
    """
    try:
        to = str(line.split(' ', 1)[1].rstrip())
        logger.debug("INIT INVITE -> TO IS {}".format(to))
    except:
        print "Invalid use of '@invite' -> try '@invite username'"
        return

    logger.debug("INVITE REQUEST TO: {}".format(to))
    if to == LOGIN['username']:
        print "You can't invite yourself!"
        return

    connect_nonce = nonce(NONCE_SIZE)
    #logger.debug("SETTING CONNECT NONCE: {}".format(connect_nonce))

    data = {'from': LOGIN['username'], 'to': to, 'nonce_user': connect_nonce, }

    c = Connection(connect_nonce, to, LOGIN['username'], _SOCK)

    if to in LOGIN['connections']:
        # we've already tried to connect to this person
        logger.debug('ALREADY CONNECTED TO: {}'.format(to))
        return
    else:
        LOGIN['connections'][to] = c

    payload = aes_encrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
                          jdump(data))

    req = jdump({
        'kind': 'CONNECT',
        'cookie': LOGIN['cookie'],
        'payload': pdump(payload)
    })

    send_data_to(req, ADDR_BOOK['server'])


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


def message_request(msg):
    try:
        # strip @msg header
        msg_body = msg.split(' ', 1)[1]
        to, message = msg_body.split(':', 1)

        logger.debug("message TO: {}".format(to, message))
    except Exception as e:
        print "The message format is '@msg TO: Your Message.'"
        logger.debug("Error on message parse: {}".format(e))
        return
    pass

    if len(msg_body) > MAX_MESSAGE_LENGTH:
        print "That message is too long to send (Max: 256 chars)"
        return

    conn = LOGIN['connections'].get(to)
    if not conn:
        print "Not yet connected to a user named {}".format(to)
        return

    if not conn.confirmed:
        print "You are not connected to B, try inviting them first."

    data = jdump({
        'message': message,
        'sender': LOGIN['username'],
        'timestamp': time.time(),
    })

    payload = pdump(aes_encrypt(conn.session_key, conn.iv, data))
    hmac = make_hmac(KEYCHAIN['private'], bytes(payload))

    msgpack = jdump({
        'kind': 'MESSAGE',
        'payload_hmac': pdump(hmac),
        'inviter_nonce': conn.inviter_nonce,
        'payload': payload,
    })

    conn.message(msgpack)

    print "{} -> {}: {}".format(LOGIN['username'], to, message)


FATAL_FROM_SERVER = ['login', 'terminate']


def server_handler(msg):
    logger.debug("SERVER MESSAGE RECEIVED...")
    # handles messages for the user from the server
    # i.e. error messages.
    try:
        enc_data = pload(msg.get('payload'))
        data = jload(aes_decrypt(KEYCHAIN['session'], KEYCHAIN['init_vector'],
                             enc_data))
        error = data.get('error')
        context = data.get('context')
        print "**SERVER**: {}".format(error)
    except:
        logger.debug("Couldn't parse encrypted server message, trying unencrypted...")

    try:

        error_payload = jload(msg.get('payload'))
        error = error_payload.get('error')
        context = error_payload.get('context')
        print "**SERVER**: {}".format(error)
    except:
        logger.debug("Couldn't parse unencrypted server message.")
        print "An unexpected error has occurred, please try restarting your client."


    if context in FATAL_FROM_SERVER:
        sys.exit(0)

# a handler for each valid message type received
socket_handlers = {
    # inputs from other clients
    'INVITE': invite_handler,
    'MESSAGE': message_handler,
    # inputs from the server
    'LOGIN': login_handler,
    'LOGOUT': logout_handler,
    'LIST': list_handler,
    'CONNECT': connect_handler,
    'SERVER': server_handler,
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
    except Exception as e:
        unknown_error()
        logger.debug("[ERROR]: {}, raw_msg: {}".format(e, raw_msg))
        sys.exit(0)

    handler = socket_handlers[msg.get('kind')]
    handler(msg)


def greet_user():
    print """
    Welcome to the chat client!!

    Attempting to connect to the server...

    If you aren't prompted for you credentials in a few seconds, 
        please try again later.
    """

def print_help(*args):
    print """
        User protocols:
        '@list' - List the users connected to the server.
        '@invite' - Invite a user to chat with you.
        '@logout' - Logout of the server.
        '@msg' - Message someone you are connected with. Usage is
            '@msg USERNAME: Your Message'
        '@help' - Prints this Dialog.
    """

# special messages from user and their handlers:
user_protocols = {
    '@list': list_request,
    '@invite': invite_request,
    '@logout': logout_request,
    '@msg': message_request,
    '@help': print_help,
}



def handle_stdin_event():
    text = sys.stdin.readline()
    if any(text.startswith(p) for p in user_protocols.keys()):
        handler = user_protocols[text.rstrip().split(' ', 1)[0]]
        handler(text)
    else:
        print "Invalid chat protocol -> "
        print_help()
        logger.debug("[CHAT INPUT]: {}".format(text))



def run():
    """
    loops forever, using a python 'select'
    to handle different events by listening on
    stdin AND the socket simultaneously
    """

    greet_user()

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
