# -*- coding: utf-8 -*-
import os
import sys
import logging
import socket
import time
from user import User
from helpers import *
from config import config
from collections import defaultdict

logging.basicConfig()
logger = logging.getLogger('chat-server')
logger.setLevel(logging.INFO)

KEYCHAIN = {}
USERS = {}  # maps uid to User class
ATTEMPTED_LOGINS = {}
BROWNLIST = defaultdict(int)
BROWN_THRESHOLD = 3 # number of logins before rate limiting
# TODO: not yet enforced -> out of time.

def load_server_keys():
    with open('server.private.key') as f:
        keystr = f.read()
        try:
            KEYCHAIN['private'] = parse_private_key(keystr)
        except Exception as e:
            logger.error("Couldn't read private key from file: {}".format(e))
    KEYCHAIN['cookie_key'] = aes_key()
    KEYCHAIN['cookie_iv'] = init_vector(16)


def handle_login_init(body, sender):
    # send cookie
    cookie = make_cookie(sender)
    # brown_value = BROWNLIST.get(str(sender[1]), 0)
    # if not brown_ok(brown_value):
    #     return

    ATTEMPTED_LOGINS[cookie] = User(cookie, sender)
    resp = jdump({'kind': 'LOGIN', 'cookie': cookie, 'context': 'cookie', })
    logger.debug("RECV LOGIN INIT, RESP IS {}".format(resp))
    ATTEMPTED_LOGINS[cookie].send(_SOCK, resp)


def make_cookie(addr):
    dough = '-'.join(map(str, [addr[0], addr[1], int(time.time())]))

    cookie = aes_encrypt(KEYCHAIN['cookie_key'], KEYCHAIN['cookie_iv'],
                         dough).encode('base64')
    return cookie


def verify_cookie(addr, cookie):
    dough = aes_decrypt(KEYCHAIN['cookie_key'], KEYCHAIN['cookie_iv'],
                        cookie.decode('base64'))
    try:
        addr0, addr1, timestamp = dough.split('-')
    except:
        logger.debug("Invalid cookie from: {}".format(addr))
        return False

    result = addr0 == str(addr[0]) and addr1 == str(
        addr[1]) and validate_server_ts(timestamp)
    logger.debug("COOKIE CHECK: {} - {} - {} - {}".format(result, addr0, addr1,
                                                          timestamp))
    return result


def handle_login_submit(body, sender):
    logger.debug("RECV LOGIN SUBMIT from {}".format(sender))
    if not verify_cookie(sender, body.get('cookie')):
        logger.debug("Invalid cookie sent from {}".format(sender))
        serror(sender, "invalid server cookie, try restarting client.", 'login')
        terminate_connection(body, sender)
        return

    user = ATTEMPTED_LOGINS[body.get('cookie')]
    if not user:
        # DoS cookie is invalid
        logger.debug("terminating connection, cookie invalid in submit")
        serror(sender, "Session Expired. Restart Client.", 'login')
        terminate_connection(body, sender)
        return

    payload = jload(rsa_decrypt(KEYCHAIN['private'], pload(body['payload'])))
    user_public_key_bytes = rsa_decrypt(KEYCHAIN['private'],
                                        pload(body['public_key']))
    public_key = parse_public_key(user_public_key_bytes)

    k_session = aes_key().encode('base64')
    nonce_server = nonce(16)
    nonce_time = time.time()
    iv = init_vector(16)

    if not verify_password(payload['username'], payload['password_hash']):
        serror(sender, "Username/Password combination do not match.", 'login')
        logger.debug("username and password don't match!")
        terminate_connection(body, sender)
        return

    already_connected = len([u for u in USERS.values() if u.username == payload['username']]) > 0
    if already_connected:
        serror(sender, "User is already connected", 'login')
        terminate_connection(body, sender)

    user.update_submit(payload['username'], payload['password_hash'],
                       payload['nonce_user'], public_key, k_session,
                       nonce_server, nonce_time, iv)


    resp = jdump({
        'kind': 'LOGIN',
        'context': 'challenge',
        'init_vector': iv.encode('base64'),
        'payload': pdump(user.challenge()),
    })

    user.send(_SOCK, resp)


def handle_login_response(body, sender):
    logger.debug("LOGIN RESPONSE RECEIVED")
    # validate the response to challenge
    try:
        user = validate_user_cookie(body.get('cookie'), ATTEMPTED_LOGINS)
    except:
        serror(sender, "Internal Server Error.", 'login')
        terminate_connection(body, sender)
        return

    enc_answer = pload(body['payload'])
    # make sure this is wrapped in an error handler
    dec_answer = aes_decrypt(
        user.session_key.decode('base64'), user.iv, enc_answer)
    logger.debug("DECRYPTED ANSWER: {}".format(dec_answer))

    if dec_answer == user.nonce_server:
        logger.debug("LOGGING IN: {}".format(user.username))
        USERS[user.cookie] = user
    else:
        uerror(user, 'Unable to log in, please restart client and try again.', 'login')
        logger.debug("FAILED TO LOGIN: {}".format(user.username))
        logger.debug("ANSWER WAS: {}".format(enc_answer.decode('base64')))

    payload = aes_encrypt(user.session_key.decode('base64'), user.iv, user.nonce)

    resp = jdump({
        'kind': 'LOGIN',
        'context': 'ack',
        'payload': pdump(payload),
    })

    user.send(_SOCK, resp)

login_handlers = {
    'INIT': handle_login_init,
    'SUBMIT': handle_login_submit,
    'RESPONSE': handle_login_response,
}


def handle_login(body, sender):
    ctx = body.get('context')
    if not ctx or ctx not in login_handlers:
        terminate_connection(body, sender)
        return

    handler = login_handlers[ctx]
    handler(body, sender)


def terminate_connection(body, sender):
    # penalize in brown list for failed attempt by IP/usrname
    logger.debug("TERMINATING CONNECTION WITH: {}".format(sender))

    for cookie, user in ATTEMPTED_LOGINS.items():
        if user.addr == sender:
            del ATTEMPTED_LOGINS[cookie]
    for cookie, user in USERS.items():
        if user.addr == sender:
            del USERS[cookie]

    try:
        serror(sender, "Terminating Connection.", "terminate")
    except:
        # at this point, we don't care if this person knows what's going on.
        pass

    BROWNLIST[str(sender[1])] += 1


def handle_logout_init(body, sender):
    user = validate_user_cookie(body.get('cookie'), USERS)

    payload = pload(body['payload'])
    data = jload(aes_decrypt(
        user.session_key.decode('base64'), user.iv, payload))

    if not data['username'] == user.username:
        logger.debug("INVALID LOGOUT REQUEST -> USERNAME DOESN'T MATCH!")
        terminate_connection(body, sender)
        return

    user.prep_logout(data['nonce_user'])

    resp = jdump({'nonce_user': data['nonce_user'], })

    resp_payload = pdump(aes_encrypt(
        user.session_key.decode('base64'), user.iv, resp))

    resp = jdump({'kind': 'LOGOUT', 'payload': resp_payload})

    user.send(_SOCK, resp)


def validate_user_cookie(cookie, where):
    user = where.get(cookie)
    if not user:
        # DoS cookie is invalid
        logger.debug("terminating connection, cookie invalid in response")
        raise ValueError("Invalid user cookie!")

    # do other checks on the cookie and the user.
    return user


def handle_logout_fin(body, sender):
    try:
        user = validate_user_cookie(body.get('cookie'), USERS)
    except:
        terminate_connection(body, sender)
        return

    payload = pload(body['payload'])

    data = jload(aes_decrypt(
        user.session_key.decode('base64'), user.iv, payload))

    logout_nonce = data['nonce_user']

    # check nonce sent by user.
    if user.logout_requested and user.logout_nonce == logout_nonce:
        remove_user(user)
    else:
        logger.debug("Invalid credentials for logout of user: {}".format(
            user.username))


def remove_user(user):
    logger.debug("REMOVING USER FROM USERS: {}".format(user.username))
    cookie = user.cookie
    try:
        del USERS[cookie]
    except:
        logger.error("Unable to logout user with username: {}".format(
            user.username))


logout_handlers = {'init': handle_logout_init, 'fin': handle_logout_fin, }


def handle_logout(body, sender):
    """
    ------
    User (U) to Server (S): ‘LOGOUT’ protocol:

    U -> S: Ksu{‘LOGOUT’, U, Nu}
    S -> U: Ksu{‘LOGOUT_ACK’, Nu}
    U -> S: Ksu{Nu}

    After logout, server will remove user from userlist, forgetting all temporary information,
    in particular the symmetric session key, the public key of the client, and the client's
    current network endpoint.

    """
    logger.debug("[RECEIVED LOGOUT]...")
    ctx = body.get('context')
    if not ctx or ctx not in logout_handlers:
        terminate_connection(body, sender)
        return

    handler = logout_handlers[ctx]
    handler(body, sender)


def handle_list(body, sender):
    logger.debug("[RECEIVED LIST]...")

    try:
        user = validate_user_cookie(body.get('cookie'), USERS)
    except:
        terminate_connection(body, sender)
        return

    # only ever one context, don't need to switch on context.
    payload = pload(body['payload'])

    data = jload(aes_decrypt(
        user.session_key.decode('base64'), user.iv, payload))

    #logger.debug("RECEIVED DATA: {}".format(data))

    if not data['username'] == user.username:
        logger.debug("INVALID LIST REQUEST -> USERNAME DOESN'T MATCH!")
        terminate_connection(body, sender)
        return

    list_response = jdump({
        'list': [u.username for u in USERS.values()],
        'nonce_user': data['nonce_user']
    })

    resp_payload = aes_encrypt(
        user.session_key.decode('base64'), user.iv, list_response)

    resp = jdump({'kind': 'LIST', 'payload': pdump(resp_payload), })

    logger.debug("SENDING LIST...")
    user.send(_SOCK, resp)


def build_ticket_to(user, target, nonce_user, ts):
    """
    TTB = Ksb{A, B, ip_port_a, Na, server_timestamp, Ka_pub}
    """
    ticket = jdump({
        'from': user.username,
        'to': target.username,
        'from_addr': user.addr,
        'nonce_user': nonce_user,
        'server_ts': ts,
        'from_public': public_bytes(user.public_key),
    })

    payload = aes_encrypt(
        target.session_key.decode('base64'), target.iv, ticket)

    logger.debug("TICKET SIZE: {}".format(len(bytes(payload))))
    return pdump(payload)


def user_by_username(username):
    for cookie, user in USERS.items():
        if user.username in (username):
            return user


def handle_connect(body, sender):
    """
    S -> A: Ksa{TTB, A, B, Na, serv_ts, ip_port_b}
    TTB = Ksb{A, B, ip_port_a, Na, server_timestamp, Ka_pub}
    """
    logger.debug("[RECEIVED CONNECT]...")
    try:
        user = validate_user_cookie(body.get('cookie'), USERS)
    except:
        terminate_connection(body, sender)
        return
    payload = pload(body['payload'])

    data = jload(aes_decrypt(
        user.session_key.decode('base64'), user.iv, payload))

    if not data['from'] == user.username:
        logger.debug("INVALID CONNECT REQUEST -> FROM DOESN'T MATCH!")
        terminate_connection(body, sender)
        return

    to = data.get('to')
    target = user_by_username(to)
    if not target:
        uerror(user, 'No user named {} is logged in!'.format(to), 'connect')
        logger.debug("Can't find target: {}".format(to))
        return

    server_ts = time.time()
    # assuming all is validated..
    TTT = build_ticket_to(user, target, data['nonce_user'], server_ts)

    logger.debug("BUILT TICKET TO TARGET...")

    connect_response = jdump({
        'ticket': TTT,
        'to': data['to'],
        'from': data['from'],
        'nonce_user': data['nonce_user'],
        'to_addr': target.addr,
        'server_ts': server_ts,
    })

    payload = aes_encrypt(
        user.session_key.decode('base64'), user.iv, connect_response)

    payload = pdump(payload)

    resp = jdump({'kind': 'CONNECT', 'payload': payload})

    user.send(_SOCK, resp)

# a handler for each valid message type
handlers = {
    'LOGIN': handle_login,
    'LOGOUT': handle_logout,
    'LIST': handle_list,
    'CONNECT': handle_connect,
}

def serror(sender, error, context=''):
    # send the user a polite message to be printed
    # in the client
    error_payload = jdump({
        'server_kind': 'error',
        'error': error,
        'context': context,
    })
    logger.debug("SENDING ANON ERROR: {}".format(error_payload))

    resp = jdump({'kind': 'SERVER', 'payload': error_payload})

    _SOCK.sendto(resp, sender)

def uerror(user, error, context=''):
    # send the user a polite message to be printed
    # in the client
    error_payload = jdump({
        'server_kind': 'error',
        'error': error,
        'context': context,
    })
    logger.debug("SENDING USER ERROR: {}".format(error_payload))

    payload = pdump(aes_encrypt(user.session_key.decode('base64'), user.iv,
                                error_payload))

    resp = jdump({'kind': 'SERVER', 'payload': payload, })

    user.send(_SOCK, resp)


def listen_and_serve():
    logger.debug("starting server...")

    while True:
        raw_msg, sender = _SOCK.recvfrom(_PORT)
        try:
            msg = jload(raw_msg)
            assert msg.get('kind') in handlers.keys()
        except AssertionError:
            logger.error("Invalid message kind".format(msg['kind']))
        except Exception as e:
            logger.error("Unable to parse message: {}, e: {}".format(raw_msg,
                                                                     e))

        handler = handlers[msg.get('kind')]
        handler(msg, sender)


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
