import time
from helpers import *

class Connection(object):
    def __init__(self, nonce, to, frm, from_ticket=False, public_key=None):
        """
        called when Connection created from invite request
        """
        self.socket = socket
        self.invter_nonce = nonce
        self.invitee_nonce = None
        self.to = to
        self.is_from_ticket = False
        self.frm = frm
        self.is_from_ticket = from_ticket
        self.public_key = public_key

    def validate(self, c):
        """
        c is the decoded payload from
        the server with connection details
        """
        # first check if the to/from is correct
        if c.get('to') != self.to:
            return False

        if c.get('from') != self.frm:
            return False

        if c.get('nonce_user') != self.nonce:
            return False

        server_ts = c.get('server_ts')
        if not server_ts or not self.validate_server_ts(server_ts):
            return False
        self.server_ts = server_ts

        ticket = c.get('ticket')
        if not ticket:
            return False
        self.ticket = ticket

        to_addr = c.get('to_addr')
        if not to_addr:
            return False
        self.to_addr = to_addr

        return True

    def validate_server_ts(timestamp):
        accept_interval = 60 * 60 * 24
        now = time.time()
        pre = now - accept_interval
        post = now + accept_interval
        return timestamp < post and timestamp > pre

    def update_connection(self):
        pass

    def invite(self, invitation):
        sender(invitation, self.to_addr)
        # send the invite to b.

    @classmethod
    def from_ticket(cls, ticket, me):
        """
        creates a connection when being received from a user
        if a connection is created from a ticket
        the nonce belongs to from, the to address is THIS CLIENT
        """

        ticket_from = ticket.get('from')
        if not ticket_from:
            return False

        ticket_to = ticket.get('to')
        if not ticket_to or ticket_to != me:
            return False

        ticket_from_addr = ticket.get('from_addr')
        if not ticket_from_addr:
            return False

        ticket_nonce_user = ticket.get('nonce_user')
        if not ticket_nonce_user:
            return False

        ticket_server_ts = ticket.get('server_ts')
        if not ticket_server_ts or not validate_server_ts(ticket_server_ts):
            return False

        ticket_from_pkey = ticket.get('from_public')
        if not ticket_from_pkey:
            return False

        # if we're here, ticket is good (hopefully)
        # in the end we only care that the connection can be used
        # to .message() the invitee from the perspective of this client
        c = Connection(ticket_nonce_user, ticket_from, ticket_to, from_ticket=True, public_key=ticket_from_pkey)
        c.server_ts = ticket_server_ts
        # invitee nonce ->
        c.invitee_nonce = nonce(16)
        return c

    def make_session_key():
        key = aes_key()
        self.session_key = key
        iv = init_vector(16)
        self.iv = iv
        return key, iv

    def respond_to_invite(self):
        """
        B -> A: {serv_ts, Na, A, B, Kab, Nb}Ka_pub
        we are 'B' if this method is being called
        """
        session_key, iv = self.make_session_key()
        resp = jdump({
            'server_ts': self.server_ts,
            'inviter_nonce': self.nonce,
            'to': self.to,
            'from': self.frm,
            'session': session_key,
            'invitee_nonce': self.invitee_nonce
        })
        payload = pdump(rsa_encrypt(self.public_key, resp))
        confirmation = jdump({
            'kind': 'INVITE',
            'context': 'confirm',
            'payload': payload
        })

        self.message(confirmation)


    def confirm_connection(self, data):
        """
        here we are "A" (inviter) and the other client is "B" (invitee)
        """
        # at this point, the driver client has found this connection
        # in the connections dict, and is sending the payload
        # along with the client's private key for decryption

        # TODO
        # veryfiy to/from
        # verify server_ts
        # verify inviter nonce

        # encrypt invitee nonce, send back
        invitee_nonce = data['invitee_nonce']
        payload = pdump(aes_encrypt(self.session_key, self.iv, invitee_nonce))
        self.message(payload)
        return True


    def message(self, payload):
        self.socket.sendto(payload, self.to_addr)
