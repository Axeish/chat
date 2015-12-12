import time
from helpers import *

logging.basicConfig()
logger = logging.getLogger('chat-client')
logger.setLevel(logging.DEBUG)


class Connection(object):
    def __init__(self,
                 nonce,
                 to,
                 frm,
                 socket,
                 from_ticket=False,
                 public_key=None):
        """
        called when Connection created from invite request
        """
        self.socket = socket
        self.inviter_nonce = nonce
        self.invitee_nonce = None
        self.to = to
        self.is_from_ticket = False
        self.frm = frm
        self.is_from_ticket = from_ticket
        self.public_key = public_key
        self.confirmed = False

    def validate(self, c):
        """
        c is the decoded payload from
        the server with connection details
        """
        logger.debug("Validating server connect payload...")
        # first check if the to/from is correct
        if c.get('to') != self.to:
            return False

        if c.get('from') != self.frm:
            return False

        if c.get('nonce_user') != self.inviter_nonce:
            return False

        server_ts = c.get('server_ts')
        if not server_ts or not validate_server_ts(server_ts):
            return False
        self.server_ts = server_ts

        ticket = c.get('ticket')
        if not ticket:
            return False
        self.ticket = ticket

        to_addr = c.get('to_addr')
        if not to_addr:
            return False
        self.to_addr = tuple(to_addr)

        return True

    def invite(self, invitation):
        logger.debug("sending invite to: {}...".format(self.to))
        self.message(invitation)
        # send the invite to b.

    @classmethod
    def from_ticket(cls, ticket, me, socket):
        """
        creates a connection when being received from a user
        if a connection is created from a ticket
        the nonce belongs to from, the to address is THIS CLIENT
        """
        logger.debug("Building connection from ticket...")

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
        c = Connection(ticket_nonce_user,
                       str(ticket_from.rstrip()),
                       str(ticket_to.rstrip()),
                       from_ticket=True,
                       public_key=ticket_from_pkey,
                       socket=socket)
        c.server_ts = ticket_server_ts
        c.to_addr = tuple(ticket_from_addr)  # reverse perspective of this connection
        # invitee nonce ->
        c.invitee_nonce = nonce(16)
        logger.debug("Successfully built connection from ticket")
        return c

    def make_session_key(self):
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
        logger.debug("Responding to invite request")
        session_key, iv = self.make_session_key()
        resp = jdump({
            'server_ts': self.server_ts,
            'inviter_nonce': self.inviter_nonce,
            'to': self.frm,  # reverse perspective when ticket receiver
            'from': self.to,
            'session': session_key.encode('base64'),
            'invitee_nonce': self.invitee_nonce
        })

        public_key = parse_public_key(str(self.public_key))
        payload = pdump(rsa_encrypt(public_key, resp))
        confirmation = jdump({
            'kind': 'INVITE',
            'context': 'confirm',
            'payload': payload,
            'init_vector': self.iv.encode('base64'),
        })

        self.message(confirmation)

    def confirm_connection(self, data, iv_enc):
        """
        here we are "A" (inviter) and the other client is "B" (invitee)
        """
        logger.debug("Confirming Connection...")
        # at this point, the driver client has found this connection
        # in the connections dict, and is sending the payload
        # along with the client's private key for decryption

        # TODO
        # veryfiy to/from
        # verify server_ts
        # verify inviter nonce
        # set session key

        self.session_key = data['session'].decode('base64')
        self.iv = iv_enc.decode('base64')

        # encrypt invitee nonce, send back
        invitee_nonce = data['invitee_nonce']
        payload = pdump(aes_encrypt(self.session_key, self.iv, invitee_nonce))
        conf = jdump({
            'kind': 'INVITE',
            'context': 'confirm_ack',
            'payload': payload
        })
        self.message(conf)

        logger.debug("Connection is confirmed")
        self.confirmed = True

        return True

    def message(self, payload):
        self.socket.sendto(payload, self.to_addr)
