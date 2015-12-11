import time
from client import send_data_to

class Connection(object):
    def __init__(self, nonce, to, from, sender):
        self.nonce = nonce
        self.to = to
        self.from = from
        self.sender = sender

    def validate(self, c):
        """
        c is the decoded payload from
        the server with connection details
        """
        # first check if the to/from is correct
        if c.get('to') != self.to:
            return False

        if c.get('from') != self.from:
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
    c = Connection()


    def message(self, payload):
        send_data_to(payload, self.to_addr)
