from helpers import jdump, rsa_encrypt


class User(object):
    def __init__(self, cookie, addr):
        self.cookie = cookie
        self.prev_ctx = 'init'
        self.addr = addr

    def update_submit(self, name, pwdhash, nonce, pkey, skey, nonce_server,
                      nonce_time, iv):
        self.username = name
        self.password_hash = pwdhash
        self.nonce = nonce
        self.public_key = pkey
        self.session_key = skey
        self.nonce_server = nonce_server
        self.nonce_time = nonce_time
        self.iv = iv

    def send(self, socket, data):
        # TODO -> Handle socket errors here
        socket.sendto(data, self.addr)

    def challenge(self):
        challenge = {
            'session_key': self.session_key, # base 64 encoded
            'username': self.username,
            'user_nonce': self.nonce,
            'server_nonce': self.nonce_server,
        }
        print "SERVER NONCE IS: {}".format(self.nonce_server.format('base64'))
        return rsa_encrypt(self.public_key, jdump(challenge))
