class User(object):
	def __init__(self, cookie, addr):
		self.cookie = cookie
		self.prev_ctx = 'init'
		self.addr = addr

	def update_context(self):
		pass

	def send(self, socket, data):
		# TODO -> Handle socket errors here
		socket.sendto(data, self.addr)

