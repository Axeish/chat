import sys
import hashlib, uuid
from helpers import *
from config import default_users, passwords

#print uuid.uuid4().hex
for k, v in default_users.items():
    salt = v[0]
    password = passwords[k]
    payload = "{}{}".format(salt, password)
    m = hashlib.sha256()
    m.update(salt)
    m.update(password)
    the_hash = m.hexdigest()
    print "'{}': '{}'".format(k, the_hash)

# with open('passwords.db', 'w') as f:
#     for
