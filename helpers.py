import json
import os

def dump(data):
    # wrap this in a try catch as well TODO
    return json.dumps(data)

def load(data):
    # TODO: ERRORS
    return json.loads(data)

def nonce(length):
    return os.urandom(length).encode('base64')