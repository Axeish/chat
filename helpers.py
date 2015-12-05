import json

def dump(data):
    # wrap this in a try catch as well TODO
    return json.dumps(data)

def load(data):
    # TODO: ERRORS
    return json.loads(data)
