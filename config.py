config = {
    "server_port": 30030,
    "server_ip": "127.0.0.1",
    "server_pub_file": 'server.public.key',
}

# not production, just for the project.
default_users = { # dict of username -> (salt, hash)
    'bob': ('9f3f91fa2d934da98280733b56fb5e4c', '072aeb5c00619cb76166d448469a4e5082b886bcf593e03613ea3cb0b9d6632c'), # soccer_fan_89!
    'sally': ('37ff0dd228814f1aaf39ff7d9052572c','024bcd34a4084d6d111c164ae13f696bfcca7bd6100b680626f15392ce65318c'), # por0s_are_cute54@
    'chris': ('b22280cbe1f1481baa258eddab0a0146','28aca671e497aa17b574bc000070721c4458058bf01599ab5d6431364a66a686'), # pass (intentionally weak for debugging)
    'ashish': ('4f59e9b6d23445e68a03239f9d762473','c28586bc760953ef9825108df81de77ebf42b9dc2b0999b2a681391bfa235a91'), # ashish
}

# stored for documentation, not actually stored on server.
passwords = {
    'bob': 'soccer_fan_89!',
    'sally': 'por0s_are_cute54@',
    'chris': 'pass',
    'ashish': 'ashish',
}