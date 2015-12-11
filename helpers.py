import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as padding_asym
import logging
import pickle

logging.basicConfig()
logger = logging.getLogger('chat-helpers')
logger.setLevel(logging.DEBUG)
AES_KEY_SIZE = 256


def jdump(data):
    # wrap this in a try catch as well TODO
    return json.dumps(data)

def jdumpb(data):
    # wrap this in a try catch as well TODO
    return json.dump(data)

def jload(string):
    # TODO: ERRORS
    return json.loads(string)

def jloadb(string):
    # TODO: ERRORS
    return json.load(string)

def pdump(data):
    return pickle.dumps(data)


def pload(string):
    return pickle.loads(string)


def nonce(length):
    return os.urandom(length).encode('base64')


def rsa_encrypt(pub_key, msgbytes):
    return pub_key.encrypt(
        msgbytes,
        padding_asym.OAEP(mgf=padding_asym.MGF1(algorithm=hashes.SHA1()),
                          algorithm=hashes.SHA1(),
                          label=None))


def rsa_decrypt(priv_key, cipher_bytes):
    return priv_key.decrypt(
        cipher_bytes,
        padding_asym.OAEP(mgf=padding_asym.MGF1(algorithm=hashes.SHA1()),
                          algorithm=hashes.SHA1(),
                          label=None))


def pad(string):
    """
    convert ascii => bytes => padded bytes (match block size for AES)
    """
    padder = padding.PKCS7(128).padder()
    plain_bytes = string.encode(encoding='UTF-8')
    return padder.update(plain_bytes) + padder.finalize()


def unpad(the_bytes):
    """
    Given padded bytes, return unpadded bytes
    """
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(the_bytes) + unpadder.finalize()


def parse_private_key(pem_string):
    """
    loads a PEM format private key, not encrypted on disk.
    """
    return serialization.load_pem_private_key(pem_string,
                                              password=None,
                                              backend=default_backend())


def parse_public_key(pem_string):
    """
    wrapper method for parsing a pem formatted public key
    """
    return serialization.load_pem_public_key(pem_string, default_backend())


def aes_key():
    return os.urandom(AES_KEY_SIZE / 8)


def aes_encrypt(key, iv, plaintext):
    # build a cipher using aes_key and init vector, iv
    padded = pad(plaintext)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend())
    encryptor = cipher.encryptor()
    return (encryptor.update(padded) + encryptor.finalize())


def aes_decrypt(key, iv, cipher_bytes):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend())
    decryptor = cipher.decryptor()
    return unpad(decryptor.update(cipher_bytes) + decryptor.finalize())


def init_vector(size):
    return os.urandom(size)


def public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)