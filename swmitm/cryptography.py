import base64
import json
import zlib

import Crypto.Cipher.AES
import Crypto.Cipher.PKCS1_v1_5
import Crypto.PublicKey.RSA
from Crypto.Util.Padding import unpad, pad


def _decrypt(message: bytes, key: bytes) -> bytes:
    cryptor = Crypto.Cipher.AES.new(key, iv=b'\x00' * 16, mode=Crypto.Cipher.AES.MODE_CBC)
    message = cryptor.decrypt(message)
    message = unpad(message, block_size=16)
    return message


def _encrypt(message: bytes, key: bytes) -> bytes:
    cryptor = Crypto.Cipher.AES.new(key, iv=b'\x00' * 16, mode=Crypto.Cipher.AES.MODE_CBC)
    message = pad(message, block_size=16)
    message = cryptor.encrypt(message)
    return message


def decrypt_message(message: bytes | str, key: bytes) -> bytes:
    return _decrypt(message=base64.b64decode(message), key=key)


def encrypt_message(message: bytes, key: bytes) -> bytes:
    return base64.b64encode(_encrypt(message=message, key=key))


def req_dict_to_bytes(message: dict) -> bytes:
    message = json.dumps(message, separators=(',', ':'))
    return message.encode()


def encrypt_request(message: dict, key: bytes) -> bytes:
    message = req_dict_to_bytes(message)
    return encrypt_message(message=message, key=key)


def decrypt_request(message: str | bytes, key: bytes) -> dict:
    message = decrypt_message(message=message, key=key)
    return json.loads(message)


def decrypt_response(message: str | bytes, key: bytes) -> dict:
    message = decrypt_message(message=message, key=key)
    return json.loads(zlib.decompress(message))


def pk_encrypt(message: bytes, key: str | bytes) -> bytes:
    cryptor = Crypto.Cipher.PKCS1_v1_5.new(Crypto.PublicKey.RSA.import_key(key))
    return base64.b64encode(cryptor.encrypt(message))
