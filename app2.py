from __future__ import print_function
from base64 import b64encode
from hashlib import sha256

import sys
import asyncio
import dkim
import dkim.canonicalization
import pprint

from Crypto.Hash import SHA256


def canon(body):
    """asdfsdaf"""
    print("Before [%s]" % (body))
    canon_policy = dkim.canonicalization.CanonicalizationPolicy.from_c_value(
        b'relaxed/relaxed')
    res = canon_policy.canonicalize_body(body.encode())
    print("After [%s]" % (res.decode()))
    return res


def hash(body):
    # shav = sha256(body)
    # # shav = sha256.nekw(body.encode()).digest()
    # bh = b64encode(shav.digest())
    shav = SHA256.new(body).digest()
    bh = b64encode(shav)
    return bh.decode()


b2 = """

test2 
"""


def main(filepath: str):
    with open(filepath, 'r') as file:
        message = file.read()
    print(hash(canon(b2)))
    parsed = dkim.rfc822_parse(message.encode())
    pprint.pp(parsed[1])
    hashed = hash(canon(parsed[1].decode()))
    pprint.pp(hashed)

    res = dkim.verify(message.encode())
    print(res)

    return res


if __name__ == "__main__":
    res = main(sys.argv[1])
    if not res:
        print("signature verification failed")
        sys.exit(1)
    print("signature ok")
