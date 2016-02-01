#!/usr/bin/env python2

import hmac, hashlib, binascii, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = sys.argv[1]

constant_hex = "0123456789abcdeffedcba9876543210"
constant = binascii.unhexlify(constant_hex)
digest = hmac.new(key, constant, hashlib.sha512).digest()

filename_binary = digest[0:32]

# right now the file needs to be in the working directory
filename = binascii.hexlify(filename_binary) + ".mtdt"

backend = default_backend()
cipherkey = digest[32:64]

with open(filename, "rb") as f:
    iv = f.read(12)
    tag = f.read(16)
    cipher = Cipher(algorithms.AES(cipherkey), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    data = "";
    while True:
        block = f.read(16)
        # data are not authenticated yet
        if block:
            data = data + decryptor.update(block)
        else:
            break
    # throws exception when the tag is wrong
    data = data + decryptor.finalize()

print data

