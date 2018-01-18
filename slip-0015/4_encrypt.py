#!/usr/bin/env python2

import hmac, hashlib, binascii, sys, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = sys.argv[1]

constant_hex = "0123456789abcdeffedcba9876543210"
constant = binascii.unhexlify(constant_hex)
digest = hmac.new(key, constant, hashlib.sha512).digest()

filename_binary = digest[0:32]

# right now the file needs to be in the working directory
filename = binascii.hexlify(filename_binary) + ".mtdt"

# hardcoded
data = """{
    "accountLabel": "Saving account",
    "addressLabels": {
      "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL": "My receiving address",
      "1GWFxtwWmNVqotUPXLcKVL2mUKpshuJYo": ""
    },
    "version": "1.0.0",
    "outputLabels": {
      "350eebc1012ce2339b71b5fca317a0d174abc3a633684bc65a71845deb596539": {
        "0": "Money to Adam"
      },
      "ebbd138134e2c8acfee4fd4edb6f7f9175ee7b4020bcc82aba9a13ce06fae85b": {
        "0": "Feeding bitcoin eater"
      }
    }
  }"""

backend = default_backend()
cipherkey = digest[32:64]

iv = os.urandom(12)
cipher = Cipher(algorithms.AES(cipherkey), modes.GCM(iv), backend=backend)
encryptor = cipher.encryptor()

ctext = encryptor.update(data) + encryptor.finalize()
tag = encryptor.tag

with open(filename, "wb") as f:
    f.write(iv)
    f.write(tag)
    f.write(ctext)

