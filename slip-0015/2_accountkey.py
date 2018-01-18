#!/usr/bin/env python2

import hmac, hashlib, base58, binascii, sys

# xpub of the first account
xpub = sys.argv[1]
# hexadecimal representation of the master key
master_hex = sys.argv[2]

master_key = binascii.unhexlify(master_hex)
digest = hmac.new(master_key, xpub, hashlib.sha256).digest()
print base58.b58encode_check(digest)

