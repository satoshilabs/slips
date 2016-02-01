#!/usr/bin/env python2

from trezorlib.client import TrezorClient
from trezorlib.transport_hid import HidTransport
from binascii import hexlify, unhexlify

# for more details on this, see python-trezor
client = TrezorClient(HidTransport(HidTransport.enumerate()[0]))

bip32_path = client.expand_path("10015'/0'")
masterkey = client.encrypt_keyvalue(
    bip32_path,
    "Enable labeling?",
    unhexlify("fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef"),
    True,
    True
)

print 'Key:', hexlify(masterkey)

