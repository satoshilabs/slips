#!/usr/bin/env python2

import binascii
import hashlib
import hmac
import struct


def int_to_string(x, pad):
    result = ['\x00'] * pad
    while x > 0:
        pad -= 1
        ordinal = x & 0xFF
        result[pad] = (chr(ordinal))
        x >>= 8
    return ''.join(result)

def string_to_int(s):
    result = 0
    for c in s:
        if not isinstance(c, int):
            c = ord(c)
        result = (result << 8) + c
    return result


# mode 0 - compatible with BIP32 private derivation
def derive(parent_key, parent_chaincode, i):
    assert len(parent_key) == 32
    assert len(parent_chaincode) == 32
    secp256k1_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    k = parent_chaincode
    d = '\x00' + parent_key + struct.pack('>L', i)
    h = hmac.new(k, d, hashlib.sha512).digest()
    key, chaincode = h[:32], h[32:]
    key = (string_to_int(key) + string_to_int(parent_key)) % secp256k1_n
    key = int_to_string(key, 32)
    return (key, chaincode)

# mode 1 - universal
def derive_universal(parent_key, parent_chaincode, i, n, curveid, data):
    assert len(parent_key) == 32
    assert len(parent_chaincode) == 32
    ctr = 0
    while True:
        k = parent_chaincode
        d = '\x01' + parent_key + struct.pack('>L', i) + curveid + struct.pack('>L', ctr) + data
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        if string_to_int(key) >= n:
            ctr += 1
        else:
            return (key, chaincode)


master_key = binascii.unhexlify('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35')
master_chaincode = binascii.unhexlify('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508')


k, c = derive(master_key, master_chaincode, 0x80000000 + 44)
assert binascii.hexlify(k) == '8a8e34c835bceec0213d542623158811d5686d931d51efbf8e3ea8f62edc703f'
assert binascii.hexlify(c) == '4681a20841656292a6f6fda184811ace2c5fa67de53c47eb9d0cc557bae2dea4'
print 'ok'


k, c = derive_universal(master_key, master_chaincode, 1337, n=(2**255 - 19), curveid='ed25519', data='https://www.example.com')
assert binascii.hexlify(k) == '51e7ccf5c5fd11301926ccdf195f6c02b2696a2b9e5a95a930f7e527654b5d03'
assert binascii.hexlify(c) == 'b45f2b67f218223833f5607d1a26b030e6a1ebc7fdd7b3bc9481e1d78ee2c728'
print 'ok'
