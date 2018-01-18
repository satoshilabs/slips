#!/usr/bin/env python2

import binascii
import hashlib
import hmac
import struct
import ecdsa
from mnemonic import mnemonic

privdev = 0x80000000


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


def seed2hdnode(seed, modifier, curve):
    while True:
        h = hmac.new(modifier, seed, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        a = string_to_int(key)
        if (a < curve.order and a != 0):
            break
        seed = h
    return (key, chaincode)


def fingerprint(publickey):
    h = hashlib.new('ripemd160', hashlib.sha256(publickey).digest()).digest()
    return h[:4]


def publickey(private_key, curve):
    Q = string_to_int(private_key) * curve.generator
    xstr = int_to_string(Q.x(), 32)
    parity = Q.y() & 1
    return chr(2 + parity) + xstr


def derive(parent_key, parent_chaincode, i, curve):
    assert len(parent_key) == 32
    assert len(parent_chaincode) == 32
    k = parent_chaincode
    if ((i & privdev) != 0):
        key = '\x00' + parent_key
    else:
        key = publickey(parent_key, curve)
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        a = string_to_int(key)
        key = (a + string_to_int(parent_key)) % curve.order
        if (a < curve.order and key != 0):
            key = int_to_string(key, 32)
            break
        d = '\x01' + h[32:] + struct.pack('>L', i)
    return (key, chaincode)


def get_curve_info(curvename):
    return (ecdsa.curves.SECP256k1, 'Bitcoin seed')


def show_testvector(name, curvename, seedhex, derivationpath):
    curve, seedmodifier = get_curve_info(curvename)
    master_seed = binascii.unhexlify(seedhex)
    k, c = seed2hdnode(master_seed, seedmodifier, curve)
    p = publickey(k, curve)
    fpr = '\x00\x00\x00\x00'
    path = 'm'
    print("### " + name + " for " + curvename)
    print("Seed (hex): " + seedhex)
    print('* Chain ' + path)
    print('    * fpr: ' + binascii.hexlify(fpr))
    print('    * chain: ' + binascii.hexlify(c))
    print('    * prv: ' + binascii.hexlify(k))
    print('    * pub: ' + binascii.hexlify(p))
    depth = 0
    for i in derivationpath:
        fpr = fingerprint(p)
        depth = depth + 1
        path = path + "/" + str(i & (privdev - 1))
        if ((i & privdev) != 0):
            path = path + "<sub>H</sub>"
        k, c = derive(k, c, i, curve)
        p = publickey(k, curve)
        print('* Chain ' + path)
        print('    * fpr: ' + binascii.hexlify(fpr))
        print('    * chain: ' + binascii.hexlify(c))
        print('    * prv: ' + binascii.hexlify(k))
        print('    * pub: ' + binascii.hexlify(p))
    print


m = mnemonic.Mnemonic("english")
show_testvector("Test vector 1",
                'secp256k1',
                binascii.hexlify(m.to_seed("hello")),
                [
                    privdev + 48,
                    privdev + 0,
                    privdev + 0,
                    privdev + 1,
                    privdev + 0,
                ])

show_testvector("Test vector 2",
                'secp256k1',
                binascii.hexlify(m.to_seed("hello")),
                [
                    privdev + 48,
                    privdev + 1,
                    privdev + 3,
                    privdev + 0,
                    privdev + 3,
                ])
