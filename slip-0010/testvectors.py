#!/usr/bin/env python3

import hashlib
import hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from base58 import b58encode_check

SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
SECP256R1_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
privdev = 0x80000000

# mode 0 - compatible with BIP32 private derivation
def seed2hdnode(seed, curve, modifier, curve_order):
    k = seed
    while True:
        h = hmac.new(modifier, seed, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        a = int.from_bytes(key, 'big')
        if (curve in ('ed25519', 'curve25519')):
            break
        if (a < curve_order and a != 0):
            break
        seed = h
        #print('RETRY seed: ' + seed.hex())
    return (key, chaincode)

def fingerprint(publickey):
    h = hashlib.new('ripemd160', hashlib.sha256(publickey).digest()).digest()
    return h[:4]

def b58xprv(parent_fingerprint, private_key, chain, depth, childnr):
    raw = (b'\x04\x88\xad\xe4' +
              bytes([depth]) + parent_fingerprint + childnr.to_bytes(4, 'big') +
              chain + b'\x00' + private_key)
    return b58encode_check(raw).decode()

def b58xpub(parent_fingerprint, public_key, chain, depth, childnr):
    raw = (b'\x04\x88\xb2\x1e' +
              bytes([depth]) + parent_fingerprint + childnr.to_bytes(4, 'big') +
              chain + public_key)
    return b58encode_check(raw).decode()

def publickey(private_key, curve):
    if curve == 'ed25519':
        sk = Ed25519PrivateKey.from_private_bytes(private_key)
        key_encoding = serialization.Encoding.Raw
        key_format = serialization.PublicFormat.Raw
        prefix = b'\x00'
    elif curve == 'curve25519':
        sk = X25519PrivateKey.from_private_bytes(private_key)
        key_encoding = serialization.Encoding.Raw
        key_format = serialization.PublicFormat.Raw
        prefix = b'\x00'
    else:
        sk = ec.derive_private_key(int.from_bytes(private_key, 'big'), curve)
        key_encoding = serialization.Encoding.X962
        key_format = serialization.PublicFormat.CompressedPoint
        prefix = b''
    return prefix + sk.public_key().public_bytes(key_encoding, key_format)

def derive(parent_key, parent_chaincode, i, curve, curve_order):
    assert len(parent_key) == 32
    assert len(parent_chaincode) == 32
    k = parent_chaincode
    if ((i & privdev) != 0):
        key = b'\x00' + parent_key
    else:
        key = publickey(parent_key, curve)
    d = key + i.to_bytes(4, 'big')
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        if curve in ('ed25519', 'curve25519'):
            break
        #print('I: ' + h.hex())
        a = int.from_bytes(key, 'big')
        key = (a + int.from_bytes(parent_key, 'big')) % curve_order
        if (a < curve_order and key != 0):
            key = key.to_bytes(32, 'big')
            break
        d = b'\x01' + h[32:] + i.to_bytes(4, 'big')
        #print('a failed: ' + h[:32].hex())
        #print('RETRY: ' + d.hex())
                        
    return (key, chaincode)

def get_curve_info(curvename):
    if curvename == 'secp256k1':
        return (ec.SECP256K1(), b'Bitcoin seed', SECP256K1_ORDER)
    if curvename == 'nist256p1':
        return (ec.SECP256R1(), b'Nist256p1 seed', SECP256R1_ORDER)
    if curvename == 'ed25519':
        return ('ed25519', b'ed25519 seed', None)
    if curvename == 'curve25519':
        return ('curve25519', b'curve25519 seed', None)
    raise BaseException('unsupported curve: '+curvename)

def show_testvector(name, curvename, seedhex, derivationpath):
    curve, seedmodifier, curve_order = get_curve_info(curvename)
    master_seed = bytes.fromhex(seedhex)
    k,c = seed2hdnode(master_seed, curve, seedmodifier, curve_order)
    p = publickey(k, curve)
    fpr = b'\x00\x00\x00\x00'
    path = 'm'
    print("### "+name+" for "+curvename)
    print()
    print("Seed (hex): " + seedhex)
    print()
    print('* Chain ' + path)
    print('  * fingerprint: ' + fpr.hex())
    print('  * chain code: ' + c.hex())
    print('  * private: ' + k.hex())
    print('  * public: ' + p.hex())
    depth = 0
    for i in derivationpath:
        if curve in ('ed25519', 'curve25519'):
            # no public derivation for ed25519 and curve25519
            i = i | privdev
        fpr = fingerprint(p)
        depth = depth + 1
        path = path + "/" + str(i & (privdev-1))
        if ((i & privdev) != 0):
            path = path + "<sub>H</sub>"
        k,c = derive(k, c, i, curve, curve_order)
        p = publickey(k, curve) 
        print('* Chain ' + path)
        print('  * fingerprint: ' + fpr.hex())
        print('  * chain code: ' + c.hex())
        print('  * private: ' + k.hex())
        print('  * public: ' + p.hex())
        #print(b58xprv(fpr, k, c, depth, i))
        #print(b58xpub(fpr, p, c, depth, i))
    print()

def show_testvectors(name, curvenames, seedhex, derivationpath):
    for curvename in curvenames:
        show_testvector(name, curvename, seedhex, derivationpath)


curvenames = ['secp256k1', 'nist256p1', 'ed25519', 'curve25519'];
        
show_testvectors("Test vector 1", curvenames,
                 '000102030405060708090a0b0c0d0e0f',
                 [privdev + 0, 1, privdev + 2, 2, 1000000000])
show_testvectors("Test vector 2", curvenames,
                 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                 [0, privdev + 2147483647, 1, privdev + 2147483646, 2])
            
show_testvectors("Test derivation retry", ['nist256p1'],
                 '000102030405060708090a0b0c0d0e0f',
                 [privdev + 28578, 33941])

show_testvectors("Test seed retry", ['nist256p1'],
                 'a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446',
                 [])

