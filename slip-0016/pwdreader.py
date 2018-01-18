#!/usr/bin/env python

from __future__ import print_function

from binascii import hexlify, unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import json
import os
try:
    from urllib.parse import urlparse
except:
    from urlparse import urlparse
    input = raw_input

from trezorlib.client import TrezorClient
from trezorlib.transport_hid import HidTransport

# Return path by BIP-32
def getPath(client):
    return client.expand_path("10016'/0")

# Deriving master key
def getMasterKey(client):
    bip32_path = getPath(client)
    ENC_KEY = 'Activate TREZOR Password Manager?'
    ENC_VALUE = unhexlify('2d650551248d792eabf628f451200d7f51cb63e46aadcbb1038aacb05e8c8aee2d650551248d792eabf628f451200d7f51cb63e46aadcbb1038aacb05e8c8aee')
    key = hexlify(client.encrypt_keyvalue(
        bip32_path,
        ENC_KEY,
        ENC_VALUE,
        True,
        True
    ))
    return key

# Deriving file name and encryption key
def getFileEncKey(key):
    filekey, enckey = key[:len(key) // 2], key[len(key) //2:]
    FILENAME_MESS = b'5f91add3fa1c3c76e90c90a3bd0999e2bd7833d06a483fe884ee60397aca277a'
    digest = hmac.new(filekey, FILENAME_MESS, hashlib.sha256).hexdigest()
    filename = digest + '.pswd'
    return [filename, filekey, enckey]

# File level decryption and file reading
def decryptStorage(path, key):
    cipherkey = unhexlify(key)
    with open(path, 'rb') as f:
        iv = f.read(12)
        tag = f.read(16)
        cipher = Cipher(algorithms.AES(cipherkey), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        data = ''
        while True:
            block = f.read(16)
            # data are not authenticated yet
            if block:
                data = data + decryptor.update(block).decode()
            else:
                break
        # throws exception when the tag is wrong
        data = data + decryptor.finalize().decode()
    return json.loads(data)

def decryptEntryValue(nonce, val):
    cipherkey = unhexlify(nonce)
    iv = val[:12]
    tag = val[12:28]
    cipher = Cipher(algorithms.AES(cipherkey), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    data = ''
    inputData = val[28:]
    while True:
        block = inputData[:16]
        inputData = inputData[16:]
        if block:
            data = data + decryptor.update(block).decode()
        else:
            break
        # throws exception when the tag is wrong
    data = data + decryptor.finalize().decode()
    return json.loads(data)

# Decrypt give entry nonce
def getDecryptedNonce(client, entry):
    print()
    print('Waiting for TREZOR input ...')
    print()
    if 'item' in entry:
        item = entry['item']
    else:
        item = entry['title']

    pr = urlparse(item)
    if pr.scheme and pr.netloc:
        item = pr.netloc

    ENC_KEY = 'Unlock %s for user %s?' % (item, entry['username'])
    ENC_VALUE = entry['nonce']
    decrypted_nonce =  hexlify(client.decrypt_keyvalue(
        getPath(client),
        ENC_KEY,
        unhexlify(ENC_VALUE),
        False,
        True
    ))
    return decrypted_nonce

# Pretty print of list
def printEntries(entries):
    print('Password entries')
    print('================')
    print()
    for k, v in entries.items():
        print('Entry id: #%s' % k)
        print('-------------')
        for kk, vv in v.items():
            if kk in ['nonce', 'safe_note', 'password']: continue # skip these fields
            print('*', kk, ': ', vv)
        print()
    return


def main():
    devices = HidTransport.enumerate()
    if not devices:
        print('TREZOR is not plugged in. Please, connect TREZOR and retry.')
        return

    client = TrezorClient(devices[0])

    print()
    print('Confirm operation on TREZOR')
    print()

    masterKey = getMasterKey(client)
    # print('master key:', masterKey)

    fileName = getFileEncKey(masterKey)[0]
    # print('file name:', fileName)

    path = os.path.expanduser('~/Dropbox/Apps/TREZOR Password Manager/')
    # print('path to file:', path)

    encKey = getFileEncKey(masterKey)[2]
    # print('enckey:', encKey)

    full_path = path + fileName
    parsed_json = decryptStorage(full_path, encKey)

    # list entries
    entries = parsed_json['entries']
    printEntries(entries)

    entry_id = input('Select entry number to decrypt: ')
    entry_id = str(entry_id)

    plain_nonce = getDecryptedNonce(client, entries[entry_id])

    pwdArr = entries[entry_id]['password']['data']
    pwdHex = ''.join([ hex(x)[2:].zfill(2) for x in pwdArr ])
    print('password: ', decryptEntryValue(plain_nonce, unhexlify(pwdHex)))

    safeNoteArr = entries[entry_id]['safe_note']['data']
    safeNoteHex = ''.join([ hex(x)[2:].zfill(2) for x in safeNoteArr ])
    print('safe_note:', decryptEntryValue(plain_nonce, unhexlify(safeNoteHex)))

    return

if __name__ == '__main__':
    main()
