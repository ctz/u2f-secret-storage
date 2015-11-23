"""
'Key storage' by abusing U2F devices.
"""

import os, sys
import hashlib
import json
import struct
from collections import namedtuple

from u2flib_host import u2f, register, authenticate
from u2flib_host.utils import websafe_decode, websafe_encode
import ec, ecdsa

# Some U2F appId
OUR_APPID = 'example:u2f-secret-storage'

# Get this from the user
SOME_PASSWORD = 'password'
SOME_ITERATIONS = 50000
    
def H(x): return hashlib.sha256(x).digest()

def make_reg_request():
    return dict(
            challenge = websafe_encode(os.urandom(32)),
            version = 'U2F_V2',
            appId = OUR_APPID
            )

def make_auth_request(keyhandle):
    return dict(
            version = 'U2F_V2',
            challenge = websafe_encode(os.urandom(32)),
            appId = OUR_APPID,
            keyHandle = websafe_encode(keyhandle)
            )

RegistrationResponse = namedtuple('RegistrationResponse', 'pubkey keyhandle asn1')

def decode_reg_response(b):
    assert b[0] == '\x05'
    pubkey = b[1:66]
    khl = ord(b[66])
    keyhandle = b[67:67 + khl]
    asn1 = b[67 + khl:] # stuff you can't decode without asn1
    return RegistrationResponse(pubkey, keyhandle, asn1)

AuthResponse = namedtuple('AuthResponse', 'userpresence counter sig')

def decode_auth_response(b):
    userp, counter = struct.unpack('>BL', b[:5])
    sig = b[5:]
    assert userp == 1
    return AuthResponse(userp, counter, sig)

def encode_auth_response_prefix(up):
    return struct.pack('>BL', up.userpresence, up.counter)

def decode_sig(sig):
    # awful asn1 non-parsing. we have a:
    # SEQUENCE
    #   INTEGER r
    #   INTEGER s
    
    assert sig[0] == '\x30' # sequence

    ls = ord(sig[3])
    lr = ord(sig[3 + 2 + ls])
    return (ec.nistp256.os2i(sig[4:4 + ls]),
            ec.nistp256.os2i(sig[4 + ls + 2:]))

def do_enroll():
    devs = u2f.list_devices()
    req = make_reg_request()
    result = register.register(devs, req, OUR_APPID)
    
    # check client data from token
    clientData = json.loads(websafe_decode(result['clientData']))

    assert clientData['origin'] == OUR_APPID
    assert clientData['challenge'] == req['challenge']
    assert clientData['typ'] == 'navigator.id.finishEnrollment'
   
    # check registration data
    regData = decode_reg_response(websafe_decode(result['registrationData']))

    salt = os.urandom(32)

    with open('data.json', 'w') as f:
        db = dict(
            hkey = websafe_encode(H(regData.pubkey)),
            keyhandle = websafe_encode(regData.keyhandle),
            salt = websafe_encode(salt)
        )
        json.dump(db, f)
        print 'written data to', f.name

    key = hashlib.pbkdf2_hmac('sha256', regData.pubkey + SOME_PASSWORD, salt, SOME_ITERATIONS)
    print 'secret is', key.encode('hex')

def do_auth():
    devs = u2f.list_devices()
    db = json.load(open('data.json'))

    keyhandle = websafe_decode(db['keyhandle'])
    salt = websafe_decode(db['salt'])
    hkey = websafe_decode(db['hkey'])

    req = make_auth_request(keyhandle)

    result = authenticate.authenticate(devs, req, OUR_APPID, check_only = False)

    authData = decode_auth_response(websafe_decode(result['signatureData']))

    open('sig.der', 'w').write(authData.sig)

    # decode our signature, and reconstruct the message that was signed
    sig = decode_sig(authData.sig)
    signed_message = H(req['appId']) + encode_auth_response_prefix(authData) + H(websafe_decode(result['clientData']))
    
    # recover the two possible public keys from the signature
    pubkeys = ecdsa.recover_candidate_pubkeys(ec.nistp256, hashlib.sha256, signed_message, sig)
    pubkeys = [ec.nistp256.ec2osp(pk) for pk in pubkeys]

    if H(pubkeys[0]) == hkey:
        pubkey = pubkeys[0]
    elif H(pubkeys[1]) == hkey:
        pubkey = pubkeys[1]
    else:
        print 'token is broken/lying/replayed!'
        sys.exit(1)

    key = hashlib.pbkdf2_hmac('sha256', pubkey + SOME_PASSWORD, salt, SOME_ITERATIONS)
    print 'secret is', key.encode('hex')

if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('enroll', 'auth'):
        print 'usage: %s <enroll|auth>' % sys.argv[0]
        sys.exit(1)

    if sys.argv[1] == 'enroll':
        do_enroll()
    else:
        do_auth()

