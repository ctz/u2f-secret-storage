"""
Comedy ECDSA signing and verification.
Don't use this for anything important.
"""

import ec

def _hash_message(curve, hash, message):
    H = hash(message).digest()
    e = curve.os2i(H)
    # nb. we don't implement case where |H| > curve |n|.
    # doesn't matter for support curves/hash functions
    return e

def sign(curve, hash, priv, message):
    """
    Sign given message, hashing it with hash.
    Use the given private key (a scalar), on given curve.
    """
    e = _hash_message(curve, hash, message)

    while True:
        k, R = curve.generate_key()
        xr = curve.fe2i(R.x)
        e, d, k, xr = ec.modp(curve.n, e, priv, k, xr)
        s = (e + xr * d) / k
        if int(xr) != 0 and int(s) != 0:
            return int(xr), int(s)

def verify(curve, hash, pub, message, sig):
    """
    Verify given signature on message (hashed with given
    hash function).  Public key is on the curve.

    Returns nothing on success, raises on error.
    """
    r, s = sig
    error = ValueError('invalid signature')

    if r < 1 or r >= curve.n or s < 1 or s >= curve.n:
        raise error

    e = _hash_message(curve, hash, message)
    e, r, s = ec.modp(curve.n, e, r, s)
    w = 1 / s
    u1 = e * w
    u2 = r * w

    p1 = curve.base_mul(int(u1))
    p2 = curve.point_mul(int(u2), pub)

    R = curve.point_add(p1, p2)
    if R.at_inf:
        raise error

    xr = curve.fe2i(R.x)
    v, = ec.modp(curve.n, xr)
    if v != r:
        raise error

def recover_candidate_pubkeys(curve, hash, message, sig):
    """
    Recovers the two possible public keys
    corresponding to the signature on given message.
    """
    r, s = sig

    e = _hash_message(curve, hash, message)
    Rp, Rn = curve.points_at_x(curve.i2fe(r))

    r, = ec.modp(curve.n, r)
    rinv = 1 / r

    out = []
    for R in (Rp, Rn):
        p = curve.point_mul(int(rinv),
                            curve.point_sub(curve.point_mul(s, R),
                                            curve.base_mul(e)))
        out.append(p)
    return out

if __name__ == '__main__':
    import hashlib
    H = hashlib.sha256

    msg = 'e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3'.decode('hex')
    Q = ec.point.xy(0xe424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c, 0x970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927)
    sig = (0xbf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f, 0x17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c)

    verify(ec.nistp256, H, Q, msg, sig)
    
    try:
        verify(ec.nistp256, H, Q, msg + 'foo', sig)
        assert False, 'signature was invalid'
    except ValueError:
        pass

    k, Q = ec.nistp256.generate_key()
    print 'pub', Q
    msg = 'hello world'
    sig = sign(ec.nistp256, H, k, msg)
    verify(ec.nistp256, H, Q, msg, sig)

    points = recover_candidate_pubkeys(ec.nistp256, H, msg, sig)
    print points
