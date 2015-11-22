# -*- coding: utf8 -*-
"""
Hyper-crappy EC over GF(p) implementation.
Please don't use for anything serious.
"""

import operator
import random

def even(v):
    return v & 1 == 0

def egcd(x, y):
    """
    Extended euclidian algorithm.
    Finds gcd(x,y) plus the coefficients of Bézout's identity.
    """
    assert x > 0 and y > 0
    g = 1
    while even(x) and even(y):
        x = x / 2
        y = y / 2
        g = g * 2
    u, v = x, y
    A, B, C, D = 1, 0, 0, 1

    while u != 0:
        while even(u):
            u = u / 2
            if even(A) and even(B):
                A = A / 2
                B = B / 2
            else:
                A = (A + y) / 2
                B = (B - x) / 2

        while even(v):
            v = v / 2
            if even(C) and even(D):
                C = C / 2
                D = D / 2
            else:
                C = (C + y) / 2
                D = (D - x) / 2

        if u >= v:
            u = u - v
            A = A - C
            B = B - D
        else:
            v = v - u
            C = C - A
            D = D - B

    return g * v, C, D

class modint(object):
    """
    A thing like an int/long, but does computations mod some prime p.
    Get the result out by int- or hex-ing the object.
    """
    def __init__(self, v, p):
        self.p = p
        self.v = v % p

    def __repr__(self):
        return repr(self.v)

    def __hex__(self):
        return hex(self.v)

    def __int__(self):
        return self.v

    def op(self, other, op):
        if isinstance(other, (int, long)):
            other = modint(other, self.p)
        r = op(self.v, other.v) % self.p
        return modint(r, self.p)

    def inverse(self):
        gcd, a, b = egcd(self.v, self.p)
        assert gcd == 1, 'cannot find inverse; not relatively prime to p'
        if a < 0:
            a += self.p
        assert int(self * a) == 1
        return modint(a, self.p)

    def sqrt(self):
        # only works for such primes; this is algorithm 3.36 from hac
        assert self.p % 4 == 3
        pp = (self.p + 1) / 4
        r = self ** pp
        return r

    def __eq__(self, other): return int(self) == int(other)
    def __ne__(self, other): return int(self) != int(other)
    def __add__(self, other): return self.op(other, operator.add)
    def __sub__(self, other): return self.op(other, operator.sub)
    def __div__(self, other): return self.op(other, lambda x, y: operator.mul(x, int(modint(y, self.p).inverse())))
    def __rdiv__(self, other): return self.op(other, lambda y, x: operator.mul(x, int(modint(y, self.p).inverse())))
    def __mul__(self, other): return self.op(other, operator.mul)
    def __rmul__(self, other): return self.op(other, operator.mul)
    def __pow__(self, other): return self.op(other, lambda x, y: pow(x, y, self.p))

def modp(p, *args):
    """
    Convert a bunch of arguments to be modints mod p.
    """
    return [modint(a, p) for a in args]

class point(object):
    """
    An affine EC point.
    """
    def __init__(self):
        self.x = 0
        self.y = 0
        self.at_inf = False

    def __repr__(self):
        if self.at_inf:
            return '<point O>'
        else:
            return '<point 0x%x, 0x%x>' % (self.x, self.y)

    def __eq__(self, other):
        return self.at_inf == other.at_inf and \
               self.x == other.x and \
               self.y == other.y

    def dup(self):
        if self.at_inf:
            return point.inf()
        else:
            return point.xy(self.x, self.y)
    
    @staticmethod
    def xy(x, y):
        r = point()
        r.x = x
        r.y = y
        return r

    @staticmethod
    def inf():
        r = point()
        r.at_inf = True
        return r

class curve_gfp(object):
    """
    A general short weierstrass curve over a GF(p) field.
    """
    def __init__(self, p, n, a, b, G):
        self.p, self.n, self.a, self.b, self.G = p, n, a, b, G

    # conversions
    # fe: field element
    # os: octet string
    # i: integer
    # ec: point on curve
    # p suffix: padded (fixed-length encoding)
    def os2i(self, os): return int(os.encode('hex'), 16)
    def fe2i(self, fe): return fe
    def i2fe(self, i): return i % self.n
    def fe_bytes(self): return (self.n.bit_length() + 7) / 8
    def os2ecp(self, os):
        fe_bytes = self.fe_bytes()
        assert os[0] == '\x04' # only support uncompressed
        assert len(os) == 1 + fe_bytes + fe_bytes
        return point.xy(self.os2i(os[1:1 + fe_bytes]), self.os2i(os[-fe_bytes:]))

    def ec2osp(self, point):
        if point.at_inf:
            return '\x00'
        
        fe_bytes = self.fe_bytes()
        xy = (('%0' + str(fe_bytes * 2) + 'x') * 2) % (point.x, point.y)
        return '\x04' + xy.decode('hex')

    def generate_key(self, rand = random.SystemRandom()):
        """
        Makes a random field element and multiplies the base
        point by it.  This forms a key pair.
        """
        k = rand.randrange(0, self.n - 1)
        return k, self.base_mul(k)

    def base_mul(self, d):
        """
        Multiplies scalar d by the base point.
        """
        return self.point_mul(d, self.G)

    def point_add(self, a, b):
        """
        Point addition.  This is from SEC1 section 2.2.1.
        """

        if a.at_inf and b.at_inf: return point.inf()
        if a.at_inf: return b.dup()
        if b.at_inf: return a.dup()
        if a == b: return self.point_double(a)
        if a.x == b.x and a.y == -b.y: return point.inf()

        x1, y1, x2, y2 = modp(self.p, a.x, a.y, b.x, b.y)
        L = (y2 - y1) / (x2 - x1)
        x3 = L ** 2 - x1 - x2
        y3 = L * (x1 - x3) - y1
        return point.xy(int(x3), int(y3))

    def point_sub(self, a, b):
        """
        Point subtraction.
        """
        assert not b.at_inf
        negb = point.xy(b.x, -b.y)
        return self.point_add(a, negb)
        
    def point_double(self, a):
        """
        Point doubling.  This is SEC1 section 2.2.1, clause 5.
        """
        x1, y1 = modp(self.p, a.x, a.y)
        L = (3 * x1 ** 2 + self.a) / (2 * y1)
        x3 = L ** 2 - 2 * x1
        y3 = L * (x1 - x3) - y1
        return point.xy(int(x3), int(y3))

    def point_mul(self, d, P):
        """
        Point multiplication of P by a scalar d.
        This is trivial double-and-add.

        It has *gaping* side channels which will leak d
        to anybody watching.
        """
        Q = point.inf()
        for i in range(d.bit_length()):
            if (1 << i) & d:
                Q = self.point_add(Q, P)
            P = self.point_double(P)
        return Q

    def point_on_curve(self, P):
        """
        Returns true if P satisfies the curve equation.
        """
        x, y = modp(self.p, P.x, P.y)
        lhs = y ** 2
        rhs = x ** 3 + x * self.a + self.b
        return lhs == rhs

    def points_at_x(self, x):
        """
        Returns the points with given x coordinate.
        """
        x, = modp(self.p, x)
        rhs = x ** 3 + x * self.a + self.b
        y = rhs.sqrt()
        return point.xy(int(x), int(y)), point.xy(int(x), -int(y))

# It's NIST P-256
nistp256 = curve_gfp(
        p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        G = point.xy(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5))

if __name__ == '__main__':
    S = point.xy(0xde2444bebc8d36e682edd27e0f271508617519b3221a8fa0b77cab3989da97c9,
                 0xc093ae7ff36e5380fc01a5aad1e66659702de80f53cec576b6350b243042a256)
    assert nistp256.point_on_curve(S)

    T = point.xy(0x55a8b00f8da1d44e62f6b3b25316212e39540dc861c89575bb8cf92e35e0986b,
                 0x5421c3209c2d6c704835d82ac4c3dd90f61a8a52598b9e7ab656e9d8c8b24316)
    assert nistp256.point_on_curve(T)

    # addition
    R = point.xy(0x72b13dd4354b6b81745195e98cc5ba6970349191ac476bd4553cf35a545a067e,
                 0x8d585cbb2e1327d75241a8a122d7620dc33b13315aa5c9d46d013011744ac264)
    assert R == nistp256.point_add(S, T)
    assert nistp256.point_on_curve(R)

    # subtraction
    R = point.xy(0xc09ce680b251bb1d2aad1dbf6129deab837419f8f1c73ea13e7dc64ad6be6021,
                 0x1a815bf700bd88336b2f9bad4edab1723414a022fdf6c3f4ce30675fb1975ef3)
    assert R == nistp256.point_sub(S, T)
    assert nistp256.point_on_curve(R)

    # doubling
    R = point.xy(0x7669e6901606ee3ba1a8eef1e0024c33df6c22f3b17481b82a860ffcdb6127b0,
                 0xfa878162187a54f6c39f6ee0072f33de389ef3eecd03023de10ca2c1db61d0c7)
    assert R == nistp256.point_double(S)
    assert nistp256.point_on_curve(R)

    # pointmul
    d = 0xc51e4753afdec1e6b6c6a5b992f43f8dd0c7a8933072708b6522468b2ffb06fd
    R = point.xy(0x51d08d5f2d4278882946d88d83c97d11e62becc3cfc18bedacc89ba34eeca03f,
                 0x75ee68eb8bf626aa5b673ab51f6e744e06f8fcf8a6c0cf3035beca956a7b41d5)
    assert R == nistp256.point_mul(d, S)
    assert nistp256.point_on_curve(R)

    # crap quality key gen
    k, Q = nistp256.generate_key()
    assert nistp256.point_on_curve(Q)
