"""An implementation of (unique) threshold signatures based on
Gap-Diffie-Hellman Boldyreva, 2002 https://eprint.iacr.org/2002/118.pdf

Dependencies:
    Charm, http://jhuisi.github.io/charm/ a wrapper for PBC (Pairing
    based crypto)

"""
from pypairing import Curve25519ZR as ZR, Curve25519G as G1
# from pypairing import G1, ZR, pair, G2
from base64 import encodebytes, decodebytes
from operator import mul, add
from functools import reduce

g1 = G1.hash(b"honeybadgerh")

ZERO = ZR(0)
ONE = ZR(1)

import hashlib


def test_compute_time(n, t, P, P1, g, h, commits):
    evals = [None] * n
    import random
    key_proposal = set(random.sample(range(n + 1), t + 1))
    shares_bit = set(random.sample(range(n + 1), t + 1))
    shares = {}
    for i in shares_bit:
        shares[i+1] = (P(i), P1(i))

    for k, (phi_k, phihat_k) in shares.items():
        coeff = g.identity()
        for kk in key_proposal:
            coeff *= commits[kk]
        if (g ** phi_k) * (h ** phihat_k) != coeff:
            # logging.info("Verification Fail")
            assert False
    eval(0, shares)
    hash(evals[0], 0)

def sign_set(g, pk, sk, Sj):
    r = sk.rand()
    R = g ** r
    hash_object = hashlib.sha256()
    hash_object.update((str(R) + str(pk) + str(Sj)).encode())
    h = int(hash_object.hexdigest(), 16)
    s = r + sk * h
    return (R, s)


def verify_sig_set(g, pk, msg):
    m, (R, s) = msg
    # S = eval(m)
    # # if len(S) <= self.n - self.t:
    # #     return False
    hash_object = hashlib.sha256()
    hash_object.update((str(R) + str(pk) + m).encode())
    h = int(hash_object.hexdigest(), 16)
    if (g ** s) / (pk ** h) != R:
        return False
    return True

def lagrange(s, j, ONE):
    """ """
    # Assert S is a subset of range(0,self.l)
    # assert len(s) == self.k
    # assert type(s) is set
    # assert s.issubset(range(0, self.l))
    s = sorted(s)
    # assert j in s
    # assert 0 <= j < self.l
    num = reduce(mul, [0 - jj - 1 for jj in s if jj != j], ONE)
    den = reduce(mul, [j - jj for jj in s if jj != j], ONE)  # noqa: E272
    # assert num % den == 0
    return num / den


# def combine_shares(sigs):
#     """ """
#     # sigs: a mapping from idx -> sig
#     s = set(sigs.keys())
#
#     # for j, sig in sigs.items():
#     #     print("sig type", type(sig), type(self.lagrange(s, j)))
#
#     res = reduce(mul, [sig ** lagrange(s, j) for j, sig in sigs.items()], G2.identity())
#     return res

def combine_shares(ys, ZR):
    """ """
    # sigs: a mapping from idx -> sig
    s = set(ys.keys())

    # for j, sig in sigs.items():
    #     print("sig type", type(sig), type(self.lagrange(s, j)))
    ret0, ret1 = ZR(0), ZR(0)
    for j, y in ys.items():
        t = lagrange(s, j, ZR(1))
        tt = y * t
        # rt = r * t
        ret0 += tt
        # ret1 += rt
    return ret0, ret1

def combine_shares2(ys, ZR):
    """ """
    # sigs: a mapping from idx -> sig
    s = set(ys.keys())

    # for j, sig in sigs.items():
    #     print("sig type", type(sig), type(self.lagrange(s, j)))
    from pypairing import G2
    ret0, ret1 = G2.identity(), ZR(0)
    for j, y in ys.items():
        t = lagrange(s, j, ZR(1))
        tt = y ** t
        # rt = r * t
        ret0 *= tt
        # ret1 += rt
    return ret0, ret1

    # res = reduce(add, [lagrange(s, j) * y for j, y in ys.items()], ZR(0))
    # return res


def check(shares, t):
    y = combine_shares(dict(list(shares.items())[: t + 1]))
    i = 1
    # j = 7
    while i + t + 1 <= len(shares):
        y2 = combine_shares(dict(list(shares.items())[i: i + t + 1]))
        if y != y2:
            return False
        i += 1
    return True


def eval(i, shares, ZR):
    x = combine_shares(shares, ZR)
    return x

def eval_bls_coin(i, shares, ZR):
    x = combine_shares2(shares, ZR)
    return x

def hash(x, i):
    import hashlib
    t = str(x) + str(i)
    s = hashlib.sha256()
    s.update(t.encode())
    return int(s.hexdigest(), 16)


class TBLSPublicKey(object):
    """ """

    def __init__(self, vk):
        """ """
        # self.l = l  # noqa: E741
        # self.k = k
        self.VK = vk
        # self.VKs = vks

    def lagrange(self, s, j):
        """ """
        # Assert S is a subset of range(0,self.l)
        # assert len(s) == self.k
        # assert type(s) is set
        # assert s.issubset(range(0, self.l))
        s = sorted(s)
        # assert j in s
        # assert 0 <= j < self.l
        num = reduce(mul, [0 - jj - 1 for jj in s if jj != j], ONE)
        den = reduce(mul, [j - jj for jj in s if jj != j], ONE)  # noqa: E272
        # assert num % den == 0
        return num / den

    def hash_message(self, m):
        """ """
        return G2.hash(m)

    # def verify_share(self, sig, i, h):
    #     """ """
    #     assert 0 <= i < self.l
    #     b = self.VKs[i]
    #     assert pair(sig, g2) == pair(h, b)
    #     return True

    # def verify_signature(self, sig, h):
    #     """ """
    #     print("vk", type(sig), type(g1), type(h), type(self.VK))
    #     assert pair(g1, sig) == pair(self.VK, h)
    #     return True

    def combine_shares(self, sigs):
        """ """
        # sigs: a mapping from idx -> sig
        s = set(sigs.keys())
        assert s.issubset(range(self.l))

        # for j, sig in sigs.items():
        #     print("sig type", type(sig), type(self.lagrange(s, j)))

        res = reduce(mul, [sig ** self.lagrange(s, j) for j, sig in sigs.items()], G2.identity())
        return res


class TBLSPrivateKey(TBLSPublicKey):
    """ """

    def __init__(self, sk):
        """ """
        # self.i = i
        self.SK = sk
        # print("SK type", type(self.SK))

    def sign(self, h):
        """ """
        return h ** self.SK
