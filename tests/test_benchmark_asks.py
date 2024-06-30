from adkg.poly_commit_hybrid import PolyCommitHybrid
from pytest import mark
from adkg.polynomial import polynomials_over, get_omega, fnt_decode_step1, fnt_decode_step2
from adkg.symmetric_crypto import SymmetricCrypto
from adkg.utils.serilization import Serial
import hashlib
# from pypairing import Curve25519G as group, Curve25519ZR as field
from pypairing import G1 as group, ZR as field

class HavenMessageType:
    ECHO = 1
    READY = 2
    SEND = 3

def get_avss_params(n, t):
    # from pypairing import G1, ZR
    g = group.rand()
    h = group.rand()
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = field.random()
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys

@mark.parametrize(
    "t, n",
    [
        (42, 128),
        (31, 64),
        (10, 32),
        (5, 16),
    ])
def test_benchmark_acss_dealer(benchmark, t, n):
    value = field.rand()
    poly = polynomials_over(field)
    sr = Serial(field)
    benchmark(_get_dealer_msg, [value], t, n, poly, field, sr)

@mark.parametrize(
    "t, n",
    [
        (42, 128),
        (31, 64),
        (10, 32),
        (5, 16),
    ])
def test_benchmark_hybrid_haven_receiver(benchmark, t, n):
    value = field.rand()
    poly = polynomials_over(field)
    sr = Serial(field)
    sc = 1
    shares, commits, msgs = _get_dealer_msg([value], t, n, poly, field, sr)
    shares[0].extend(msgs)
    benchmark( _handle_dealer_msg, shares[0], t, n, 0, sr, sc)

@mark.parametrize(
    "t, n",
    [
        (42, 128),
        (31, 64),
        (10, 32),
        (5, 16),
    ])
def test_benchmark_reconstruction(benchmark, t, n):
    value = field.rand()
    poly = polynomials_over(field)
    sr = Serial(field)
    sc = 1
    shares, commits, msgs = _get_dealer_msg([value], t, n, poly, field, sr)
    benchmark(recv_eval_share, shares, commits[0], n, t, field, sr)

def ifft(shares, ZR, omega2, n):
    polynomial = polynomials_over(ZR)
    zs = list(shares.keys())
    ys = list(shares.values())
    as_, ais_ = fnt_decode_step1(polynomial, zs, omega2, n)
    prec_ = fnt_decode_step2(polynomial, zs, ys, as_, ais_, omega2, n)
    return prec_

def hash_eval(self, j, fj):
    import hashlib
    t = str(j) + str(fj)
    s = hashlib.sha256()
    s.update(t.encode())
    return s.digest()

def check_rec(phi, omega, commits, n, sn):
    ys = list(phi.evaluate_fft(omega, n))
    for j in range(sn):
        if hash_eval(j+1, ys[j]) != commits[j]:
            return False
    return True
def recv_eval_share(sk_list, commits, n, t, ZR, sr):
    nn = n
    nn = nn if nn & nn - 1 == 0 else 2 ** nn.bit_length()
    omega2 = get_omega(ZR, 2 * nn)
    omega = omega2 ** 2
    x0s = 0
    eval_shares = {}

    for j in range(len(sk_list)):
        # print(i,view,j)
        skij = sk_list[j]
        skij = sr.deserialize_f(skij)
        if commits[j] != hash_eval(j+1, skij):
            continue
        eval_shares[j] = skij
        if len(eval_shares) == t + 1:
            shares = dict(list(eval_shares.items())[: t + 1])
            phi_rec = ifft(shares, ZR, omega2, nn)
            if check_rec(phi_rec, omega, commits, nn, n):
                x0s = phi_rec(0)
            else:
                x0s = 0
            return
def decode_proposal(proposal, sr, sc, n):

    shares_size = sc * 32
    shares = sr.deserialize_fs(proposal[0: 0 + shares_size])

    proposal = proposal[shares_size: ]
    commits_array = [proposal[i:i + 32] for i in range(0, len(proposal), 32)]
    commits = [commits_array[i:i + n] for i in range(0, len(commits_array), n)]
    return (shares, commits, proposal)

def verify_proposal(shares, commits, my_id, sc):
    for i in range(sc):
        if hash_eval(my_id + 1, shares[i]) != commits[i][my_id]:
            return False
    return True

def _handle_dealer_msg(msg, t, n, my_id, sr, sc):
    shares, commits, __m = decode_proposal(msg, sr, sc, n)
    ret = verify_proposal(shares, commits, my_id, sc)
    return ret, __m


def hash_eval(j, fj):
    import hashlib
    t = str(j) + str(fj)
    s = hashlib.sha256()
    s.update(t.encode())
    return s.digest()

def _get_dealer_msg(values, t, n, poly, field, sr):
    # Sample B random degree-(t) polynomials of form φ(·)
    # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
    # The same as B (batch_size)
    """
    while len(values) % (batch_size) != 0:
        values.append(0)
    """
    sc = len(values)
    phi = [None] * sc
    commitments = [None] * sc

    ys = [None] * sc
    nn = n
    nn = nn if nn & nn - 1 == 0 else 2 ** nn.bit_length()
    omega2 = get_omega(field, 2 * nn)
    omega = omega2 ** 2

    for k in range(sc):
        phi[k] = poly.random(t, values[k])
        ys[k] = list(phi[k].evaluate_fft(omega, nn))
    for k in range(sc):
        commitments[k] = [hash_eval(j, ys[k][j - 1]) for j in range(1, n + 1)]

    shares = [bytearray() for _ in range(n)]
    commits = bytearray()

    for i in range(n):
        phis_i = [ys[k][i] for k in range(sc)]
        shares[i].extend(sr.serialize_fs(phis_i))

    for i in range(sc):
        commits.extend(b"".join(commitments[i]))

    return shares, commitments, commits