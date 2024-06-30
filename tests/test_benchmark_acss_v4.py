from adkg.broadcast.crypto import coin
from adkg.poly_commit_hybrid import PolyCommitHybrid
from pytest import mark
from adkg.polynomial import polynomials_over, get_omega, fnt_decode_step1, fnt_decode_step2
from adkg.symmetric_crypto import SymmetricCrypto
from adkg.utils.serilization import Serial
import hashlib
from pypairing import Curve25519G as group, Curve25519ZR as field, curve25519multiexp as multiexp
# from pypairing import G1 as group, ZR as field, blsmultiexp as multiexp

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
    values = [field.rand()]
    sr = Serial(field)
    g, h, pks, sks = get_avss_params(n, t)
    pc = PolyCommitHybrid(g, h, field, multiexp)
    sc = 1
    sc0 = 0
    poly = polynomials_over(field)
    benchmark(_get_dealer_msg, sc, sc0, n, t, g, field, pks, poly, poly, pc, pc, sr, sr, values)

@mark.parametrize(
    "t, n",
    [
        (42, 128),
        (31, 64),
        (10, 32),
        (5, 16),
    ])
def test_benchmark_hybrid_haven_receiver(benchmark, t, n):
    values = [field.rand()]
    sr = Serial(field)
    g, h, pks, sks = get_avss_params(n, t)
    pc = PolyCommitHybrid(g, h, field, multiexp)
    sc = 1
    sc0 = 0
    poly = polynomials_over(field)
    datab = _get_dealer_msg(sc, sc0, n, t, g, field, pks, poly, poly, pc, pc, sr, sr, values)
    dual_codes = {}
    dual_codes[(t+1, n)] = gen_dual_code(n, t + 1, poly, field)
    benchmark(_recv_dealer_msg, 0, datab, sr, sr, n, t, sc, sc0, 0, g, pc, sks, dual_codes, multiexp)


@mark.parametrize(
    "t, n",
    [
        (42, 128),
        (31, 64),
        (10, 32),
        (5, 16),
    ])
def test_benchmark_reconstruction(benchmark, t, n):
    values = [field.rand()]
    sr = Serial(field)
    g, h, pks, sks = get_avss_params(n, t)
    pc = PolyCommitHybrid(g, h, field, multiexp)
    sc = 1
    sc0 = 0
    poly = polynomials_over(field)
    phis, datab = _get_dealer_msg1(sc, sc0, n, t, g, field, pks, poly, poly, pc, pc, sr, sr, values)
    dual_codes = {}
    dual_codes[(t+1, n)] = gen_dual_code(n, t + 1, poly, field)
    msg, commits = _recv_dealer_msg(0, datab, sr, sr, n, t, sc, sc0, 0, g, pc, sks, dual_codes, multiexp)
    benchmark(reconstruct, phis, n, t, commits[0], g, field)


def decode_proposal(proposal, sr, sr1, n, t, sc, sc0, my_id):
    g_size =  sr.g_size
    g1_size =  sr1.g_size
    c_size = 32
    # deserializing commitments

    com_size = g_size * ( t + 1) * sc0
    com_size1 = g1_size *  n * (sc - sc0)

    commits_all =  []
    import time
    tm = time.time()
    commits_all1 =  sr1.deserialize_gs(proposal[com_size: com_size + com_size1])
    x = time.time() - tm
    print(f'time: {x} {len(commits_all1)}')
    commits = [(commits_all[i * ( t + 1):(i + 1) * ( t + 1)] if i < sc0 else commits_all1[(i - sc0) *  n:(i + 1 - sc0) *  n])
               for i in range(sc)]
    # deserializing ciphertexts
    # IMPORTANT: Here 32 additional bytes are used in the ciphertext for padding
    ctx_per_node = (sc0 * 2 + sc - sc0 + 1)
    ctx_size = c_size * ctx_per_node *  n
    my_ctx_start = com_size + com_size1 + c_size * ctx_per_node *  my_id
    my_ctx_end = my_ctx_start + c_size * ctx_per_node
    ctx_bytes = proposal[my_ctx_start:my_ctx_end]

    # deserializing the ephemeral public key
    # tm = time.time()
    ephkey =  sr.deserialize_g(proposal[com_size + com_size1 + ctx_size:])
    #  veri_time2 += (time.time() - tm)

    return (ctx_bytes, commits, ephkey)

def gen_dual_code(n, degree, poly, CoinZR):
    def get_vi(i, n):
        out = CoinZR(1)
        for j in range(1, n + 1):
            if j != i:
                out = out / (i - j)
        return out

    q = poly.random(n - degree - 2)
    q_evals = [q(i + 1) for i in range(n)]
    return [q_evals[i] * get_vi(i + 1, n) for i in range(n)]

def check_degree(claimed_degree, commitments, dual_codes, CoinMultiexp, g1):
    if (claimed_degree, len(commitments)) not in dual_codes.keys():
         dual_codes[(claimed_degree, len(commitments))] =  gen_dual_code(len(commitments), claimed_degree, poly1)

    dual_code =  dual_codes[(claimed_degree, len(commitments))]
    check =  CoinMultiexp(commitments, dual_code)

    return check ==  g1 ** 0

def verify_proposal(dealer_id, dispersal_msg, commits, ephkey, private_key, sr, sr1, sc, sc0, my_id, g1, poly_commit, t, dual_codes, CoinMultiexp):
    shared_key = ephkey **  private_key

    try:
        sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
    except ValueError as e:  # TODO: more specific exception
        return False

    shares =  []
    shares1 =  sr1.deserialize_fs(sharesb[sc0 * 2 * 32:])
    phis, phis_hat = shares[:sc0], shares[sc0:]
    phis.extend(shares1)

    for i in range(0, sc0):
        if not poly_commit.verify_eval(commits[i],  my_id + 1, phis[i], phis_hat[i]):
            return False

    for i in range(sc0, sc):
        if not (check_degree(t + 1, commits[i], dual_codes, CoinMultiexp, g1) and  g1 ** phis[i] == commits[i][ my_id]):
            return False
    return True, shares1

def reconstruct(sharess, n, t, commits, g1, CoinZR):
    shares = {}
    for i in range(t+1):
        shares[i] = sharess[i][0]
    for k, phi_k in shares.items():
        coeff = commits[k]

        if (g1 ** phi_k) != coeff:
            assert False

    evals = coin.eval(0, shares,  CoinZR)

    # @profile
def _recv_dealer_msg(dealer_id, _m, sr, sr1, n, t, sc, sc0, my_id, g1, poly_commit, private_key, dual_codes, CoinMultiexp):
    dispersal_msg, commits, ephkey =  decode_proposal(_m, sr, sr1, n, t, sc, sc0, my_id)
    ret, shares1 =  verify_proposal(dealer_id, dispersal_msg, commits, ephkey, private_key[my_id], sr, sr1, sc, sc0, my_id, g1,
                    poly_commit, t, dual_codes, CoinMultiexp)
    assert ret
    return shares1, commits


def _get_dealer_msg(sc, sc0, n, t, g, field, public_keys, poly, poly1, poly_commit, poly_commit1, sr, sr1, values):
    # Sample B random degree-(t) polynomials of form φ(·)
    # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
    # The same as B (batch_size)
    """
    while len(values) % (batch_size) != 0:
        values.append(0)
    """
    phi = [None] * sc
    phi_hat = [None] * sc
    commitments = [None] * sc

    for k in range(sc):
        if k < sc0:
            phi[k] =  poly.random( t, values[k])
            phi_hat[k] =  poly.random( t,  field.rand())
            commitments[k] =  poly_commit.commit(phi[k], phi_hat[k])
        else:
            phi[k] =  poly1.random( t, values[k])
            commitments[k] =  poly_commit1.commit_to_eval2( n,  t, phi[k], None)

    ephemeral_secret_key =  field.rand()
    ephemeral_public_key =  g ** ephemeral_secret_key
    dispersal_msg_list = bytearray()
    for i in range(n):
        shared_key =  public_keys[i] ** ephemeral_secret_key
        phis_i1 = [phi[k](i + 1) for k in range(sc0, sc)]
        ciphertext = SymmetricCrypto.encrypt(shared_key.__getstate__(),
                                               sr1.serialize_fs(
                                                 phis_i1))
        dispersal_msg_list.extend(ciphertext)

    # g_commits = commitments[0]
    # for k in range(1, sc0):
    #     g_commits = g_commits + commitments[k]
    # datab =  sr.serialize_gs(g_commits)  # Serializing commitments
    datab = bytearray()

    g_commits1 = commitments[sc0]
    for k in range(sc0 + 1, sc):
        g_commits1 = g_commits1 + commitments[k]
    datab.extend( sr1.serialize_gs(g_commits1))
    # sr1.deserialize_gs(datab)
    datab.extend(dispersal_msg_list)
    datab.extend( sr.serialize_g(ephemeral_public_key))
    return bytes(datab)

def _get_dealer_msg1(sc, sc0, n, t, g, field, public_keys, poly, poly1, poly_commit, poly_commit1, sr, sr1, values):
    # Sample B random degree-(t) polynomials of form φ(·)
    # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
    # The same as B (batch_size)
    """
    while len(values) % (batch_size) != 0:
        values.append(0)
    """
    phi = [None] * sc
    phi_hat = [None] * sc
    commitments = [None] * sc

    for k in range(sc):
        if k < sc0:
            phi[k] =  poly.random( t, values[k])
            phi_hat[k] =  poly.random( t,  field.rand())
            commitments[k] =  poly_commit.commit(phi[k], phi_hat[k])
        else:
            phi[k] =  poly1.random( t, values[k])
            commitments[k] =  poly_commit1.commit_to_eval2( n,  t, phi[k], None)

    ephemeral_secret_key =  field.rand()
    ephemeral_public_key =  g ** ephemeral_secret_key
    dispersal_msg_list = bytearray()
    phis = []
    for i in range(n):
        shared_key =  public_keys[i] ** ephemeral_secret_key
        phis_i1 = [phi[k](i + 1) for k in range(sc0, sc)]
        phis.append(phis_i1)
        ciphertext = SymmetricCrypto.encrypt(shared_key.__getstate__(),
                                               sr1.serialize_fs(
                                                 phis_i1))
        dispersal_msg_list.extend(ciphertext)

    # g_commits = commitments[0]
    # for k in range(1, sc0):
    #     g_commits = g_commits + commitments[k]
    # datab =  sr.serialize_gs(g_commits)  # Serializing commitments
    datab = bytearray()

    g_commits1 = commitments[sc0]
    for k in range(sc0 + 1, sc):
        g_commits1 = g_commits1 + commitments[k]
    datab.extend( sr1.serialize_gs(g_commits1))
    # sr1.deserialize_gs(datab)
    datab.extend(dispersal_msg_list)
    datab.extend( sr.serialize_g(ephemeral_public_key))
    return phis, bytes(datab)