from adkg.poly_commit_hybrid import PolyCommitHybrid
from pytest import mark, fixture
import logging
from adkg.polynomial import polynomials_over
from adkg.vaba import VABA
import asyncio
import numpy as np
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
# from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod
    
import time

logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

@fixture(scope="session")
def num(pytestconfig):
    return pytestconfig.getoption("num")

@fixture(scope="session")
def ths(pytestconfig):
    return pytestconfig.getoption("ths")

@fixture(scope="session")
def deg(pytestconfig):
    return pytestconfig.getoption("deg")

@fixture(scope="session")
def curve(pytestconfig):
    return pytestconfig.getoption("curve")


def get_avss_params(n, G1, ZR):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        private_keys[i] = ZR.hash(str(i).encode())
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


def gen_vector(t, deg, n, ZR):
    coeff_1 = np.array([[ZR(i+1)**j for j in range(t+1)] for i in range(n)])
    coeff_2 = np.array([[ZR(i+1)**j for j in range(t+1, deg+1)] for i in range(n)])
    hm_1 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(t+1)])
    hm_2 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(deg-t)])
    rm_1 = np.matmul(coeff_1, hm_1)
    rm_2 = np.matmul(coeff_2, hm_2)

    return (rm_1.tolist(), rm_2.tolist())

@mark.asyncio
async def test_adkg(test_router, num, ths, deg, curve):

    n = 4
    t = 1
    deg = 2

    t = int(ths)
    deg = int(deg)
    n = int(num)

    g2 = None

    from pypairing import ZR, G1, G2, blsmultiexp as multiexp, dotprod
    g2 = G2.hash(b'g')

    assert n > 3*t and deg < n-t
    
    logging.info(f"ADKG Experiment with n:{n}, t:{t}, deg:{deg}")

    g, h, pks, sks = get_avss_params(n, G1, ZR)

    sends, recvs, _ = test_router(n, maxdelay=0.01)
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    mat1, mat2 = gen_vector(t, deg, n, ZR)

    dkg_tasks = [None] * n # async task for adkg
    dkg_list = [None] * n #

    start_time = time.time()
    curve_params = (ZR, G1, multiexp, dotprod)
    from pypairing import Curve25519ZR as CoinZR, Curve25519G as CoinG1, curve25519multiexp as CoinMultiexp, curve25519dotprod as CoinDotprod


    g1 = CoinG1.hash(b'g')
    h1 = CoinG1.hash(b'h')
    pc1 = PolyCommitHybrid(g1, h1, CoinZR, CoinMultiexp)
    coin_parameters = (g1, h1, pc1, CoinZR, CoinG1, CoinMultiexp)

    for i in range(n):
        dkg = VABA(pks, sks[i], g, g2, h, n, t, deg, i, sends[i], recvs[i], pc, curve_params, (mat1, mat2))
        dkg_list[i] = dkg
        dkg_tasks[i] = asyncio.create_task(dkg.run_adkg(start_time))
    
    outputs = await asyncio.gather(
        *[dkg_list[i].output_queue.get() for i in range(n)]
    )
    for dkg in dkg_list:
        dkg.kill()
    for task in dkg_tasks:
        task.cancel()
    
    
    for i in range(1,n):
        assert outputs[i] == outputs[i-1]