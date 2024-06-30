from adkg.config import HbmpcConfig
from adkg.ipc import ProcessProgramRunner
from adkg.poly_commit_hybrid import PolyCommitHybrid
# from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
import asyncio
import time
import logging
import uvloop
import numpy as np

from adkg.vaba import VABA

logger = logging.getLogger("benchmark_logger")
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

def get_avss_params(n, G1, ZR):
    g, h = G1.hash(b'g'), G1.hash(b'h') 
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

async def _run(peers, n, t, k, my_id, start_time, ver, blscoin, blscurve):
    g2 = None

    # if not blscurve:
    #     from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod
    # else:
    from pypairing import ZR, G1, G2, blsmultiexp as multiexp, dotprod

    # if not blscoin:
    #     from pypairing import Curve25519ZR as CoinZR, Curve25519G as CoinG1, curve25519multiexp as CoinMultiexp, curve25519dotprod as CoinDotprod
    # else:
    from pypairing import ZR as CoinZR, G1 as CoinG1, G2 as CoinG2, blsmultiexp as CoinMultiexp, dotprod as CoinDotprod
    g2 = CoinG2.hash(b'g')

    g1 = CoinG1.hash(b'g')
    h1 = CoinG1.hash(b'h')
    pc1 = PolyCommitHybrid(g1, h1, CoinZR, CoinMultiexp)
    coin_parameters = (g1, h1, pc1, CoinZR, CoinG1, CoinMultiexp)

    g, h, pks, sks = get_avss_params(n, G1, ZR)
    logging.info(type(g))
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    deg = k
    mat1, mat2 = gen_vector(t, deg, n, ZR)
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("")
        logging.debug(f"Starting ADKG: {(my_id)}")
        logging.debug(f"Start time: {(start_time)}, diff {(start_time-int(time.time()))}")

        benchmark_logger = logging.LoggerAdapter(
           logging.getLogger("benchmark_logger"), {"node_id": my_id}
        )
        curve_params = (ZR, G1, multiexp, dotprod)
        # if ver:
        from adkg.adkg import ADKG
        # else:
        #     from adkg.adkg2 import ADKG
        with VABA(pks, sks[my_id], g, g2, h, n, t, deg, my_id, send, recv, pc, curve_params, (mat1, mat2)) as adkg:
            while True:
                if time.time() > start_time:
                    break
                time.sleep(0.1)
            begin_time = time.time()
            logging.info(f"ADKG start time: {(begin_time)}")
            adkg_task = asyncio.create_task(adkg.run_adkg(begin_time))
            await adkg_task
            adkg.kill()
            adkg_task.cancel()
            # adkg.print_task("outside")
        bytes_sent = runner.node_communicator.bytes_sent
        msg_sent = runner.node_communicator.msg_sent
        for k, v in runner.node_communicator.bytes_count.items():
            logging.info(f"[{my_id}] Bytes Sent: {k}:{v} which is {round((100 * v) / bytes_sent, 3)}%")
        logging.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}, msg count: {msg_sent}")
        benchmark_logger.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}, msg count: {msg_sent}")

if __name__ == "__main__":
    from adkg.config import HbmpcConfig
    logging.info("Running ADKG ...")
    HbmpcConfig.load_config()
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.k,
                HbmpcConfig.my_id,
                HbmpcConfig.time,
                HbmpcConfig.v,
                HbmpcConfig.b,
                HbmpcConfig.bc
            )
        )
    finally:
        loop.close()

