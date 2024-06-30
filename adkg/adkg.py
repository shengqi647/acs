from collections import defaultdict

from adkg.broadcast.optqrbc_bracha import optqrbc_b
from adkg.broadcast.optqrbc_validated import optqrbc_v
from adkg.polynomial import polynomials_over
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss_ht import ACSS_HT

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc
from adkg.broadcast.crypto.coin import sign_set, verify_sig_set

from pypairing import G2
from adkg.utils.serilization import Serial

import pickle

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)


class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"

    @staticmethod
    def RBC1(view, i):
        return f"[{view}-{i}"

    @staticmethod
    def RBC2(view, i):
        return f"]{view}-{i}"

    @staticmethod
    def B1(view):
        return f"({view}"

    @staticmethod
    def B2(view):
        return f"){view}"

    @staticmethod
    def Eval(view):
        return f"E{view}"

    @staticmethod
    def S(view):
        return f"S{view}"

    @staticmethod
    def SIGS(view):
        return f"o{view}"


class CP:
    def __init__(self, g, h, ZR):
        self.g = g
        self.h = h
        self.ZR = ZR

    def dleq_derive_chal(self, x, y, a1, a2):
        commit = str(x) + str(y) + str(a1) + str(a2)
        try:
            commit = commit.encode()
        except AttributeError:
            pass
        hs = hashlib.sha256(commit).digest()
        return self.ZR.hash(hs)

    def dleq_verify(self, x, y, chal, res):
        a1 = self.multiexp([x, self.g], [chal, res])
        a2 = self.multiexp([y, self.h], [chal, res])

        eLocal = self.dleq_derive_chal(x, a1, y, a2)
        return eLocal == chal

    def dleq_prove(self, alpha, x, y):
        w = self.ZR.random()
        a1 = self.g ** w
        a2 = self.h ** w
        e = self.dleq_derive_chal(x, a1, y, a2)
        return e, w - e * alpha  # return (challenge, response)


class PoK:
    def __init__(self, g, ZR, multiexp):
        self.g = g
        self.ZR = ZR
        self.multiexp = multiexp

    def pok_derive_chal(self, x, a):
        commit = str(x) + str(a)
        try:
            commit = commit.encode()
        except AttributeError:
            pass
        hs = hashlib.sha256(commit).digest()
        return self.ZR.hash(hs)

    def pok_verify(self, x, chal, res):
        a = self.multiexp([x, self.g], [chal, res])
        eLocal = self.pok_derive_chal(x, a)
        return eLocal == chal

    def pok_prove(self, alpha, x):
        w = self.ZR.rand()
        a = self.g ** w
        e = self.pok_derive_chal(x, a)
        return e, w - e * alpha  # return (challenge, response)


class ADKG:
    def __init__(self, public_keys, private_key, g, g2, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices, bls_coin, coin_parameters):
        self.coin_parameters = coin_parameters
        self.g1, self.h1, self.poly_commit1, self.CoinZR, self.CoinG1, self.CoinMultiexp = coin_parameters

        self.g2 = g2
        self.bls_coin = bls_coin
        self.r2_time = None
        self.acss_task = None
        self.rbc2_time = None
        self.eval_time = None
        self.terminate_view = None
        self.other_time = None
        self.rbc1_time = None
        self.agreement = None
        self.output = None
        self.t_signal = asyncio.Event()
        self.acss_outputs = None
        self.acss_signal = None
        self.key_proposal = [None] * n
        self.key_proposal_signal = [asyncio.Event() for _ in range(n)]
        self.tasks = []
        self.exp_view = 2
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc0 = ceil((deg + 1) / (t + 1))
        self.sc = self.sc0 + (1 if bls_coin else self.exp_view)
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache()  # FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.matrix = matrices

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send
        self.output_queue = asyncio.Queue()

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            for task in self.tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("ADKG task finished")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, outputs, values, acss_signal):
        acsstag = ADKGMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS_HT(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc ,
                            self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1, self.multiexp, self.sc0, self.coin_parameters)
        self.acss_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, dealer_id=i))

        while True:
            (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares': shares, 'commits': commitments}
            if len(outputs) >= self.n - self.t:
                acss_signal.set()

            if len(outputs) == self.n:
                return

    async def commonsubset(self, rbc_out, acss_outputs, acss_signal, rbc_signal, rbc_values, coin_keys, aba_in,
                           aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False] * self.n
        aba_values = [0] * self.n

        async def _recv_rbc(j):
            # rbc_values[j] = await rbc_out[j]
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)

            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)

            subset = True
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    coin_keys[j]((acss_outputs, rbc_values[j]))
                    return
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block

            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)

        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None

        rbc_signal.set()

    async def make_rbc1(self, rbc1_input, pre_rbc2_signals, pre_rbc2_outputs, rbc1_signal, rbc1_signals, rbc1_outputs,
                        view):
        rbc1_outputs_queue = [None] * self.n

        async def predicate(kpl):
            # kp = Bitmap(self.n, _key_proposal)
            # kpl = []
            # for ii in range(self.n):
            #     if kp.get_bit(ii):
            #         kpl.append(ii)
            kpl = pickle.loads(kpl)
            if view == 0:
                if len(kpl) <= self.t:
                    return False

                while True:
                    subset = True
                    for kk in kpl:
                        if kk not in self.acss_outputs.keys():
                            subset = False
                    if subset:
                        self.acss_signal.clear()
                        return True
                    self.acss_signal.clear()
                    await self.acss_signal.wait()
            if view > 0:
                x, rbc2_indices = kpl
                cnt = [0] * self.n
                candidates = []
                for i in rbc2_indices:
                    await pre_rbc2_signals[i].wait()
                    cnt[pre_rbc2_outputs[i]] += 1
                    if cnt[pre_rbc2_outputs[i]] > self.t:
                        candidates.append(pre_rbc2_outputs[i])
                if len(candidates) == 0 or x in candidates:
                    return True
                return False

        async def _setup(j):
            rbc_send, rbc_recv = self.get_send(ADKGMsgType.RBC1(view, j)), self.subscribe_recv(
                ADKGMsgType.RBC1(view, j))
            rbc_input = rbc1_input if j == self.my_id else None
            # from adkg.broadcast.qrbc import qrbc
            rbc1_outputs_queue[j] = asyncio.Queue()
            rbc1_signals[j] = asyncio.Event()
            self.tasks.append(asyncio.create_task(
                optqrbc_v(
                    str(view),
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    pickle.dumps(rbc_input),
                    rbc1_outputs_queue[j].put_nowait,
                    rbc_send,
                    rbc_recv,
                    view
                ))
            )

        await asyncio.gather(*[_setup(j) for j in range(self.n)])

        proceed_signal = asyncio.Event()
        cnt = 0
        S = set()

        async def _recv(j):
            nonlocal cnt
            x = await rbc1_outputs_queue[j].get()
            rbc1_outputs[j] = pickle.loads(x)
            rbc1_signals[j].set()
            rbc1_signal.set()
            if view == 0:
                rbc1_outputs[j] = j
                self.key_proposal[j] = pickle.loads(x)
                self.key_proposal_signal[j].set()
            S.add(j)
            cnt += 1
            if cnt >= self.n - self.t:
                proceed_signal.set()

        self.tasks.extend([asyncio.create_task(_recv(j)) for j in range(self.n)])
        await proceed_signal.wait()

        # print("S=", S)
        # with open("S", "a") as file:
        #     file.write(f"S{self.my_id} = {S}, {len(S)}\n")

        send = self.get_send(ADKGMsgType.B1(view))
        for j in range(self.n):
            send(j, S)
        return S


    def send_sig_on_set(self, j, Sj, view):
        send = self.get_send(ADKGMsgType.S(view))
        sig = sign_set(self.g, self.public_keys[self.my_id], self.private_key, Sj)
        send(j, (str(Sj), sig))

    def send_sigs(self, S, sigs, view):
        send = self.get_send(ADKGMsgType.SIGS(view))
        for i in range(self.n):
            send(i, (str(S), sigs))
    async def  make_broadcast1(self, rbc1_signals, S, view):
        recv = self.subscribe_recv(ADKGMsgType.B1(view))

        cnt = 0
        proceed_signal = asyncio.Event()
        T = set()

        async def check(j, Sj):
            nonlocal cnt, T
            for i in Sj:
                await rbc1_signals[i].wait()

            self.send_sig_on_set(j, Sj, view)

            T = T.union(Sj)
            cnt += 1
            if cnt >= self.n - self.t:
                proceed_signal.set()

        async def _recv():
            while True:
                j, Sj = await recv()
                asyncio.create_task(check(j, Sj))

        sigs = []
        sig_signal = asyncio.Event()
        async def _recv_sig():
            cnt_sig = 0
            recv_sig = self.subscribe_recv(ADKGMsgType.S(view))
            while True:
                j, (s, sig) = await recv_sig()
                sj = eval(s)
                if len(sj) >= 0 and verify_sig_set(self.g, self.public_keys[j], (s, sig)):
                    sigs.append((j, sig))
                    if len(sigs) >= self.n - self.t:
                        self.send_sigs(S, sigs, view)
                        sig_signal.set()
                        logging.info("sigs collected 1")
                        return

        async def _recv_sigs():
            recv_sigs = self.subscribe_recv(ADKGMsgType.SIGS(view))
            while True:
                j, (s, sigs) = await recv_sigs()
                sj = eval(s)
                if len(sj) < self.n - self.t:
                    continue
                for sig in sigs:
                    j, sigj = sig
                    if not verify_sig_set(self.g, self.public_keys[j],(s, sigj)):
                        continue
                sig_signal.set()
                logging.info("sigs collected 2")
                return

        recv_task = asyncio.create_task(_recv())
        recv_sig_task = asyncio.create_task(_recv_sig())
        recv_sigs_task = asyncio.create_task(_recv_sigs())

        await sig_signal.wait()
        recv_sig_task.cancel()
        recv_sigs_task.cancel()
        logging.info("sigs collected and proceeding")

        await proceed_signal.wait()
        recv_task.cancel()

        # print("T=", T)

        send = self.get_send(ADKGMsgType.B2(view))
        for j in range(self.n):
            send(j, T)

        asyncio.create_task(self.share_sending(view))

    async def make_broadcast2(self, rbc1_signals, rbc1_outputs, view):
        recv = self.subscribe_recv(ADKGMsgType.B2(view))

        cnt = 0
        proceed_signal = asyncio.Event()

        async def check(j, Sj):
            nonlocal cnt
            for i in Sj:
                await rbc1_signals[i].wait()

            cnt += 1
            if cnt >= self.n - self.t:
                proceed_signal.set()

        async def _recv():
            while True:
                j, Sj = await recv()
                asyncio.create_task(check(j, Sj))

        recv_task = asyncio.create_task(_recv())
        await proceed_signal.wait()
        recv_task.cancel()

        X = set()
        for i in range(self.n):
            if rbc1_outputs[i] is not None:
                X.add(rbc1_outputs[i])

        return X

    async def waiting_acss(self, i, kpl):
        while True:
            subset = True
            for kk in self.key_proposal[i]:
                if kk not in self.acss_outputs.keys():
                    subset = False
            if subset:
                self.acss_signal.clear()
                return
            self.acss_signal.clear()
            await self.acss_signal.wait()

    async def share_sending(self, view):

        send = self.get_send(ADKGMsgType.Eval(view))

        def broadcast(msg):
            for i in range(self.n):
                send(i, msg)

        async def sending(i):
            await self.key_proposal_signal[i].wait()
            await self.waiting_acss(i, self.key_proposal[i])
            sk = None
            for k in self.key_proposal[i]:
                kk = self.sc0 if self.bls_coin else self.sc0 + view
                if sk is None:
                    sk = self.acss_outputs[k]['shares']['msg'][kk]
                else:
                    sk += self.acss_outputs[k]['shares']['msg'][kk]


            if self.bls_coin:
                sig = self.g2.hash(str(view).encode()) ** sk
                sig = Serial(G2).serialize_g(sig)
                broadcast((i, sig))
            else:
                broadcast((i, sk))
            return

        [asyncio.create_task(sending(j)) for j in range(self.n)]
    async def recv_eval_share(self, eval_shares, eval_signal, view):
        recv = self.subscribe_recv(ADKGMsgType.Eval(view))
        while True:
            j, (i, skij) = await recv()
            if self.bls_coin:
                skij = Serial(G2).deserialize_g(skij)
            eval_shares[i][j] = skij
            if len(eval_shares[i]) >= self.t + 1:
                eval_signal[i].set()

    async def pe(self, eval_signal, eval_shares, evals, X, view):
        from adkg.broadcast.crypto import coin

        logging.info("collecting")

        for i in X:
            await eval_signal[i].wait()

        logging.info("share collected")

        ctm = time.time()
        g2hash = None if not self.bls_coin else self.g2.hash(str(view).encode())

        for i in X:
            shares = dict(list(eval_shares[i].items())[: self.t + 1])
            for k, phi_k in shares.items():
                coeff = self.g1.identity()
                for kk in self.key_proposal[i]:
                    kkk = self.sc0 if self.bls_coin else self.sc0 + view
                    coeff *= self.acss_outputs[kk]['commits'][kkk][k]

                if not self.bls_coin:
                    if (self.g1 ** phi_k) != coeff:
                        logging.info("Verification Fail")
                        assert False
                else:
                    from pypairing import pair
                    if pair(self.g1 , phi_k) != pair(coeff, g2hash):
                        logging.info("Verification Fail")
                        assert False
            if not self.bls_coin:
                evals[i] = coin.eval(i, shares, self.CoinZR)
            else:
                evals[i] = coin.eval_bls_coin(i, shares, self.CoinZR)
            evals[i] = coin.hash(evals[i][0], i)
            # print(evals[i], end=',')
        self.eval_time = time.time() - ctm

        logging.info("Eval finish")


        ret = None
        for i in range(self.n):
            # print(ret, None if (ret is None) else evals[ret])
            # print(i, evals[i])
            if (evals[i] is not None) and ((ret is None) or (evals[i] > evals[ret])):
                ret = i

        return ret

    async def make_rbc2(self, rbc2_input, rbc1_signal, rbc1_outputs, rbc2_signals, rbc2_outputs, view):
        rbc2_outputs_queue = [asyncio.Queue() for j in range(self.n)]

        async def predicate(x):
            x = int(x)
            while True:
                for i in range(self.n):
                    if rbc1_outputs[i] is not None:
                        if rbc1_outputs[i] == x:
                            return True
                await rbc1_signal.wait()
                rbc1_signal.clear()

        async def _setup(j):
            rbc_send, rbc_recv = self.get_send(ADKGMsgType.RBC2(view, j)), self.subscribe_recv(
                ADKGMsgType.RBC2(view, j))
            rbc_input = (await rbc2_input.get()) if j == self.my_id else None
            # from adkg.broadcast.qrbc import qrbc
            # rbc2_outputs_queue[j] = asyncio.Queue()
            rbc2_signals[j] = asyncio.Event()

            self.tasks.append(asyncio.create_task(
                optqrbc_b(
                    str(view),
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    str(rbc_input),
                    rbc2_outputs_queue[j].put_nowait,
                    rbc_send,
                    rbc_recv
                ))
            )
            self.print_task("add"+ str(view))

        [asyncio.create_task(_setup(j)) for j in range(self.n)]

        proceed_signal = asyncio.Event()
        cnt = 0
        c = [0] * self.n
        proof = [[] for _ in range(self.n)]
        proof_rand = []
        ret_x = None
        ret_proof = None

        async def _recv(j):
            nonlocal cnt, ret_x, ret_proof
            x = await rbc2_outputs_queue[j].get()
            x = int(x)
            rbc2_outputs[j] = x
            rbc2_signals[j].set()
            c[x] += 1
            proof[x].append(j)
            proof_rand.append(j)
            cnt += 1
            if c[x] > self.t and ret_x is None:
                ret_x = x
                ret_proof = proof[x]
            if c[x] >= self.n - self.t:
                self.output = x
                self.terminate_view = view
                if self.r2_time is not None:
                    self.rbc2_time = time.time() - self.r2_time
                self.t_signal.set()
            if cnt >= self.n - self.t:
                if ret_x is None:
                    ret_x = x
                    ret_proof = proof_rand
                proceed_signal.set()

        self.tasks.extend([asyncio.create_task(_recv(j)) for j in range(self.n)])
        await proceed_signal.wait()

        return ret_x, ret_proof

    async def proceed_view(self, rbc1_input, pre_rbc2_signals, pre_rbc2_output, rbc2_signals, rbc2_outputs, view):

        logging.info(f"Entered view {view}")

        rbc1_outputs = [None] * self.n
        rbc1_signals = [None] * self.n
        rbc1_signal = asyncio.Event()
        x_signal = asyncio.Queue()
        eval_shares = defaultdict(dict)
        eval_signal = [asyncio.Event() for _ in range(self.n)]
        evals = [None for _ in range(self.n)]

        tm = time.time()
        S = await self.make_rbc1(rbc1_input, pre_rbc2_signals, pre_rbc2_output, rbc1_signal, rbc1_signals, rbc1_outputs,
                             view)

        ctm = time.time()
        self.rbc1_time = ctm - tm
        tm = ctm

        logging.info("Finish rbc1")
        rbc2_task = asyncio.create_task(
            self.make_rbc2(x_signal, rbc1_signal, rbc1_outputs, rbc2_signals, rbc2_outputs, view))

        await self.make_broadcast1(rbc1_signals, S, view)
        logging.info("Finish b1")
        share_recv_task = asyncio.create_task(self.recv_eval_share(eval_shares, eval_signal, view))
        X = await self.make_broadcast2(rbc1_signals, rbc1_outputs, view)

        ctm = time.time()
        self.other_time = ctm - tm
        tm = ctm

        logging.info(f"Finish X = {X}")
        x = await self.pe(eval_signal, eval_shares, evals, X, view)
        x_signal.put_nowait(x)

        ctm = time.time()
        self.r2_time = ctm
        tm = ctm

        share_recv_task.cancel()
        logging.info(f"Elect x = {x} in view {view}")

        ret, ret_p = await rbc2_task

        logging.info(f"Finish rbc2 with {ret}, {ret_p}, signal: {self.t_signal}")
        return (ret, ret_p)

    async def agreement3(self, view_input):

        async def vaba():
            nonlocal view_input
            rbc2_outputs = []
            rbc2_signals = []
            view = 0
            while self.output is None:
                rbc2_outputs.append([None for _ in range(self.n)])
                rbc2_signals.append([None for _ in range(self.n)])
                view_input = await self.proceed_view(view_input, None if view == 0 else rbc2_signals[view - 1],
                                                     None if view == 0 else rbc2_outputs[view - 1]
                                                     , rbc2_signals[view], rbc2_outputs[view], view)
                view += 1
                # TODO: If secrets run out, do ACSS again
                assert view + 1 < self.exp_view


        vaba_task = asyncio.create_task(vaba())
        await self.t_signal.wait()

        vaba_task.cancel()
        logging.info(f"t_signal set, waiting for key proposal {self.output}, {self.key_proposal_signal[self.output]}")
        await self.key_proposal_signal[self.output].wait()
        logging.info(f"Termination with {self.output}")

        for task in self.tasks:
            task.cancel()
            # task.close()

        self.print_task("cancelled")

        logging.info("derive_key")
        mks, secret, pk = await self.derive_key2(self.acss_outputs, self.acss_signal, self.key_proposal[self.output])
        logging.info(f"Output: {mks}, {secret}, {pk}")
        return mks, secret, pk

    async def derive_key2(self, acss_outputs, acss_signal, proposal):
        self.mks = set(proposal)  # master key set
        # Waiting for all ACSS to terminate
        for k in self.mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()
        secrets = [[self.ZR(0)] * self.n for _ in range(self.sc0)]
        randomness = [[self.ZR(0)] * self.n for _ in range(self.sc0)]
        commits = [[self.G1.identity()] * self.n for _ in range(self.sc0)]
        for idx in range(self.sc0):
            for node in range(self.n):
                if node in self.mks:
                    secrets[idx][node] = acss_outputs[node]['shares']['msg'][idx]
                    randomness[idx][node] = acss_outputs[node]['shares']['rand'][idx]
                    commits[idx][node] = acss_outputs[node]['commits'][idx][0]
        z_shares = [self.ZR(0)] * self.n
        r_shares = [self.ZR(0)] * self.n
        for i in range(self.n):
            for sec in range(self.sc0):
                z_shares[i] = z_shares[i] + self.dotprod(self.matrix[sec][i], secrets[sec])
                r_shares[i] = r_shares[i] + self.dotprod(self.matrix[sec][i], randomness[sec])
        # Sending PREKEY messages
        keytag = ADKGMsgType.PREKEY
        send, recv = self.get_send(keytag), self.subscribe_recv(keytag)

        for i in range(self.n):
            send(i, (z_shares[i], r_shares[i]))
        sk_shares = []
        rk_shares = []

        secret, random = None, None
        while True:
            (sender, msg) = await recv()
            sk_share, rk_share = msg

            sk_shares.append([sender + 1, sk_share])
            rk_shares.append([sender + 1, rk_share])

            # Interpolating the share
            if len(sk_shares) >= self.t + 1:
                secret = self.poly.interpolate_at(sk_shares, 0)
                random = self.poly.interpolate_at(rk_shares, 0)
                commit = self.G1.identity()
                for sec in range(self.sc0):
                    commit = commit * self.multiexp(commits[sec], self.matrix[sec][self.my_id])
                if self.multiexp([self.g, self.h], [secret, random]) == commit:
                    break
                # TODO(@sourav): Implement the fallback path
        mx = self.g ** secret
        my = self.h ** random
        gpok = PoK(self.g, self.ZR, self.multiexp)
        hpok = PoK(self.h, self.ZR, self.multiexp)
        gchal, gres = gpok.pok_prove(secret, mx)
        hchal, hres = hpok.pok_prove(random, my)

        keytag = ADKGMsgType.KEY
        send, recv = self.get_send(keytag), self.subscribe_recv(keytag)

        for i in range(self.n):
            send(i, (mx, my, gchal, gres, hchal, hres))
        pk_shares = [[self.my_id + 1, mx]]
        rk_shares = [[self.my_id + 1, my]]
        while True:
            (sender, msg) = await recv()
            if sender != self.my_id:
                x, y, gchal, gres, hchal, hres = msg
                valid_pok = gpok.pok_verify(x, gchal, gres) and hpok.pok_verify(y, hchal, hres)
                if valid_pok:
                    pk_shares.append([sender + 1, x])
                    rk_shares.append([sender + 1, y])

            if len(pk_shares) > self.deg:
                break
        pk = interpolate_g1_at_x(pk_shares, 0, self.G1, self.ZR)
        rk = interpolate_g1_at_x(rk_shares, 0, self.G1, self.ZR)
        com0 = self.multiexp(commits[0], [self.ZR(1)] * self.n)
        # TODO:(@sourav) FIXME! Add the fallback path
        assert pk * rk == com0
        return (self.mks, secret, pk)

    async def run_adkg(self, start_time):
        logging.info(f"Starting ADKG for node {self.my_id}")
        logging.info("entering")
        self.acss_outputs = {}
        self.acss_signal = asyncio.Event()
        acss_signal = self.acss_signal
        acss_outputs = self.acss_outputs

        acss_start_time = time.time()
        values = [self.ZR.rand() if i < self.sc0 else self.CoinZR.rand() for i in range(self.sc)]
        logging.info("start acss")
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        acss_time = time.time() - acss_start_time
        key_proposal = list(acss_outputs.keys())

        self.agreement = asyncio.create_task(self.agreement3(key_proposal))
        mks, sk, pk = await self.agreement
        adkg_time = time.time() - start_time

        self.output_queue.put_nowait((values[0], mks, sk, pk))

        self.benchmark_logger.info(f"time3:  {self.acss.veri_time3}, time1: {self.acss.veri_time}, time2: {self.acss.veri_time2}, type: {type(pk)}, bls_coin: {self.bls_coin}, ADKG time:  {adkg_time} ACSS time: {acss_time}, RBC1 time: {self.rbc1_time}, Other time: {self.other_time}, Eval time: {self.eval_time}, RBC2 time: {self.rbc2_time}, End view: {self.terminate_view}")
        logging.info(
            f" time3: {self.acss.veri_time3}, time1: {self.acss.veri_time}, time2: {self.acss.veri_time2}, type: {type(pk)}, bls_coin: {self.bls_coin}, ADKG time:  {adkg_time} ACSS time: {acss_time}, RBC1 time: {self.rbc1_time}, Other time: {self.other_time}, Eval time: {self.eval_time}, RBC2 time: {self.rbc2_time}, End view: {self.terminate_view}")

        self.print_task("finished")

        # TODO: correctly cancel all rbc tasks (This code snippet doesn't work correctly.)
        # for task in self.tasks:
        #     if not task.done():
        #         task.cancel()
        #         try:
        #             await task
        #         except asyncio.CancelledError:
        #             pass

    def print_task(self, info):
        return
        print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$", info)
        for task in asyncio.all_tasks():
            if task._coro.__name__ == 'optqrbc_b':
                logging.info(str(task.__hash__() )+' '+ str(task))
        print("--------------------------------------------------------------")


