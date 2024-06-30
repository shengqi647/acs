from collections import defaultdict

from adkg.broadcast.optqrbc_bracha import optqrbc_b
from adkg.broadcast.optqrbc_gather import optqrbc_u
from adkg.broadcast.optqrbc import optqrbc
from adkg.broadcast.ra_bracha import reliable_agreement
from adkg.polynomial import polynomials_over, fnt_decode_step1, fnt_decode_step2, get_omega
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from adkg.utils.bitmap import Bitmap
from adkg.asks import ASKS
from adkg.broadcast.crypto import coin

from adkg.utils.serilization import Serial
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)


class ADKGMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"
    RA = "T"

    @staticmethod
    def RBC0(i):
        return f"R{i}"

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

class VABA:
    def __init__(self, public_keys, private_key, g, g2, h, n, t, deg, my_id, send, recv, pc, curve_params, matrices):
        self.ra_input = asyncio.Queue()
        self.index_input = [None] * n
        self.valid_set = set()
        self.rbc0_signal = asyncio.Event()
        self.rbc0_signals = [asyncio.Event() for _ in range(n)]
        self.proposed_value = [None] * n
        self.current_time = 0
        self.g2 = g2
        self.r2_time = None
        self.acss_task = None
        self.rbc2_time = None
        self.eval_time = 0
        self.eval2_time = 0
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
        self.exp_view = 1
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc0 = 0
        self.sc = self.sc0 + self.exp_view
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache()  # FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.matrix = matrices
        self.sr = Serial(self.ZR)

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
        self.acss = ASKS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc ,
                            self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1, self.multiexp, self.sc0)
        self.acss_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, dealer_id=i))

        while True:
            (dealer, _, shares, commits, status) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares': shares, 'commits': commits}
            if len(outputs) >= self.n - self.t:
                acss_signal.set()

            if len(outputs) == self.n:
                return

    async def make_rbc1(self, rbc1_input, pre_rbc2_signals, pre_rbc2_outputs, rbc1_signal, rbc1_signals, rbc1_outputs,
                        S, echo2_disable, view):
        rbc1_outputs_queue = [None] * self.n

        async def predicate(_kpl):
            if view == 0:
                bit_num = (self.n-1)//8 + 1
                kpl = byte_to_list(_kpl[:bit_num])
                pre_set = byte_to_list(_kpl[bit_num:])

                if len(kpl) <= self.t:
                    return False
                if len(pre_set) < self.n - self.t:
                    return False

                for i in pre_set:
                    await self.rbc0_signals[i].wait()

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
                kpl = byte_to_list(_kpl)
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

        def list_to_byte(key_proposal):
            riv = Bitmap(self.n)
            for k in key_proposal:
                riv.set_bit(k)
            return bytes(riv.array)

        def byte_to_list(rbcl):
            rbcb = Bitmap(self.n, rbcl)
            rbc_values = []
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values.append(i)
            return rbc_values
        async def _setup(j):
            rbc_send, rbc_recv = self.get_send(ADKGMsgType.RBC1(view, j)), self.subscribe_recv(
                ADKGMsgType.RBC1(view, j))
            rbc_input = list_to_byte(rbc1_input) if j == self.my_id else None
            if view == 0 and j == self.my_id:
                rbc_input = rbc_input + list_to_byte(self.valid_set)
            rbc1_outputs_queue[j] = asyncio.Queue()
            rbc1_signals[j] = asyncio.Event()
            self.tasks.append(asyncio.create_task(
                optqrbc_u(
                    str(view),
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    rbc_input,
                    rbc1_outputs_queue[j].put_nowait,
                    rbc_send,
                    rbc_recv,
                    echo2_disable,
                    view
                ))
            )

        await asyncio.gather(*[_setup(j) for j in range(self.n)])

        proceed_signal = asyncio.Event()
        cnt = 0

        send = self.get_send(ADKGMsgType.B1(view))
        batch_ack = []
        async def _recv(j):
            nonlocal cnt
            x = await rbc1_outputs_queue[j].get()

            if view == 0:
                bit_num = (self.n-1)//8 + 1
                rbc1_outputs[j] = byte_to_list(x[:bit_num])
                self.index_input[j] = byte_to_list(x[bit_num:])
            else:
                rbc1_outputs[j] = byte_to_list(x)
            rbc1_signals[j].set()
            rbc1_signal.set()
            if view == 0:
                self.key_proposal[j] = rbc1_outputs[j]
                rbc1_outputs[j] = j
                self.key_proposal_signal[j].set()
            S.add(j)
            cnt += 1

            # broadcast confirm
            if not proceed_signal.is_set():
                batch_ack.append(j)
            else:
                for i in range(self.n):
                    send(i, [j])

            if cnt >= self.n - self.t:
                for i in range(self.n):
                    send(i, batch_ack)
                proceed_signal.set()

        self.tasks.extend([asyncio.create_task(_recv(j)) for j in range(self.n)])
        await proceed_signal.wait()

    async def recv_confirm(self, cnt_ack_rbc, echo2_disable, S, view):
        recv = self.subscribe_recv(ADKGMsgType.B1(view))
        send = self.get_send(ADKGMsgType.B2(view))
        cnt_confirm = 0
        while True:
            j, ack_list = await recv()
            for i in ack_list:
                cnt_ack_rbc[i].add(j)
                if len(cnt_ack_rbc[i]) == self.n - self.t:
                    cnt_confirm += 1
                    if cnt_confirm == self.n - self.t:
                        echo2_disable[0] = True
                        for k in range(self.n):
                            send(k, S)
                        return

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

        batch_sk = []
        non_batch_sk = []

        for i in range(self.n):
            if i in self.acss_outputs.keys():
                batch_sk.append((i, self.sr.serialize_f(self.acss_outputs[i]['shares'][view])))
            else:
                non_batch_sk.append(i)

        broadcast(batch_sk)
        async def sending(i):
            while True:
                subset = True
                if i not in self.acss_outputs.keys():
                    subset = False
                if subset:
                    self.acss_signal.clear()
                    break
                self.acss_signal.clear()
                await self.acss_signal.wait()
            sk = self.acss_outputs[i]['shares'][view]
            broadcast([(i, self.sr.serialize_f(sk))])

        [asyncio.create_task(sending(j)) for j in non_batch_sk]

    def ifft(self, shares, ZR, omega2, n):
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

    def check_rec(self, i, phi, omega, n, view):
        ys = list(phi.evaluate_fft(omega, n))
        for j in range(self.n):
            if self.hash_eval(j+1, ys[j]) != self.acss_outputs[i]['commits'][view][j]:
                return False
        return True
    async def recv_eval_share(self, x0s, eval_shares, eval_signal, view):
        recv = self.subscribe_recv(ADKGMsgType.Eval(view))

        nn = self.n
        nn = nn if nn & nn - 1 == 0 else 2 ** nn.bit_length()
        omega2 = get_omega(self.ZR, 2 * nn)
        omega = omega2 ** 2

        while True:
            j, sk_list = await recv()
            for (i, skij) in sk_list:
                skij = self.sr.deserialize_f(skij)
                if self.acss_outputs[i]['commits'][view][j] != self.hash_eval(j+1, skij):
                    logging.info('Invalid secrets.')
                    continue
                eval_shares[i][j] = skij
                if len(eval_shares[i]) == self.t + 1:
                    shares = dict(list(eval_shares[i].items())[: self.t + 1])
                    ctm = time.time()
                    phi_rec = self.ifft(shares, self.ZR, omega2, nn)
                    self.eval_time += time.time() - ctm
                    ctm = time.time()
                    if self.check_rec(i, phi_rec, omega, nn, view):
                        x0s[i] = phi_rec(0)
                    else:
                        x0s[i] = 0
                    self.eval2_time += time.time() - ctm
                    eval_signal[i].set()

    async def pe(self, eval_signal, eval_shares, x0s, evals, X, view):

        for i in X:
            rk = self.ZR(0)
            for kk in self.key_proposal[i]:
                await eval_signal[kk].wait()
                rk += x0s[kk]
            evals[i] = coin.hash(rk, i)

        ret = None
        for i in range(self.n):
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
            if j == self.my_id:
                self.other_time = time.time() - self.current_time
                self.current_time = time.time()
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
                self.rbc2_time = time.time() - self.current_time


                self.ra_input.put_nowait(x)
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

        logging.info(f"Start view {view}")

        rbc1_outputs = [None] * self.n
        rbc1_signals = [None] * self.n
        rbc1_signal = asyncio.Event()
        echo2_disable = [False]
        x_signal = asyncio.Queue()
        eval_shares = defaultdict(dict)
        eval_signal = [asyncio.Event() for _ in range(self.n)]
        evals = [None for _ in range(self.n)]
        x0s = [None for _ in range(self.n)]
        cnt_ack_rbc = [set() for _ in range(self.n)]
        S = set()

        self.current_time = time.time()

        confirm_recv_task = asyncio.create_task(self.recv_confirm(cnt_ack_rbc, echo2_disable, S, view))
        await self.make_rbc1(rbc1_input, pre_rbc2_signals, pre_rbc2_output, rbc1_signal, rbc1_signals, rbc1_outputs,
                             S, echo2_disable, view)

        self.rbc1_time = time.time() - self.current_time
        self.current_time = time.time()

        rbc2_task = asyncio.create_task(
            self.make_rbc2(x_signal, rbc1_signal, rbc1_outputs, rbc2_signals, rbc2_outputs, view))

        share_recv_task = asyncio.create_task(self.recv_eval_share(x0s, eval_shares, eval_signal, view))
        X = await self.make_broadcast2(rbc1_signals, rbc1_outputs, view)
        asyncio.create_task(self.share_sending(view))

        x = await self.pe(eval_signal, eval_shares, x0s, evals, X, view)

        x_signal.put_nowait(x)

        share_recv_task.cancel()
        logging.info(f"Elect x = {x} in view {view}")

        ret, ret_p = await rbc2_task

        return (ret, ret_p)
        # pass

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
                assert view < self.exp_view

        output_queue = asyncio.Queue()
        async def ra():
            ra_send, ra_recv = self.get_send(ADKGMsgType.RA), self.subscribe_recv(
                ADKGMsgType.RA)

            self.tasks.append(asyncio.create_task(
                reliable_agreement(
                    's0',
                    self.my_id,
                    self.n,
                    self.t,
                    self.ra_input.get,
                    output_queue.put_nowait,
                    ra_send,
                    ra_recv
                )
            ))

        ra_task = asyncio.create_task(ra())
        vaba_task = asyncio.create_task(vaba())
        output = await output_queue.get()

        ra_task.cancel()
        vaba_task.cancel()
        await self.key_proposal_signal[self.output].wait()

        self.mks = set(self.index_input[self.output])
        mks_v = []
        for k in self.mks:
            await self.rbc0_signals[k].wait()
            mks_v.append(self.proposed_value[k])

        logging.info(f"Agreed on {self.output}, set: {self.mks}, value_set: {mks_v}")
        return self.output

    async def make_rbc0(self, rbc1_input):
        rbc1_outputs_queue = [None] * self.n

        async def predicate(_kpl):
            return True
        async def _setup(j):
            rbc_send, rbc_recv = self.get_send(ADKGMsgType.RBC0(j)), self.subscribe_recv(
                ADKGMsgType.RBC0(j))
            rbc_input = rbc1_input if j == self.my_id else None
            rbc1_outputs_queue[j] = asyncio.Queue()
            self.tasks.append(asyncio.create_task(
                optqrbc(
                    's0',
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    rbc_input,
                    rbc1_outputs_queue[j].put_nowait,
                    rbc_send,
                    rbc_recv,
                ))
            )

        await asyncio.gather(*[_setup(j) for j in range(self.n)])

        cnt = 0
        async def _recv(j):
            nonlocal cnt
            x = await rbc1_outputs_queue[j].get()
            self.proposed_value[j] = x
            self.rbc0_signals[j].set()
            self.valid_set.add(j)
            cnt += 1

            if cnt >= self.n - self.t:
                self.rbc0_signal.set()

        self.tasks.extend([asyncio.create_task(_recv(j)) for j in range(self.n)])

    async def run_adkg(self, start_time):
        logging.info(f"Starting ADKG for node {self.my_id}")
        self.acss_outputs = {}
        self.acss_signal = asyncio.Event()
        acss_signal = self.acss_signal
        acss_outputs = self.acss_outputs

        acss_start_time = time.time()
        values = [self.ZR.rand() for i in range(self.sc)]
        logging.info("Start avss and RBC0")
        await asyncio.create_task(self.make_rbc0(b'\x00'))
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, values, acss_signal))
        await acss_signal.wait()
        await self.rbc0_signal.wait()
        acss_signal.clear()
        acss_time = time.time() - acss_start_time
        key_proposal = list(acss_outputs.keys())

        self.agreement = asyncio.create_task(self.agreement3(key_proposal))
        mks = await self.agreement
        adkg_time = time.time() - start_time

        for task in self.tasks:
            task.cancel()

        self.output_queue.put_nowait((mks))

        self.benchmark_logger.info(
            f"ADKG time:  {adkg_time} ACSS time: {acss_time}, RBC1 time: {self.rbc1_time}, Other time: {self.other_time},  RBC2 time: {self.rbc2_time}, Eval time: {self.eval_time+ self.eval2_time}, End view: {self.terminate_view}")

        logging.info(
            f"ADKG time:  {adkg_time} ACSS time: {acss_time}, RBC1 time: {self.rbc1_time}, Other time: {self.other_time},  RBC2 time: {self.rbc2_time}, Eval time: {self.eval_time+ self.eval2_time}, End view: {self.terminate_view}")


