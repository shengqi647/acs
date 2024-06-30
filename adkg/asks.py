import asyncio
import time
from collections import defaultdict
from pickle import dumps, loads
import re
from adkg.polynomial import polynomials_over
from adkg.symmetric_crypto import SymmetricCrypto
from adkg.utils.misc import wrap_send, subscribe_recv
from adkg.broadcast.optqrbc_asks import optqrbc
from adkg.utils.serilization import Serial
from adkg.polynomial import get_omega


import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.DEBUG)

class ASKS:
    #@profile
    def __init__(
            self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, multiexp, sc0
    ):  # (# noqa: E501)
        # from pairing import cur

        self.secrets = [None] * sc
        self.dual_codes = {}

        self.public_keys, self.private_key = public_keys, private_key
        self.n, self.t, self.deg, self.my_id = n, t, deg, my_id
        self.g, self.h = g, h 
        self.sr = Serial(G1)
        self.sc = sc
        self.sc0 = sc0
        self.poly_commit = pc
        self.ZR = field
        self.multiexp = multiexp

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.acss_status = defaultdict(lambda: True)
        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        self.output_queue = asyncio.Queue()
        self.tagvars = {}
        self.tasks = []
        self.data = {}

    def __enter__(self):
        return self

    #def __exit__(self, typ, value, traceback):
    def kill(self):
        self.subscribe_recv_task.cancel()
        for task in self.tasks:
            task.cancel()
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()

    def decode_proposal(self, proposal):

        shares_size = self.sc * 32
        shares = self.sr.deserialize_fs(proposal[0: 0 + shares_size])

        proposal = proposal[shares_size: ]
        commits_array = [proposal[i:i + 32] for i in range(0, len(proposal), 32)]
        commits = [commits_array[i:i + self.n] for i in range(0, len(commits_array), self.n)]

        return (shares, commits, proposal)

    def gen_dual_code(self, n, degree, poly):
        def get_vi(i, n):
            out = self.CoinZR(1)
            for j in range(1, n+1):
                if j != i:
                    out = out / (i-j)
            return out
        q = poly.random(n -degree -2)
        q_evals = [q(i+1) for i in range(n)]
        return [q_evals[i] * get_vi(i+1, n) for i in range(n)]

    def verify_proposal(self, dealer_id, shares, commits):
        for i in range(self.sc):
            if self.hash_eval(self.my_id + 1, shares[i]) != commits[i][self.my_id]:
                self.acss_status[dealer_id] = False
                return False

        self.acss_status[dealer_id] = True
        self.data[dealer_id] = [shares, commits]
        return True

    def hash_eval(self, j, fj):
        import hashlib
        t = str(j) + str(fj)
        s = hashlib.sha256()
        s.update(t.encode())
        return s.digest()

    def _get_dealer_msg(self, values, n):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        """
        while len(values) % (batch_size) != 0:
            values.append(0)
        """
        phi = [None]*self.sc
        phi_hat = [None]*self.sc
        commitments = [None]*self.sc
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        commits_to_eval = None

        ys = [None] * self.sc
        nn = n
        nn = nn if nn & nn - 1 == 0 else 2 ** nn.bit_length()
        omega2 = get_omega(self.field, 2 * nn)
        omega = omega2 ** 2

        for k in range(self.sc):
            phi[k] = self.poly.random(self.t, values[k])
            ys[k] = list(phi[k].evaluate_fft(omega, nn))
        for k in range(self.sc):
            commitments[k] = [self.hash_eval(j, ys[k][j-1]) for j in range(1, n + 1)]

        shares = [bytearray() for _ in range(n)]
        commits = bytearray()

        for i in range(n):
            phis_i = [ys[k][i] for k in range(self.sc)]
            shares[i].extend(self.sr.serialize_fs(phis_i))

        for i in range(self.sc):
            commits.extend(b"".join(commitments[i]))

        return shares, bytes(commits)

    #@profile
    async def avss(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        n = self.n
        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        msg1 = None
        if self.my_id == dealer_id:
            msg1, broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            shares, commits, __m = self.decode_proposal(_m)
            ret = self.verify_proposal(dealer_id, shares, commits)

            return ret, __m
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            msg1,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()

        # avss processing
        shares, commits = self.data[dealer_id]
        self.output_queue.put_nowait((dealer_id, avss_id, shares, commits, self.acss_status[dealer_id]))

        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]