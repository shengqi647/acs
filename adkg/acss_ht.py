import asyncio
import time
from collections import defaultdict
from pickle import dumps, loads
import re
from adkg.polynomial import polynomials_over
from adkg.symmetric_crypto import SymmetricCrypto
from adkg.utils.misc import wrap_send, subscribe_recv
from adkg.broadcast.optqrbc import optqrbc
from adkg.utils.serilization import Serial


import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.DEBUG)


class HbAVSSMessageType:
    OK = 1
    IMPLICATE = 2
    RECOVERY = 4
    RECOVERY1 = 5
    RECOVERY2 = 6
    KDIBROADCAST = 7

class ACSS_HT:
    #@profile
    def __init__(
            self, public_keys, private_key, g, h, n, t, deg, sc, my_id, send, recv, pc, field, G1, multiexp, sc0, coin_parameters
    ):  # (# noqa: E501)

        self.veri_time3 = 0
        self.g1, self.h1, self.poly_commit1, self.CoinZR, self.CoinG1, self.CoinMultiexp = coin_parameters
        self.field1 = self.CoinZR
        self.sr1 = Serial(self.CoinG1)
        self.poly1 = polynomials_over(self.field1)
        self.poly1.clear_cache()

        self.dual_codes = {}
        self.veri_time2 = 0
        self.veri_time = 0
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
        # self.benchmark_logger.info("ACSS kill called")
        self.subscribe_recv_task.cancel()
        # self.benchmark_logger.info("ACSS recv task cancelled")
        for task in self.tasks:
            task.cancel()
        # self.benchmark_logger.info("ACSS self.tasks cancelled")
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
        # self.benchmark_logger.info("ACSS self tagvars canceled")

    
    #@profile
    async def _handle_implication(self, tag, j, idx, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments =  self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != self.g**j_sk:
            return False
        # decrypt and verify
        implicate_msg = None #FIXME: IMPORTANT!!
        j_shared_key = (self.tagvars[tag]['ephemeral_public_key'])**j_sk

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_shares, j_witnesses = SymmetricCrypto.decrypt(
                j_shared_key.__getstate__(), implicate_msg
            )
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        return not self.poly_commit.batch_verify_eval(
            commitments[idx], j + 1, j_shares, j_witnesses, self.t
        )

    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['in_share_recovery']:
            return
        if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
            logger.debug("[%d] sent_kdi_broadcast", self.my_id)
            kdi = self.tagvars[tag]['shared_key']
            multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
            self.kdi_broadcast_sent = True
        if self.tagvars[tag]['all_shares_valid']:
            return

        if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
            logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
            
            # FIXME: IMPORTANT!! read the message from rbc output
            # retrieved_msg = await avid.retrieve(tag, sender)
            retrieved_msg = None
            try:
                j_shares, j_witnesses = SymmetricCrypto.decrypt(
                    avss_msg[1].__getstate__(), retrieved_msg
                )
            except Exception as e:  # TODO: Add specific exception
                logger.debug("Implicate confirmed, bad encryption:", e)
            commitments = self.tagvars[tag]['commitments']
            if (self.poly_commit.batch_verify_eval(commitments,
                                                   sender + 1, j_shares, j_witnesses, self.t)):
                if not self.saved_shares[sender]:
                    self.saved_shared_actual_length += 1
                    self.saved_shares[sender] = j_shares

        # if t+1 in the saved_set, interpolate and sell all OK
        if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
            logger.debug("[%d] interpolating", self.my_id)
            # Batch size
            shares = []
            secret_count = len(self.tagvars[tag]['commitments'])
            for i in range(secret_count):
                phi_coords = [
                    (j + 1, self.saved_sharesput[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
                ]
                shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
            self.tagvars[tag]['all_shares_valid'] = True
            self.tagvars[tag]['shares'] = shares
            self.tagvars[tag]['in_share_recovery'] = False
            self.interpolated = True
            multicast((HbAVSSMessageType.OK, ""))
    
    def decode_proposal(self, proposal):
        g_size = self.sr.g_size
        g1_size = self.sr1.g_size
        c_size = 32
        # deserializing commitments

        com_size = g_size*(self.t+1) * self.sc0
        com_size1 = g1_size * self.n * (self.sc - self.sc0)

        tm = time.time()
        commits_all = self.sr.deserialize_gs(proposal[0: com_size])
        self.veri_time += (time.time() - tm)

        commits_all1 = self.sr1.deserialize_gs(proposal[com_size: com_size + com_size1])


        commits = [(commits_all[i*(self.t+1):(i+1)*(self.t+1)] if i < self.sc0 else commits_all1[(i-self.sc0)*self.n:(i+1-self.sc0)*self.n]) for i in range(self.sc)]
        # deserializing ciphertexts
        # IMPORTANT: Here 32 additional bytes are used in the ciphertext for padding
        ctx_per_node = (self.sc0*2+self.sc-self.sc0+1)
        ctx_size = c_size*ctx_per_node*self.n
        my_ctx_start = com_size + com_size1 + c_size*ctx_per_node*self.my_id
        my_ctx_end = my_ctx_start + c_size*ctx_per_node
        ctx_bytes = proposal[my_ctx_start:my_ctx_end]

        # deserializing the ephemeral public key
        ephkey = self.sr.deserialize_g(proposal[com_size+com_size1+ctx_size:])

        return (ctx_bytes, commits, ephkey)

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

    def check_degree(self, claimed_degree, commitments):
        if (claimed_degree, len(commitments)) not in self.dual_codes.keys():
            self.dual_codes[(claimed_degree, len(commitments))] = self.gen_dual_code(len(commitments), claimed_degree, self.poly1)

        dual_code = self.dual_codes[(claimed_degree, len(commitments))]
        check = self.CoinMultiexp(commitments, dual_code)

        return check == self.g1 ** 0

    def verify_proposal(self, dealer_id, dispersal_msg, commits, ephkey):
        shared_key = ephkey**self.private_key

        try:
            sharesb = SymmetricCrypto.decrypt(shared_key.__getstate__(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False

        shares = self.sr.deserialize_fs(sharesb[:self.sc0 * 2 * 32])
        shares1 = self.sr1.deserialize_fs(sharesb[self.sc0 * 2 * 32:])
        phis, phis_hat = shares[:self.sc0], shares[self.sc0:]
        phis.extend(shares1)

        tm = time.time()
        for i in range(0, self.sc0):
            if not self.poly_commit.verify_eval(commits[i], self.my_id + 1, phis[i], phis_hat[i]):
                self.acss_status[dealer_id] = False
                return False
        self.veri_time3 += time.time() - tm
        tm = time.time()
        for i in range(self.sc0, self.sc):
            if not (self.check_degree(self.t + 1, commits[i]) and self.g1 ** phis[i] == commits[i][self.my_id]):
                self.acss_status[dealer_id] = False
                return False
        self.veri_time2 += time.time() - tm
        self.acss_status[dealer_id] = True
        self.data[dealer_id] = [commits, phis, phis_hat, ephkey, shared_key]


        return True

    
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in range(self.n):
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['in_share_recovery'] = False
        
        ok_set = set()
        implicate_set = set()
        output = False

        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dealer_id)

        if self.tagvars[tag]['all_shares_valid']:
            shares = {'msg': self.tagvars[tag]['shares'][0], 'rand':self.tagvars[tag]['shares'][1]}

            commitments = self.tagvars[tag]['commitments']
            self.output_queue.put_nowait((dealer_id, avss_id, shares, commitments))
            output = True
            logger.debug("[%d] Output", self.my_id)
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            logger.debug("Implicate Sent [%d]", dealer_id)
            self.tagvars[tag]['in_share_recovery'] = True

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    logger.debug("Handling Implicate Message [%d]", dealer_id)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        logger.debug("Handle implication called [%d]", dealer_id)
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                ok_set.add(sender)

            # The only condition where we can terminate
            if (len(ok_set) == 3 * self.t + 1) and output:
                logger.debug("[%d] exit", self.my_id)
                break
    #@profile
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

        for k in range(self.sc):
            if k < self.sc0:
                # TODO(@sourav): Implement FFT here
                from pypairing import  pair, G2

                phi[k] = self.poly.random(self.t, values[k])
                phi_hat[k] = self.poly.random(self.t, self.field.rand())
                commitments[k] = self.poly_commit.commit(phi[k], phi_hat[k])
            else:
                phi[k] = self.poly1.random(self.t, values[k])
                commitments[k] = self.poly_commit1.commit_to_eval2(self.n, self.t, phi[k], None)

        ephemeral_secret_key = self.field.rand()
        ephemeral_public_key = self.g**ephemeral_secret_key
        dispersal_msg_list = bytearray()
        for i in range(n):
            shared_key = self.public_keys[i]**ephemeral_secret_key
            phis_i = [phi[k](i + 1) for k in range(self.sc0)]
            phis_i1 = [phi[k](i + 1) for k in range(self.sc0, self.sc)]
            phis_hat_i = [phi_hat[k](i + 1) for k in range(self.sc0)]
            ciphertext = SymmetricCrypto.encrypt(shared_key.__getstate__(), self.sr.serialize_fs(phis_i+phis_hat_i) + self.sr1.serialize_fs(phis_i1))
            dispersal_msg_list.extend(ciphertext)

        g_commits = commitments[0]
        for k in range(1, self.sc0):
            g_commits = g_commits + commitments[k]
        datab = self.sr.serialize_gs(g_commits) # Serializing commitments

        g_commits1 = commitments[self.sc0]
        for k in range(self.sc0 + 1, self.sc):
            g_commits1 = g_commits1 + commitments[k]
        datab.extend(self.sr1.serialize_gs(g_commits1))
        datab.extend(dispersal_msg_list)
        datab.extend(self.sr.serialize_g(ephemeral_public_key))

        return bytes(datab)

    #@profile
    def _handle_dealer_msgs(self, tag, dealer_id):
        # TODO(@sourav): To add a check here to match hash
        commits, phis, phis_hat, ephkey, shared_key = self.data[dealer_id]
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commits
        self.tagvars[tag]['ephemeral_public_key'] = ephkey

        if self.acss_status[dealer_id]:
            self.tagvars[tag]['shares'] =  [phis, phis_hat]
            self.tagvars[tag]['witnesses'] = [None]
            return True
        return False

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
        if self.my_id == dealer_id:
            broadcast_msg = self._get_dealer_msg(values, n)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            dispersal_msg, commits, ephkey = self.decode_proposal(_m)
            ret = self.verify_proposal(dealer_id, dispersal_msg, commits, ephkey)
            return ret
        
        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()

        # avss processing
        await self._process_avss_msg(avss_id, dealer_id, rbc_msg)
        
        for task in self.tagvars[acsstag]['tasks']:
            task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]