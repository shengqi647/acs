from collections import defaultdict
import logging
import math

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

def ceil(x):
    return int(math.ceil(x))


class RBCMsgType:
    PROPOSE = 1
    ECHO = 2
    READY = 3
    TERMINATE = 4


async def optqrbc_b(sid, pid, n, f, leader, predicate, input, output, send, receive):
    """
    Bracha Reliable Broadcast
    """
    assert n >= 3 * f + 1
    assert f >= 0
    assert 0 <= leader < n
    assert 0 <= pid < n

    k = f + 1  # Wait to reconstruct. (# noqa: E221)
    echo_threshold = 2 * f +1   # Wait for ECHO to send R. (# noqa: E221)
    ready_threshold = f + 1  # Wait for R to amplify. (# noqa: E221)
    output_threshold = 2 * f + 1  # Wait for this many R to output

    def broadcast(o):
        for i in range(n):
            send(i, o)

    if pid == leader:
        m = input

        assert isinstance(m, (str, bytes))
        logger.debug("[%d] Input received: %d bytes" % (pid, len(m)))
        
        broadcast((RBCMsgType.PROPOSE, m))
        
    stripes = [None for _ in range(n)]
    
    echo_counter = defaultdict(lambda: 0)
    ready_counter = defaultdict(lambda: 0)
    echo_senders = set()
    ready_senders = set()
    ready_sent = False
    leader_hash = None
    leader_msg = None

    terminate_senders = set()
    committed_hash = None


    while True:  # main receive loop
        try:
            sender, msg = await receive()
            if msg[0] == RBCMsgType.PROPOSE and leader_hash is None:
                (_, leader_msg) = msg
                if sender != leader:
                    logger.info(f"[{pid}] PROPOSE message from other than leader: {sender}")
                    continue
            
                valid = await predicate(leader_msg)
                if valid:
                    leader_hash = leader_msg
                    broadcast((RBCMsgType.ECHO, leader_hash))

                    # TODO: double check this
                    if leader_hash == committed_hash:
                        broadcast((RBCMsgType.TERMINATE, 0))
                    
            elif msg[0] == RBCMsgType.ECHO:
                (_, _digest) = msg
                if sender in echo_senders:
                    # Received redundant ECHO message from the same sender
                    continue
                echo_senders.add(sender)
                echo_counter[_digest] = echo_counter[_digest]+1
                
                if echo_counter[_digest] >= echo_threshold and not ready_sent:
                    ready_sent = True
                    broadcast((RBCMsgType.READY, _digest))
            
            elif msg[0] == RBCMsgType.READY:
                (_, _digest) = msg
                if sender in ready_senders:
                    logger.info("[{pid}] Redundant R")
                    continue
                ready_senders.add(sender)
                ready_counter[_digest] = ready_counter[_digest]+1
                if ready_counter[_digest] >= ready_threshold and not ready_sent:
                    ready_sent = True
                    broadcast((RBCMsgType.READY, _digest))
                
                if ready_counter[_digest] >= output_threshold:
                    committed_hash = _digest
                    if _digest == leader_hash:
                        committed = True
                        output(leader_msg)
                        return

            elif msg[0] == RBCMsgType.TERMINATE:
                if sender in terminate_senders:
                    logger.info("[{pid}] Redundant TERMINATE")
                    continue
                terminate_senders.add(sender)
                if len(terminate_senders) == n:
                    return

        except Exception as e:
            print(e)