import asyncio
from collections import defaultdict
import logging
import math

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

def ceil(x):
    return int(math.ceil(x))


class RBCMsgType:
    ECHO = 2
    READY = 3
    TERMINATE = 4


async def reliable_agreement(sid, pid, n, f, input, output, send, receive):
    """
    Bracha Reliable Agreement
    """
    assert n >= 3 * f + 1
    assert f >= 0
    assert 0 <= pid < n

    k = f + 1  # Wait to reconstruct. (# noqa: E221)
    echo_threshold = 2 * f +1   # Wait for ECHO to send R. (# noqa: E221)
    ready_threshold = f + 1  # Wait for R to amplify. (# noqa: E221)
    output_threshold = 2 * f + 1  # Wait for this many R to output

    def broadcast(o):
        for i in range(n):
            send(i, o)

    async def send_echo():
        x = await input()
        broadcast((RBCMsgType.ECHO, x))

    echo_task = asyncio.create_task(send_echo())
        

    echo_counter = defaultdict(lambda: 0)
    ready_counter = defaultdict(lambda: 0)
    echo_senders = set()
    ready_senders = set()
    ready_sent = False

    terminate_senders = set()

    while True:  # main receive loop
        try:
            sender, msg = await receive()
                    
            if msg[0] == RBCMsgType.ECHO:
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
                    output(_digest)
                    echo_task.cancel()
                    return

        except Exception as e:
            print(e)