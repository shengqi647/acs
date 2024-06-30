from serilization import Serial
from pypairing import G1 as blsG1
from pypairing import Curve25519G as G1
import time

sr = Serial(G1)

nn = 16
# n = int(nn / 3 * 4 * nn)
n = 43 * 128 * 3

a = []

for i in range(n):
    a.append(G1.rand())

tm = time.time()
for i in range(n):
    sr.deserialize_g(sr.serialize_g(a[i]))
print(f"time G1: {(time.time() - tm)}")

b = []

for i in range(n):
    b.append(blsG1.rand())

blssr = Serial(blsG1)

tm = time.time()
for i in range(n):
    blssr.deserialize_g(blssr.serialize_g(b[i]))
print(f"time blsG1: {(time.time() - tm)}")

from charm.toolbox.pairinggroup import PairingGroup, G1

p = PairingGroup('SS512')
c = []
for i in range(n):
    c.append(p.random(G1))
tm = time.time()
for i in range(n):
    p.deserialize(p.serialize(c[i]))
print(f"time SS512G1: {(time.time() - tm)}")