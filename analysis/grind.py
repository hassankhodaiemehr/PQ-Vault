"""Empirical validation of the grinding term: an adversary whose valid intervals cover a fraction p of [0,Ws)
re-randomises its signature-tree root until all k coins land in its intervals. Expected trials = p^{-k}."""
import os, hashlib, json, random, math
def coin(j, R, Ws):
    d = hashlib.sha3_256(b'CCOK-COIN-v2' + j.to_bytes(8, 'little') + R + Ws.to_bytes(8, 'little')).digest()
    return int.from_bytes(d[:16], 'little') % Ws
def trials_to_success(p, k, Ws=10**9, rng=random.Random(1)):
    good = int(p * Ws); t = 0
    while True:
        t += 1; R = rng.getrandbits(256).to_bytes(32, 'big')
        if all(coin(j, R, Ws) < good for j in range(k)): return t
out = []
for p in (0.5, 1/3):
    for k in range(2, 13 if p == 0.5 else 9):
        reps = 300 if p ** -k < 600 else 120
        ts = [trials_to_success(p, k) for _ in range(reps)]
        m = sum(ts) / len(ts); se = (sum((x - m) ** 2 for x in ts) / (len(ts) - 1)) ** 0.5 / len(ts) ** 0.5
        out.append(dict(p=p, k=k, mean=m, se=se, theory=p ** -k)); print(out[-1])
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'grind.json'), 'w'), indent=1)
