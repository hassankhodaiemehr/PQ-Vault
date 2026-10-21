"""Light-client verification benchmark (runs on any machine with `pip install pqcrypto`)."""
import time, json, random, platform, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pycert as pc
def run(scheme='ML-DSA-44', n=4096, model='qrom', reps=7, seed=7):
    random.seed(seed); m = pc.SCHEMES[scheme]
    ws = [max(1, int(random.lognormvariate(0, 1.5) * 1e6)) for _ in range(n)]; T = sum(ws)
    msg = pc.h(b'checkpoint-17')
    # only signers that can be selected need real keys; to keep keygen cheap, all validators get real keys
    keys = [m.keygen() for _ in range(n)]
    pks = [k[0] for k in keys]; att = pc.leaves_tree([pc.att_leaf(pks[i], ws[i]) for i in range(n)])
    order = list(range(n)); random.shuffle(order); sigs = [None] * n; acc = 0
    for i in order:
        if acc >= 0.85 * T: break
        sigs[i] = m.sign(keys[i][1], msg); acc += ws[i]
    proven = T // 3
    t = time.perf_counter(); c = pc.build(msg, proven, pks, ws, sigs, att, model); tb = time.perf_counter() - t
    tv = []
    for _ in range(reps):
        t = time.perf_counter(); ok = pc.verify(msg, proven, scheme, att[-1][0], c, model, total=T, n=n); tv.append(time.perf_counter() - t); assert ok
    tv.sort()
    return dict(host=platform.node(), cpu=platform.processor() or platform.machine(), cores=os.cpu_count(), scheme=scheme, n=n, model=model,
                k=c['k'], reveals=len(c['rev']), cert_bytes=pc.size(c), build_ms=tb * 1e3, verify_ms=tv[reps // 2] * 1e3)
if __name__ == '__main__':
    tag = sys.argv[1] if len(sys.argv) > 1 else 'host'
    out = [run(s, n, mo) for s in ('ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87') for n in (1024, 4096) for mo in ('classical', 'qrom')]
    for o in out: o['tag'] = tag; print(json.dumps(o))
