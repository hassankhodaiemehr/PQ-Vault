"""Python reference of the corrected compact certificate (same logic as pqcert Rust crate, SHA3-256 instead of Keccak)."""
import hashlib, math
import pqcrypto
SCHEMES = {'ML-DSA-44': pqcrypto.ml_dsa_44, 'ML-DSA-65': pqcrypto.ml_dsa_65, 'ML-DSA-87': pqcrypto.ml_dsa_87}

def h(*ps):
    x = hashlib.sha3_256()
    for p in ps: x.update(p)
    return x.digest()
L8 = lambda v: int(v).to_bytes(8, 'little')

def leaves_tree(data):
    n = len(data); size = 1
    while size < n: size <<= 1
    lvl = [h(b'\x00', data[i]) if i < n else h(b'\x00', b'pad') for i in range(size)]
    levels = [lvl]
    while len(lvl) > 1:
        lvl = [h(b'\x01', lvl[i], lvl[i + 1]) for i in range(0, len(lvl), 2)]; levels.append(lvl)
    return levels

def multiproof(levels, pos):
    known = sorted(set(pos)); out = []
    for l in range(len(levels) - 1):
        s = set(known)
        for i in known:
            if (i ^ 1) not in s: out.append(levels[l][i ^ 1])
        known = sorted(set(i >> 1 for i in known))
    return out

def verify_multiproof(root, depth, pos, leaves, proof):
    cur = list(zip(pos, leaves)); pi = 0
    for _ in range(depth):
        nxt = []; k = 0
        while k < len(cur):
            i, x = cur[k]
            if i % 2 == 0 and k + 1 < len(cur) and cur[k + 1][0] == i + 1:
                l, r = x, cur[k + 1][1]; k += 2
            else:
                if pi >= len(proof): return False
                s = proof[pi]; pi += 1; l, r = (x, s) if i % 2 == 0 else (s, x); k += 1
            nxt.append((i >> 1, h(b'\x01', l, r)))
        cur = nxt
    return pi == len(proof) and len(cur) == 1 and cur[0][1] == root

def num_reveals(signed, proven, lam=128, log2q=64, model='qrom'):
    num = lam + log2q if model == 'classical' else lam + 2 * log2q + 4
    return math.ceil(num / math.log2(signed / proven))

def coin(j, rs, ra, signed, proven, msg, n):
    d = h(b'CCOK-COIN-v2', L8(j), rs, ra, L8(signed), L8(proven), L8(n), msg)
    return int.from_bytes(d[:16], 'little') % signed

def att_leaf(pk, w): return pk + L8(w)
def sig_leaf(sig, l): return b'\x01' + sig + L8(l) if sig is not None else b'\x00unsigned'

def build(msg, proven, pks, ws, sigs, att_levels, model='qrom'):
    n = len(pks); ls = [0] * n; acc = 0
    for i in range(n):
        if sigs[i] is not None: ls[i] = acc; acc += ws[i]
    signed = acc; assert signed > proven
    st = leaves_tree([sig_leaf(sigs[i], ls[i]) for i in range(n)])
    rs, ra = st[-1][0], att_levels[-1][0]
    k = num_reveals(signed, proven, model=model)
    idx = [i for i in range(n) if sigs[i] is not None]; ends = [ls[i] + ws[i] for i in idx]
    import bisect
    chosen = set()
    for j in range(k):
        c = coin(j, rs, ra, signed, proven, msg, n); chosen.add(idx[bisect.bisect_right(ends, c)])
    pos = sorted(chosen)
    rev = [(i, pks[i], ws[i], sigs[i], ls[i]) for i in pos]
    return dict(rs=rs, signed=signed, n=n, k=k, rev=rev, ps=multiproof(st, pos), pa=multiproof(att_levels, pos))

def size(c):
    return 44 + sum(4 + len(pk) + 8 + len(s) + 8 for _, pk, _, s, _ in c['rev']) + 32 * (len(c['ps']) + len(c['pa']))

def verify(msg, proven, scheme, ra, c, model='qrom', total=None, n=None, min_ratio=1.1):
    m = SCHEMES[scheme]
    if c['signed'] <= proven or c['k'] != num_reveals(c['signed'], proven, model=model): return False
    if total is not None and c['signed'] > total: return False      # Ws <= W from verifier state
    if n is not None and c['n'] != n: return False                   # N from verifier state
    if c['signed'] < min_ratio * proven: return False                # bounds k_rev
    depth = max(0, math.ceil(math.log2(c['n']))) if c['n'] > 1 else 0
    rev = c['rev']
    if not rev or len(rev) > c['k']: return False                    # |P| <= k_rev
    if any(rev[t][0] >= rev[t + 1][0] for t in range(len(rev) - 1)): return False
    if any(not 0 <= r[0] < c['n'] for r in rev): return False          # positions in [N]
    for i, pk, w, s, l in rev:
        if w <= 0 or l + w > c['signed']: return False
    used = [False] * len(rev)
    for j in range(c['k']):
        x = coin(j, c['rs'], ra, c['signed'], proven, msg, c['n'])
        hit = [t for t, (_, _, w, _, l) in enumerate(rev) if l <= x < l + w]
        if not hit: return False                                     # every coin covered
        for t in hit: used[t] = True
    if not all(used): return False                                   # every reveal used by some coin
    for i, pk, w, s, l in rev:
        try: m.verify(pk, msg, s)
        except Exception: return False
    pos = [r[0] for r in rev]
    if not verify_multiproof(c['rs'], depth, pos, [h(b'\x00', sig_leaf(r[3], r[4])) for r in rev], c['ps']): return False
    return verify_multiproof(ra, depth, pos, [h(b'\x00', att_leaf(r[1], r[2])) for r in rev], c['pa'])
