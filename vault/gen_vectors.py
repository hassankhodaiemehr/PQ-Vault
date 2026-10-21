"""Generate a real ML-DSA-44 compact certificate for the PQVault Foundry tests.
Keys/signatures: ZKNOX dilithium_py (FIPS 204, NIST mode). Hashing: Keccak-256, matching PQVault.sol."""
import sys, os, math, random, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pythonref'))
from Crypto.Hash import keccak
from eth_abi import encode
from dilithium_py.dilithium.default_parameters import Dilithium2 as D
from dilithium_py.shake.shake_wrapper import shake128, shake256

def K(*ps):
    h = keccak.new(digest_bits=256)
    for p in ps: h.update(p)
    return h.digest()
u64 = lambda v: int(v).to_bytes(8, 'big')
u32 = lambda v: int(v).to_bytes(4, 'big')

def expanded_pk(pk):
    rho, t1 = D._unpack_pk(pk)
    A_hat = D._expand_matrix_from_seed(rho, _xof=shake128)
    tr = D._h(pk, 64, _xof=shake256)
    t1 = t1.scale(1 << D.d).to_ntt()
    A = [[[int(v) for v in col] for col in row] for row in A_hat.compact_256(32)]
    T1 = [[int(v) for v in row[0]] for row in t1.compact_256(32)]
    return encode(['bytes', 'bytes', 'bytes'], [encode(['uint256[][][]'], [A]), tr, encode(['uint256[][]'], [T1])])

class Tree:
    def __init__(self, leaves):
        self.levels = [leaves]
        while len(self.levels[-1]) > 1:
            l = self.levels[-1]; self.levels.append([K(b'\x01', l[i], l[i + 1]) for i in range(0, len(l), 2)])
    def root(self): return self.levels[-1][0]
    def path(self, i):
        out = []
        for l in self.levels[:-1]: out.append(l[i ^ 1]); i >>= 1
        return out

LAMBDA, LOG2Q, KAPPA = 128, 64, 4
# PQVault is deployed at this address in the tests (deployCodeTo) so that withdrawal leaves can bind address(this)
VAULT_ADDR = bytes.fromhex('00000000000000000000000000000000000Fa017'); CHAIN_ID = 31337  # Foundry default chain id
def log2fp(x):  # bit-exact port of PQVault.log2fp (64.64 fixed point)
    assert x >= 1 << 64
    n, y = 0, x >> 64
    while y > 1: y >>= 1; n += 1
    r, y = n << 64, x >> n
    for i in range(32):
        y = (y * y) >> 64
        if y >= 2 << 64: y >>= 1; r |= 1 << (63 - i)
    return r
TARGET_FP = (LAMBDA + 2 * LOG2Q + KAPPA) << 64
def num_reveals(Ws, Wp):
    """k = smallest integer with k * log2fp(Ws/Wp) >= 260, as required on chain."""
    l = log2fp((Ws << 64) // Wp); k = -(-TARGET_FP // l)
    assert k * l >= TARGET_FP and (k - 1) * l < TARGET_FP
    assert k == math.ceil((LAMBDA + 2 * LOG2Q + KAPPA) / math.log2(Ws / Wp)), 'fixed-point and float rule differ'
    return k

def main(n_real=64, depth=16, seed=11, vault_addr=VAULT_ADDR, chain_id=CHAIN_ID):
    rng = random.Random(seed); N = 1 << depth
    ws = [max(1, int(rng.lognormvariate(0, 1.5) * 1e6)) for _ in range(n_real)]
    W = sum(ws); Wp = W // 3
    keys = [D.key_derive(bytes([i % 256, i // 256]) * 16, _xof=shake256, _xof2=shake128) for i in range(n_real)]
    pkdata = [expanded_pk(pk) for pk, _ in keys]
    codehash = [K(b'\x00', d) for d in pkdata]
    att_leaves = [K(b'\x00', codehash[i], u64(ws[i])) for i in range(n_real)] + [K(b'\x00', b'\x00' * 32, u64(0))] * (N - n_real)
    att = Tree(att_leaves); rAtt = att.root()
    # withdrawals tree (depth WDEPTH = 20), index-aware ordering, leaf bound to (vault address, chain id)
    wleaf_of = lambda rcpt, amt, nonce: K(b'\x00', vault_addr, chain_id.to_bytes(32, 'big'), rcpt, amt.to_bytes(32, 'big'), u64(nonce))
    recipient = bytes.fromhex('00000000000000000000000000000000000000aa'); amount = 10 ** 18; nonce = 7
    wd = 20; windex = 0x5A5A5 & ((1 << wd) - 1)
    wleaves = {windex: wleaf_of(recipient, amount, nonce),
               windex ^ 1: wleaf_of(bytes.fromhex('00000000000000000000000000000000000000bb'), 2 * amount, 8),
               windex ^ 6: wleaf_of(bytes.fromhex('00000000000000000000000000000000000000cc'), 3 * amount, 9)}
    empty = [K(b'\x00', b'empty')]
    for _ in range(wd): empty.append(K(b'\x01', empty[-1], empty[-1]))
    level = dict(wleaves); wpath = []; i = windex
    for d in range(wd):
        wpath.append(level.get(i ^ 1, empty[d]))
        nxt = {}
        for x in set(q >> 1 for q in level):
            l, r = level.get(2 * x, empty[d]), level.get(2 * x + 1, empty[d])
            nxt[x] = K(b'\x01', l, r)
        level = nxt; i >>= 1
    omega = level[0]
    # self-check of the index-aware path
    node, i = wleaves[windex], windex
    for sib in wpath: node = K(b'\x01', node, sib) if i % 2 == 0 else K(b'\x01', sib, node); i >>= 1
    assert node == omega
    # checkpoint header; M is recomputed on chain exactly like this (PQVault.checkpointMsg)
    e, lastM = 1, b'\x00' * 32
    hBlock, stateRoot, bindRoot = K(b'sidechain block e=1'), K(b'sidechain state root e=1'), K(b'bind root e=1')
    rAttNext, Wnext, Nnext = rAtt, W, N  # attestor set unchanged in this vector
    M = K(encode(['string', 'uint256', 'address', 'uint256', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'uint64', 'uint64'],
                 ['PQV-CP', chain_id, '0x' + vault_addr.hex(), e, lastM, hBlock, stateRoot, omega, rAttNext, bindRoot, Wnext, Nnext]))
    order = list(range(n_real)); rng.shuffle(order); signer = [False] * n_real; acc = 0
    for i in order:
        if acc >= 0.85 * W: break
        signer[i] = True; acc += ws[i]
    sigs = [D.sign(keys[i][1], M, deterministic=True, _xof=shake256, _xof2=shake128) if signer[i] else None for i in range(n_real)]
    L = [0] * n_real; a = 0
    for i in range(n_real):
        if signer[i]: L[i] = a; a += ws[i]
    Ws = a
    unsigned = K(b'\x00', b'\x00unsigned')
    sig_leaves = [K(b'\x00', b'\x01', sigs[i], u64(L[i])) if signer[i] else unsigned for i in range(n_real)] + [unsigned] * (N - n_real)
    st = Tree(sig_leaves); rSig = st.root()
    k = num_reveals(Ws, Wp)
    idx = [i for i in range(n_real) if signer[i]]
    recs = []
    for j in range(k):
        c = int.from_bytes(K(b'CCOK-COIN-v2', u64(j), rSig, rAtt, u64(Ws), u64(Wp), u64(N), M)[:16], 'big') % Ws
        pos = next(i for i in idx if L[i] <= c < L[i] + ws[i])
        recs.append((j, pos))
    # C_cert leaf binds the full record, including both Merkle paths (matches PQVault._committed)
    rec_leaf = lambda j, pos: K(encode(['uint64', 'uint32', 'bytes32', 'uint64', 'bytes32', 'uint64', 'bytes32', 'bytes32'],
                                       [j, pos, codehash[pos], ws[pos], K(sigs[pos]), L[pos], K(b''.join(st.path(pos))), K(b''.join(att.path(pos)))]))
    kpow, ct_depth = 1, 0
    while kpow < k: kpow <<= 1; ct_depth += 1
    cleaves = [rec_leaf(j, p) for j, p in recs] + [K(b'pad')] * (kpow - k)
    ct = Tree(cleaves); cCert = ct.root()
    distinct = sorted(set(p for _, p in recs))
    records = []
    for j, p in recs:
        records.append((j, p, codehash[p], ws[p], sigs[p], L[p], st.path(p), att.path(p), ct.path(j)))
    out = encode(
        ['(uint64,uint64,uint64,bytes32,bytes32,bytes32,uint64,uint64,bytes32,uint32[],bytes[],(uint64,uint32,bytes32,uint64,bytes,uint64,bytes32[],bytes32[],bytes32[])[],bytes32,address,uint256,uint64,uint256,bytes32[],address,uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64)'],
        [(W, Wp, N, M, rAtt, rSig, Ws, k, cCert, distinct, [pkdata[p] for p in distinct], records, omega, '0x' + recipient.hex(), amount, nonce, windex, wpath,
          '0x' + vault_addr.hex(), chain_id, hBlock, stateRoot, rAttNext, bindRoot, Wnext, Nnext)])
    open(os.path.join(os.path.dirname(__file__), 'vectors.bin'), 'wb').write(out)
    meta = dict(W=W, Wp=Wp, Ws=Ws, N=N, n_real=n_real, k=k, distinct=len(distinct), signers=sum(signer), depth=depth, cert_depth=ct_depth, wdepth=wd, windex=windex, M=M.hex())
    json.dump(meta, open(os.path.join(os.path.dirname(__file__), 'vectors_meta.json'), 'w')); print(meta)

if __name__ == '__main__':
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 64)
