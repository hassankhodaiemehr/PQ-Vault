"""EVM gas model for accepting a checkpoint certificate on Ethereum (Sec. IX-D).
All constants are explicit assumptions; see the paper for sources."""
import os, math, json
TX_BASE = 21000; CD_NZ = 16; CD_FLOOR = 40; TX_CAP = 2 ** 24
SSTORE_NEW = 22100; SSTORE_UPD = 5000
MERKLE_NODE = 110      # keccak(65B)=48 gas + ~60 gas loop/memory overhead
COIN = 360             # keccak(~140B) + interval search + bookkeeping
SIG = {'sol-nist': 8.1e6, 'sol-eth': 4.9e6, 'precompile': 4500}   # ZKNOX ETHDILITHIUM; EIP-8051 (draft)
PK_BYTES = {'sol-nist': 1312, 'sol-eth': 1312, 'precompile': 20512}  # EIP-8051 takes the expanded public key
SIG_BYTES = 2420

def calldata(nbytes, exec_gas):
    std = CD_NZ * nbytes + exec_gas
    return max(std, CD_FLOOR * nbytes)

def direct(n, reveals, kr, mode):
    d = math.ceil(math.log2(n))
    pkb = PK_BYTES[mode]
    leafhash = 30 + 6 * math.ceil((pkb + 8) / 32)
    per_rev_exec = SIG[mode] + 2 * d * MERKLE_NODE + leafhash + 30 + 6 * math.ceil((SIG_BYTES + 9) / 32)
    exec_gas = reveals * per_rev_exec + kr * COIN
    # multiproof hashes ~ measured ratio; use reveals*(d - log2 reveals)+ for both trees
    mp = 2 * max(0, reveals * (d - math.log2(max(reveals, 1))) + reveals)
    nbytes = reveals * (pkb + SIG_BYTES + 28) + 32 * mp + 64
    total_one = TX_BASE + calldata(nbytes, exec_gas)
    # split into transactions under the 2^24 cap (incremental verification keeps a running state: 2 SSTOREs/tx)
    per_tx_budget = TX_CAP - TX_BASE - 2 * SSTORE_UPD
    ntx = math.ceil((total_one - TX_BASE) / per_tx_budget)
    total = total_one + ntx * (TX_BASE + 2 * SSTORE_UPD) + SSTORE_NEW
    return dict(mode=mode, calldata_bytes=nbytes, exec_gas=exec_gas, total_gas=total, n_tx=ntx)

def opf_propose():
    nbytes = 4 + 32 * 5 + 8 * 2
    store = 6 * SSTORE_NEW
    return TX_BASE + calldata(nbytes, store)

def opf_finalize():
    return TX_BASE + 2 * SSTORE_UPD + SSTORE_NEW + 3000

def opf_challenge():
    return TX_BASE + calldata(40, 2 * SSTORE_NEW)

def opf_response(n, kr, mode):
    d = math.ceil(math.log2(n)); pkb = PK_BYTES[mode]
    nbytes = SIG_BYTES + pkb + 40 + 2 * d * 32 + math.ceil(math.log2(kr)) * 32
    exec_gas = SIG[mode] + (2 * d + math.ceil(math.log2(kr))) * MERKLE_NODE + COIN + (30 + 6 * math.ceil((pkb + 8) / 32)) + 2 * SSTORE_UPD
    return TX_BASE + calldata(nbytes, exec_gas)

def withdraw(depth=20):
    nbytes = 4 + 32 * depth + 96
    return TX_BASE + calldata(nbytes, depth * MERKLE_NODE + SSTORE_NEW + 9000 + 2600)

if __name__ == '__main__':
    out = {}
    for n, reveals, kr in [(1024, 118, 191), (65536, 188, 192)]:
        for mode in SIG:
            out[f'direct_{n}_{mode}'] = direct(n, reveals, kr, mode)
            out[f'resp_{n}_{mode}'] = opf_response(n, kr, mode)
    out['opf_propose'] = opf_propose(); out['opf_finalize'] = opf_finalize(); out['opf_challenge'] = opf_challenge(); out['withdraw'] = withdraw()
    json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gas.json'), 'w'), indent=1)
    for k, v in out.items(): print(k, v)
