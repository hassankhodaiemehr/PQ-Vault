"""Multi-process networked certification experiment.
Aggregator and validators are separate OS processes talking over real TCP sockets (asyncio streams).
WAN conditions are emulated per message (region-based one-way latency + jitter + link serialisation)."""
import asyncio, json, os, random, struct, sys, time, multiprocessing as mp
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pycert as pc
M = pc.SCHEMES['ML-DSA-44']
REGIONS = {'us-east': 1.0, 'us-west': 35.0, 'eu': 40.0, 'sa': 60.0, 'asia': 95.0}   # one-way ms to aggregator (us-east)
REGION_P = [0.30, 0.15, 0.30, 0.05, 0.20]
UPLINK_MBPS = 50.0; AGG_MBPS = 1000.0
SIGN_MS = 0.42   # measured single-core ML-DSA-44 signing time of our Rust implementation (Sec. IX)

def region_of(seed, i):
    return random.Random(seed * 7919 + i).choices(list(REGIONS), REGION_P)[0]

def oneway(rng, region):
    return REGIONS[region] * rng.lognormvariate(0, 0.1) / 1e3

async def send(w, typ, payload):
    w.write(struct.pack('>BI', typ, len(payload)) + payload); await w.drain()

async def recv(r):
    hdr = await r.readexactly(5); typ, ln = struct.unpack('>BI', hdr); return typ, await r.readexactly(ln)

# ---------------- validator process ----------------
def validator_proc(port, ids, seed, offline, rounds):
    async def one(i):
        rng = random.Random(seed * 100003 + i)
        region = region_of(seed, i)
        pk, sk = M.keygen()
        # all N validators share 2 vCPUs, so signatures are produced ahead of time and each validator is
        # charged its single-core signing time as a delay (aggregator-side work is executed for real)
        pre = {pc.h(b'checkpoint', rd.to_bytes(4, 'big')): M.sign(sk, pc.h(b'checkpoint', rd.to_bytes(4, 'big'))) for rd in range(rounds)}
        r, w = await asyncio.open_connection('127.0.0.1', port)
        await send(w, 0, struct.pack('>I', i) + pk)                      # registration (pk)
        while True:
            try: typ, p = await recv(r)
            except asyncio.IncompleteReadError: return
            if typ == 9: return
            if typ == 1 and i not in offline:                           # header to sign
                sig = pre[p]
                await asyncio.sleep(SIGN_MS / 1e3 + oneway(rng, region) + (len(sig) * 8) / (UPLINK_MBPS * 1e6))
                await send(w, 2, struct.pack('>I', i) + sig)
            if typ == 3:                                                 # certificate -> light-client verification
                t = time.perf_counter(); c = json_cert_decode(p)
                ok = pc.verify(c['msg'], c['proven'], 'ML-DSA-44', c['ra'], c['cert'], total=c['total'], n=c['nstate'])
                await send(w, 4, json.dumps(dict(i=i, ok=ok, ms=(time.perf_counter() - t) * 1e3)).encode())
    async def main():
        await asyncio.gather(*[one(i) for i in ids])
    asyncio.run(main())

def json_cert_encode(msg, proven, ra, c, total, nstate):
    # (ra, proven, total, nstate) stand for the verifier state that a deployed light client reads from the vault
    hx = lambda b: b.hex()
    return json.dumps(dict(msg=hx(msg), proven=proven, ra=hx(ra), total=total, nstate=nstate, rs=hx(c['rs']), signed=c['signed'], n=c['n'], k=c['k'],
        rev=[(i, hx(pk), w, hx(s), l) for i, pk, w, s, l in c['rev']], ps=[hx(x) for x in c['ps']], pa=[hx(x) for x in c['pa']])).encode()

def json_cert_decode(b):
    d = json.loads(b); fx = bytes.fromhex
    cert = dict(rs=fx(d['rs']), signed=d['signed'], n=d['n'], k=d['k'], rev=[(i, fx(pk), w, fx(s), l) for i, pk, w, s, l in d['rev']],
                ps=[fx(x) for x in d['ps']], pa=[fx(x) for x in d['pa']])
    return dict(msg=fx(d['msg']), proven=d['proven'], ra=fx(d['ra']), total=d['total'], nstate=d['nstate'], cert=cert)

# ---------------- aggregator ----------------
async def aggregator(n, rounds, nprocs, offline_frac, target_frac, n_lightclients, seed):
    rng = random.Random(seed)
    ws = [max(1, int(rng.lognormvariate(0, 1.5) * 1e6)) for _ in range(n)]; T = sum(ws)
    regs = {}; conns = {}; ready = asyncio.Event(); inbox = asyncio.Queue()
    async def handle(r, w):
        typ, p = await recv(r); i = struct.unpack('>I', p[:4])[0]; regs[i] = p[4:]; conns[i] = (r, w)
        if len(regs) == n: ready.set()
        try:
            while True:
                typ, p = await recv(r); await inbox.put((typ, p, time.perf_counter()))
        except (asyncio.IncompleteReadError, ConnectionResetError): pass
    server = await asyncio.start_server(handle, '127.0.0.1', 0, limit=2**24)
    port = server.sockets[0].getsockname()[1]
    offline = set(rng.sample(range(n), int(offline_frac * n)))
    chunks = [list(range(k, n, nprocs)) for k in range(nprocs)]
    procs = [mp.Process(target=validator_proc, args=(port, ch, seed, offline, rounds)) for ch in chunks]
    for p in procs: p.start()
    await asyncio.wait_for(ready.wait(), 1800)
    pks = [regs[i] for i in range(n)]; att = pc.leaves_tree([pc.att_leaf(pks[i], ws[i]) for i in range(n)]); ra = att[-1][0]
    proven = T // 3; vrng = random.Random(seed + 1)
    vregion = {i: region_of(seed, i) for i in range(n)}
    results = []
    for rd in range(rounds):
        msg = pc.h(b'checkpoint', rd.to_bytes(4, 'big'))
        t0 = time.perf_counter(); bytes_in = 0
        async def push(i, typ, payload):
            await asyncio.sleep(oneway(vrng, vregion[i]))
            await send(conns[i][1], typ, payload)
        for i in range(n): asyncio.create_task(push(i, 1, msg))
        sigs = [None] * n; acc = 0; nver = 0; t_ver = 0.0
        deadline = t0 + 5.0
        while acc < target_frac * T and time.perf_counter() < deadline:
            try: typ, p, ta = await asyncio.wait_for(inbox.get(), timeout=max(0.01, deadline - time.perf_counter()))
            except asyncio.TimeoutError: break
            if typ != 2: continue
            # aggregator ingress serialisation
            bytes_in += len(p) + 5
            i = struct.unpack('>I', p[:4])[0]; s = p[4:]
            tv = time.perf_counter()
            try: M.verify(pks[i], msg, s); ok = True
            except Exception: ok = False
            t_ver += time.perf_counter() - tv; nver += 1
            if ok and sigs[i] is None: sigs[i] = s; acc += ws[i]
        t_collect = time.perf_counter() - t0 + bytes_in * 8 / (AGG_MBPS * 1e6)
        tb = time.perf_counter(); c = pc.build(msg, proven, pks, ws, sigs, att); t_build = time.perf_counter() - tb
        blob = json_cert_encode(msg, proven, ra, c, T, n); size = pc.size(c)
        # disseminate to light clients (sampled validators act as light clients), measure verification + delivery
        lcs = rng.sample(range(n), n_lightclients); t_send = time.perf_counter()
        async def push_lc(slot, i):
            await asyncio.sleep((slot + 1) * len(blob) * 8 / (AGG_MBPS * 1e6))   # egress serialisation
            await push(i, 3, blob)
        for slot, i in enumerate(lcs): asyncio.create_task(push_lc(slot, i))
        got = []
        while len(got) < n_lightclients:
            typ, p, ta = await inbox.get()
            if typ == 4: d = json.loads(p); d['arrive'] = ta - t_send; got.append(d)
            # late signatures from previous phase are ignored
        results.append(dict(n=n, round=rd, signers=sum(s is not None for s in sigs), signed_frac=acc / T,
            collect_ms=t_collect * 1e3, agg_verify_ms=t_ver * 1e3, n_verified=nver, build_ms=t_build * 1e3, cert_bytes=size,
            wire_bytes=len(blob), bytes_in=bytes_in, lc_verify_ms_median=sorted(x['ms'] for x in got)[len(got) // 2],
            lc_all_ok=all(x['ok'] for x in got), end_to_end_ms=(t_collect + t_build) * 1e3 + max(x['arrive'] for x in got) * 1e3 / 1))
        print(json.dumps(results[-1]), flush=True)
        while not inbox.empty(): inbox.get_nowait()
        await asyncio.sleep(0.5)
    for i in range(n): await send(conns[i][1], 9, b'')
    server.close()
    for p in procs: p.join(timeout=10)
    return results

if __name__ == '__main__':
    n = int(sys.argv[1]); rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    asyncio.run(aggregator(n, rounds, nprocs=2, offline_frac=0.10, target_frac=0.80, n_lightclients=8, seed=n))
