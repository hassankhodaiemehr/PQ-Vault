"""Monte Carlo evaluation of the QPoS leader election (revision, Sec. VIII / XI-E).
Hash-faithful: per-slot scores are derived from SHA3-256 of (reveal || seed)."""
import os, hashlib, json, math, sys
import numpy as np

def H(*parts):
    h = hashlib.sha3_256()
    for p in parts: h.update(p if isinstance(p, bytes) else str(p).encode())
    return h.digest()

def u01(d):  # 256-bit digest -> uniform in (0,1]
    return (int.from_bytes(d, 'big') + 1) / 2**256

def stakes_lognormal(n, rng, sigma=1.5):
    s = np.exp(rng.normal(0, sigma, n)); return s / s.sum()

# ---------- E5a: fairness of the exponential race (hash-faithful) ----------
def fairness(n=200, slots=40000, seed=1):
    rng = np.random.default_rng(seed); b = stakes_lognormal(n, rng)
    wins = np.zeros(n); S = H('epoch-seed')
    nonces = [H('nonce', i) for i in range(n)]
    for j in range(slots):
        Sj = H(S, j)
        sc = [-math.log2(u01(H(nonces[i], j, Sj))) / b[i] for i in range(n)]  # revealed value modelled as RO output
        wins[int(np.argmin(sc))] += 1
    exp = b * slots
    chi2 = float(((wins - exp) ** 2 / exp).sum())
    tv = 0.5 * float(np.abs(wins / slots - b).sum())
    return dict(n=n, slots=slots, chi2=chi2, dof=n - 1, tv_distance=tv,
                top10=[(float(b[i]), float(wins[i] / slots)) for i in np.argsort(-b)[:10]])

# ---------- E5b: Sybil invariance ----------
def sybil(alpha=0.2, splits=(1, 2, 5, 10, 50), slots=200000, seed=2):
    rng = np.random.default_rng(seed); out = []
    for m in splits:
        # honest: 100 equal validators sharing 1-alpha ; adversary splits alpha into m identities
        rates = np.concatenate([np.full(100, (1 - alpha) / 100), np.full(m, alpha / m)])
        E = rng.exponential(1.0, (slots, len(rates))) / rates
        w = np.argmin(E, axis=1) >= 100
        out.append(dict(m=m, share=float(w.mean()), se=float(w.std() / math.sqrt(slots))))
    return out

# ---------- E5c: targeted-slot capture under seed-update rules ----------
# Normalised total stake = 1. Adversary stake alpha (single identity is WLOG for the race).
def capture(alpha, rule, trials=400000, seed=3, m_ids=1):
    """Probability that the adversary is leader at a target slot T.
    rule 'qrl': S_T = H(S_{T-1} || reveal of the ACTUAL proposer of T-1); a skipped leader is replaced by the
      runner-up. If the top-L ranks at T-1 are adversarial, the adversary can steer S_T to any of L+1 seeds.
    rule 'schedule' (this work): S_j = H(S_0 || j) -> proposer identity at T-1 has no influence on S_T."""
    rng = np.random.default_rng(seed)
    if rule == 'schedule':
        X = rng.exponential(1, trials) / alpha; Y = rng.exponential(1, trials) / (1 - alpha)
        return float((X < Y).mean())
    # slot T-1: adversary identities' scores and honest top-(m_ids+1) order statistics (Poisson race)
    A = np.sort(rng.exponential(1, (trials, m_ids)) / (alpha / m_ids), axis=1)
    Hs = np.cumsum(rng.exponential(1, (trials, m_ids + 1)) / (1 - alpha), axis=1)
    # length of adversarial prefix in the merged ranking
    L = np.zeros(trials, dtype=int)
    for r in range(m_ids):
        L += (A[:, r] < Hs[:, 0]) & (L == r)
    opts = np.where(L >= 1, L + 1, 1)
    # under each reachable seed the adversary knows its own best score at T: Exp(alpha); picks the minimum
    maxo = opts.max()
    X = rng.exponential(1, (trials, maxo)) / alpha
    mask = np.arange(maxo)[None, :] < opts[:, None]
    x = np.where(mask, X, np.inf).min(axis=1)
    y = rng.exponential(1, trials) / (1 - alpha)
    return float((x < y).mean())

def closed_form(alpha, m):  # Prop. 5: m-way seed choice
    return m * alpha / (1 + (m - 1) * alpha)

# ---------- E5d: epoch-seed (last-revealer) bias on epoch share ----------
def epoch_bias(alpha, c, k=2000, trials=400, seed=4):
    """Adversary controls c late reveals -> chooses best of 2^c epoch seeds; metric = epoch block share."""
    rng = np.random.default_rng(seed); gains = []
    for t in range(trials):
        shares = rng.binomial(k, alpha, 2 ** c) / k
        gains.append(shares.max() - alpha)
    g = np.array(gains); bound = math.sqrt(2 * c * math.log(2) * alpha * (1 - alpha) / k)
    return dict(alpha=alpha, c=c, k=k, mean_gain=float(g.mean()), bound=bound)

if __name__ == '__main__':
    res = {}
    res['fairness'] = fairness()
    res['sybil'] = sybil()
    alphas = [0.05, 0.1, 0.2, 0.3, 0.4]
    res['capture'] = []
    for a in alphas:
        row = dict(alpha=a, schedule=capture(a, 'schedule'))
        for m in (1, 2, 4):
            row[f'qrl_m{m}'] = capture(a, 'qrl', m_ids=m)
        row['cf_m2'] = closed_form(a, 2); row['cf_m4'] = closed_form(a, 4); row['cf_m16'] = closed_form(a, 16)
        row['cf_expected_d1'] = a + a * (closed_form(a, 2) - a)
        res['capture'].append(row); print(row, file=sys.stderr)
    res['epoch_bias'] = [epoch_bias(a, c) for a in (0.1, 0.3) for c in (1, 4, 8, 12)]
    json.dump(res, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'qpos_results.json'), 'w'), indent=1)
    print(json.dumps(res['fairness'], indent=0)[:300])
