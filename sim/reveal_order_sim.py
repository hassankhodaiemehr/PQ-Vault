"""Model-level checks of the QPoS-S reveal order and fallback proposers (Section 7 of the paper).
Samples the exponential race of Lemma 8 directly; checks Proposition 13 (late reveals) and
Theorem 11 (a slot is guaranteed iff its first B+1 ranks are honest; failure <= p_B)."""
import json, numpy as np
from math import comb
rng = np.random.default_rng(7)
out = {}
def lead_adv(adv_w, hon_w, trials):
    w = np.concatenate([adv_w, hon_w]); isadv = np.r_[np.ones(len(adv_w), bool), np.zeros(len(hon_w), bool)]
    order = np.argsort(rng.exponential(1, (trials, len(w))) / w, axis=1)
    return np.argmax(~isadv[order], axis=1)          # c = number of leading adversarial ranks
def honest(alpha, n=300):
    h = rng.lognormal(0, 1.5, n); return h / h.sum() * (1 - alpha)
# 1. one epoch, Sybil splitting: P[c>=x] vs alpha^x
out["one_epoch"] = []
for alpha in (0.2, 0.3):
    for split in (1, 10, 100):
        c = lead_adv(np.full(split, alpha / split), honest(alpha), 100000)
        out["one_epoch"].append(dict(alpha=alpha, split=split, P=[float((c >= x).mean()) for x in (1, 2, 3, 4)],
                                     bound=[alpha ** x for x in (1, 2, 3, 4)]))
# 2. steered chain of epochs: adversary picks, among 2^c candidates, the one maximizing next c
out["steered"] = []
for alpha in (0.05, 0.1, 0.2, 0.3):
    adv = np.full(20, alpha / 20); hon = honest(alpha); c = 0; E = []; cap = []; cs = []
    for ep in range(100000):
        m = 2 ** min(c, 20)
        cap.append(float((rng.random(m) < alpha).any()))  # target slot: adversary leads under some candidate
        c = int(lead_adv(adv, hon, m).max()); E.append(2 ** c); cs.append(c)
    mu = (1 - 2 * alpha) / (1 - 3 * alpha)
    out["steered"].append(dict(alpha=alpha, E2c=float(np.mean(E)), mu=mu, Ec=float(np.mean(cs)),
                               Ec_bound=mu * alpha / (1 - alpha), capture=float(np.mean(cap)),
                               P_c_ge_25=float(np.mean(np.array(cs) >= 25))))
# 3. fallback proposers with DoS budget B: a slot is NOT guaranteed if an adversarial identity is among
#    its first B+1 ranks (then the adversary can suppress the honest ones ahead of it and propose itself);
#    with L >= B this is the only way to lose the honest proposer. Bound p_B = 1-(1-alpha_B)^(B+1), w_max = 0.01
out["fallback"] = []
for alpha in (0.2, 0.3):
    hon = np.full(70, (1 - alpha) / 70); adv = np.full(30, alpha / 30)
    w = np.r_[adv, hon]; isadv = np.r_[np.ones(30, bool), np.zeros(70, bool)]
    order = np.argsort(rng.exponential(1, (200000, 100)) / w, axis=1)
    for B in (0, 1, 2):
        notguar = isadv[order[:, :B + 1]].any(axis=1)
        ab = alpha / (1 - B * (1 - alpha) / 70)
        out["fallback"].append(dict(alpha=alpha, B=B, not_guaranteed=float(notguar.mean()),
                                    bound=1 - (1 - ab) ** (B + 1)))
import os
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reveal_order_results.json'), 'w') as f:
    json.dump(out, f, indent=1)
print(json.dumps(out, indent=1))
