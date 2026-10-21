import json, math, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
C = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#6250d6']
plt.rcParams.update({'font.size': 8, 'font.family': 'serif', 'axes.linewidth': 0.8, 'axes.edgecolor': 'black',
                     'axes.grid': True, 'grid.color': '#e3e3e3', 'grid.linewidth': 0.5, 'axes.axisbelow': True,
                     'lines.linewidth': 1.4, 'lines.markersize': 4, 'legend.frameon': True, 'legend.edgecolor': '#555555',
                     'legend.fancybox': False, 'legend.framealpha': 1.0, 'legend.fontsize': 6.5, 'legend.borderpad': 0.4,
                     'xtick.direction': 'in', 'ytick.direction': 'in', 'xtick.top': True, 'ytick.right': True,
                     'axes.spines.top': True, 'axes.spines.right': True, 'savefig.bbox': 'tight', 'savefig.pad_inches': 0.03})
BELOW = dict(loc='upper center', bbox_to_anchor=(0.5, -0.24), ncol=2)
import os
BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
# output folder: $FIG_OUT, else paper/figs of the repository, else ../manuscript/figs (authors' layout)
OUT = os.environ.get('FIG_OUT') or next((d for d in (os.path.join(BASE, 'paper', 'figs'), os.path.join(BASE, '..', 'manuscript', 'figs')) if os.path.isdir(d)), os.path.join(BASE, 'figs'))
os.makedirs(OUT, exist_ok=True); OUT = OUT + os.sep
W1 = 3.45
# ---- Fig: reveal count and effective security ----
fig, ax = plt.subplots(1, 2, figsize=(W1 * 2, 2.1))
fig.subplots_adjust(wspace=0.28)
r = np.linspace(1.2, 5, 200)
ax[0].plot(r, np.ceil(192 / np.log2(r)), color=C[0], label='classical rule (Micali et al.)')
ax[0].plot(r, np.ceil(260 / np.log2(r)), color=C[1], ls='--', label='QROM rule (this work)')
ax[0].set_yscale('log'); ax[0].set_xlim(1.2, 5); ax[0].set_ylim(60, 3000)
ax[0].set_xlabel(r'$W_s/W_p$'); ax[0].set_ylabel(r'reveals $k_{\mathrm{rev}}$')
ax[0].axvline(2.55, color='#666', lw=0.7, ls=':')
ax[0].annotate(r'$W_p{=}W/3$, 85% signed', xy=(2.55, 1400), xytext=(2.75, 1400), fontsize=6.5, va='center',
               arrowprops=dict(arrowstyle='-', color='#666', lw=0.6), bbox=dict(boxstyle='square,pad=0.2', fc='white', ec='none'))
ax[0].set_title('(a) Reveals required', fontsize=8)
ax[0].legend(loc='upper center', bbox_to_anchor=(0.5, -0.24), ncol=1)
lq = np.arange(20, 81)
for lam, col, ls in ((128, C[0], '-'), (192, C[2], '-.')):
    k = np.ceil((lam + lq) / math.log2(2.55))
    eps = (1 / 2.55) ** k
    T = 2.0 ** lq / (2 * (16 + k + 1))
    succ = np.minimum(0, np.log2(4 / math.pi ** 2) + 2 * np.log2(2 * T + 1) + np.log2(eps))
    ax[1].plot(lq, -succ, color=col, ls=ls, label=fr'classical rule, attack, $\lambda$={lam}')
    ax[1].plot(lq, np.full_like(lq, lam, dtype=float), color=col, lw=0.9, ls=':', label=fr'QROM rule, proven, $\lambda$={lam}')
ax[1].set_xlim(20, 80); ax[1].set_ylim(40, 210)
ax[1].set_xlabel(r'$\log_2 q$ (adversary oracle queries)'); ax[1].set_ylabel('security (bits)')
ax[1].set_title('(b) Security against Grover grinding', fontsize=8)
ax[1].legend(**BELOW)
fig.savefig(OUT + 'fig_kr.pdf'); plt.close(fig)

# ---- Fig: certificate size vs N ----
rows = [json.loads(l) for l in open(os.path.join(BASE, 'pqcert/results/bench_cloud.jsonl'))]
fig, ax = plt.subplots(figsize=(W1, 1.75))
for dist, col, mk in (('uniform', C[0], 'o'), ('lognormal', C[1], 's'), ('zipf', C[2], '^')):
    for model, ls in (('qrom', '-'), ('classical', ':')):
        pts = sorted((x['n'], x['cert_bytes']) for x in rows if x['dist'] == dist and x['model'] == model and x['scheme'] in ('ML-DSA-44', 'Dilithium2-r3') and abs(x['proven_frac'] - 1/3) < 1e-3)
        ax.plot([p[0] for p in pts], [p[1] / 1e6 for p in pts], color=col, ls=ls, marker=mk, label=f'{dist}, {"QROM" if model=="qrom" else "classical"}')
pts = sorted((x['n'], x['naive_bytes']) for x in rows if x['dist'] == 'lognormal' and x['model'] == 'qrom' and x['scheme'] in ('ML-DSA-44', 'Dilithium2-r3') and abs(x['proven_frac'] - 1/3) < 1e-3)
ax.plot([p[0] for p in pts], [p[1] / 1e6 for p in pts], color='#444', marker='x', label='all signatures')
ax.set_xscale('log', base=2); ax.set_yscale('log'); ax.set_xlabel('validators $N$'); ax.set_ylabel('size (MB)')
hh, ll = ax.get_legend_handles_labels(); od = [0, 1, 6, 2, 3, 4, 5]
ax.legend([hh[i] for i in od], [ll[i] for i in od], loc='upper center', bbox_to_anchor=(0.5, -0.3), ncol=3, fontsize=5.8, handlelength=1.6, columnspacing=0.8, handletextpad=0.4, borderpad=0.3, labelspacing=0.25); ax.set_ylim(0.15, 400)
fig.savefig(OUT + 'fig_size.pdf'); plt.close(fig)

# ---- Fig: steering ----
q = json.load(open(os.path.join(BASE, 'sim/qpos_results.json')))
cap = q['capture']; a = [x['alpha'] for x in cap]
fig, ax = plt.subplots(figsize=(W1, 2.3))
aa = np.linspace(0.02, 0.45, 100)
pm = lambda al, m: m * al / (1 + (m - 1) * al)
ax.plot(aa, aa, color=C[0], label='QPoS-S schedule (theory: $\\alpha$)')
ax.plot(a, [x['schedule'] for x in cap], 'o', color=C[0], label='QPoS-S (simulated)')
ax.plot(aa, aa + aa ** 2 * (1 - aa) / (1 + aa), color=C[1], ls='--', label='runner-up rule, 1 identity (theory)')
ax.plot(a, [x['qrl_m1'] for x in cap], 's', color=C[1], label='runner-up rule, 1 identity (sim.)')
ax.plot(a, [x['qrl_m4'] for x in cap], '^', color=C[2], label='runner-up rule, 4 identities (sim.)')
ax.plot(aa, pm(aa, 16), color=C[3], ls='-.', label=r'$p_{16}(\alpha)$: 16-way choice (4 late reveals)')
ax.set_xlabel(r'adversarial stake $\alpha$'); ax.set_ylabel('Pr[capture target slot]'); ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.2), ncol=2); ax.set_xlim(0, 0.46); ax.set_ylim(0, 1)
fig.savefig(OUT + 'fig_steer.pdf'); plt.close(fig)

# ---- Fig: network latency breakdown ----
net = [json.loads(l) for l in open(os.path.join(BASE, 'net/net_results.jsonl'))]
ns = sorted(set(x['n'] for x in net))
def med(n, key): v = sorted(x[key] for x in net if x['n'] == n); return v[len(v) // 2]
col = [med(n, 'collect_ms') for n in ns]; bld = [med(n, 'build_ms') for n in ns]; e2e = [med(n, 'end_to_end_ms') for n in ns]
dis = [e - c - b for e, c, b in zip(e2e, col, bld)]
fig, ax = plt.subplots(figsize=(W1, 2.15))
x = np.arange(len(ns)); w = 0.55
ax.bar(x, col, w, color=C[0], label='collect signatures (80% stake)')
ax.bar(x, bld, w, bottom=col, color=C[3], label='build certificate')
ax.bar(x, dis, w, bottom=np.array(col) + np.array(bld), color=C[2], label='disseminate + verify')
for i, e in enumerate(e2e): ax.text(i, e + 15, f'{e:.0f}', ha='center', fontsize=7)
ax.set_xticks(x, [str(n) for n in ns]); ax.set_xlabel('validators $N$'); ax.set_ylabel('median latency (ms)')
ax.set_ylim(0, max(e2e) * 1.15); ax.grid(axis='x', visible=False); ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.22), ncol=2)
fig.savefig(OUT + 'fig_net.pdf'); plt.close(fig)

# ---- Fig: grinding validation ----
g = json.load(open(os.path.join(BASE, 'analysis/grind.json')))
fig, ax = plt.subplots(figsize=(W1, 2.05))
for p, colr, mk, lab in ((0.5, C[0], 'o', '1/2'), (1 / 3, C[1], 's', '1/3')):
    pts = [x for x in g if abs(x['p'] - p) < 1e-9]
    ax.errorbar([x['k'] for x in pts], [x['mean'] for x in pts], yerr=[2 * x['se'] for x in pts], fmt=mk, color=colr, ms=4, capsize=2, label=f'measured, $W_k/W_s$={lab}')
    ax.plot([x['k'] for x in pts], [x['theory'] for x in pts], color=colr, lw=0.9, label=f'$(W_s/W_k)^{{k}}$, {lab}')
ax.set_yscale('log', base=2); ax.set_xlabel('reveals $k$'); ax.set_ylabel('oracle trials to forge (mean)'); ax.legend(loc='lower right')
fig.savefig(OUT + 'fig_grind.pdf'); plt.close(fig)
print('figs done')

# ---- Fig: combined 3x1 panel (k_rev rule, Grover security, steering) ----
from matplotlib.legend_handler import HandlerTuple
fig, ax = plt.subplots(1, 3, figsize=(W1 * 2.05, 1.85))
fig.subplots_adjust(wspace=0.36)
LEG = dict(loc='upper center', bbox_to_anchor=(0.5, -0.24), ncol=1, fontsize=5.4, handlelength=1.8, borderpad=0.3, labelspacing=0.2, handletextpad=0.5)
r = np.linspace(1.2, 5, 200)
ax[0].plot(r, np.ceil(192 / np.log2(r)), color=C[0], label='classical rule (Micali et al.)')
ax[0].plot(r, np.ceil(260 / np.log2(r)), color=C[1], ls='--', label='QROM rule (this work)')
ax[0].set_yscale('log'); ax[0].set_xlim(1.2, 5); ax[0].set_ylim(60, 3000)
ax[0].set_xlabel(r'$W_s/W_p$'); ax[0].set_ylabel(r'reveals $k_{\mathrm{rev}}$')
ax[0].axvline(2.55, color='#666', lw=0.7, ls=':')
ax[0].text(2.68, 1500, r'$W_p{=}W/3$,' '\n' r'85% signed', fontsize=6.2, va='center', bbox=dict(boxstyle='square,pad=0.15', fc='white', ec='none'))
ax[0].set_title('(a) Reveals required', fontsize=8)
ax[0].legend(**LEG)
lq = np.arange(20, 81)
for lam, col, ls in ((128, C[0], '-'), (192, C[2], '-.')):
    k = np.ceil((lam + lq) / math.log2(2.55)); eps = (1 / 2.55) ** k
    T = 2.0 ** lq / (2 * (16 + k + 1))
    succ = np.minimum(0, np.log2(4 / math.pi ** 2) + 2 * np.log2(2 * T + 1) + np.log2(eps))
    ax[1].plot(lq, -succ, color=col, ls=ls, label=fr'classical rule, attacked, $\lambda$={lam}')
    ax[1].plot(lq, np.full_like(lq, lam, dtype=float), color=col, lw=0.9, ls=':', label=fr'QROM rule, proven, $\lambda$={lam}')
ax[1].set_xlim(20, 80); ax[1].set_ylim(40, 210)
ax[1].set_xlabel(r'$\log_2 q$ (oracle queries)'); ax[1].set_ylabel('security (bits)')
ax[1].set_title('(b) Security under Grover grinding', fontsize=8)
ax[1].legend(**LEG)
q = json.load(open(os.path.join(BASE, 'sim/qpos_results.json')))
cap = q['capture']; a = [x['alpha'] for x in cap]
aa = np.linspace(0.02, 0.45, 100); pm = lambda al, m: m * al / (1 + (m - 1) * al)
l1, = ax[2].plot(aa, aa, color=C[0]); m1, = ax[2].plot(a, [x['schedule'] for x in cap], 'o', color=C[0], ms=3.2)
ro = json.load(open(os.path.join(BASE, 'sim/reveal_order_results.json')))['steered']
def pcap(al):  # Prop. 12 bound, B = 0
    mu = (1 - 2 * al) / (1 - 3 * al); p = al
    return p + sum(min(1, mu * al ** x) * ((1 - p) ** (2 ** (x - 1)) - (1 - p) ** (2 ** x)) for x in range(1, 40))
ab = np.linspace(0.02, 0.32, 80)
l5, = ax[2].plot(ab, [pcap(v) for v in ab], color=C[4], ls=':'); m5, = ax[2].plot([x['alpha'] for x in ro], [x['capture'] for x in ro], 'D', color=C[4], ms=3.0)
l2, = ax[2].plot(aa, aa + aa ** 2 * (1 - aa) / (1 + aa), color=C[1], ls='--'); m2, = ax[2].plot(a, [x['qrl_m1'] for x in cap], 's', color=C[1], ms=3.2)
m3, = ax[2].plot(a, [x['qrl_m4'] for x in cap], '^', color=C[2], ms=3.2)
l4, = ax[2].plot(aa, pm(aa, 16), color=C[3], ls='-.')
ax[2].legend([(l1, m1), (l5, m5), (l2, m2), m3, l4], ['QPoS-S, fixed seed: theory, sim.', r'QPoS-S, steered seeds: bound $\pi_{\mathsf{cap}}$, sim.', 'runner-up rule, 1 identity', 'runner-up rule, 4 identities (sim.)', r'$p_{16}(\alpha)$: 4 late reveals'],
             handler_map={tuple: HandlerTuple(ndivide=None)}, **LEG)
ax[2].set_xlabel(r'adversarial stake $\alpha$'); ax[2].set_ylabel('Pr[capture target slot]')
ax[2].set_xlim(0, 0.46); ax[2].set_ylim(0, 1)
ax[2].set_title('(c) Steering a target slot', fontsize=8)
fig.savefig(OUT + 'fig_theory.pdf'); plt.close(fig)
