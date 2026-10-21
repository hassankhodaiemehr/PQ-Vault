# PQ-Vault: artifact

Code, raw results and plotting scripts for the paper

> H. Khodaiemehr, K. Bagheri and C. Feng, **"PQ-Vault: Provably Quantum-Safe Asset Custody for Unmodified Ethereum"**, submitted to *IEEE Transactions on Dependable and Secure Computing*, 2026.

PQ-Vault escrows Ethereum assets in a vault contract whose release path uses only hash-based and ML-DSA (FIPS 204) checks. A quantum-safe proof-of-stake sidechain (QPoS-S) certifies checkpoints with compact certificates. The vault accepts a checkpoint optimistically, and a fraud proof opens a single reveal.

This is a research prototype. It has not been audited and must not hold real funds.

## Contents

| Folder | What it is | Paper |
|---|---|---|
| `pqcert/` | Rust crate: compact certificates (Alg. 1) with the QROM reveal rule. It uses domain-separated Keccak-256 Merkle trees with compact multiproofs and 128-bit coin reduction. Backends: round-3 Dilithium2/3/5 (`crystals-dilithium` 1.0.0), FIPS 204 ML-DSA-44 (`ml-dsa` =0.1.1) and Falcon-512. Includes the benchmark and signature micro-benchmark binaries. | Secs. 6, 9.1–9.2; Tables 5–7; Fig. 2 |
| `hsbench/` | Benchmark of the synchronized hash-based signatures of Drake et al. (generalized XMSS, target sum) | Table 7 |
| `net/` | Python certificate implementation over SHA3-256 (`pycert.py`), the multi-process network experiment and the light-client benchmark | Secs. 9.1, 9.4 |
| `vault/` | Solidity vault and dispute state machine (`PQVault.sol`), Foundry tests and the test-vector generator | Secs. 5, 8, 9.5; Table 8 |
| `sim/` | Model-level Monte Carlo simulations of leader election: fairness, Sybil splitting, steering, epoch seeds, reveal order and fallback proposers | Secs. 7, 9.6; Fig. 3(c) |
| `analysis/` | Grinding validation, L1 gas model, and the plotting script for all figures | Sec. 9.3; Figs. 2, 3 |
| `paper/` | LaTeX sources and PDF of the preprint (paper with appendices) | — |

Raw results used in the paper are stored next to the code that produced them (`*/results/`, `*.jsonl`, `*.json`).

Labels in older result files: the certificate benchmarks `pqcert/results/bench_cloud.jsonl`, `h384.jsonl`, `sigbench.jsonl` and the `D2` rows of `fips204_crosscheck.jsonl` were run with **round-3 Dilithium**, although those files label the schemes `ML-DSA-44/65/87`. The current code labels them `Dilithium2-r3`, `Dilithium3-r3` and `Dilithium5-r3`. Only rows labelled `ML-DSA-44 (FIPS 204)` use FIPS 204. Every Python experiment (`net/`) and the Solidity vault use FIPS 204 ML-DSA-44.

## Requirements

- **Rust:** stable (tested with 1.97); `cargo` fetches all crates.
- **Python:** 3.10 or newer, plus `pip install -r requirements.txt`.
- **Foundry:** forge 1.5.1 and solc 0.8.30, for `vault/` only.
- **git and network access:** to GitHub (ZKNOX verifiers, hash-sig reference implementation) and PyPI.

Timings in the paper are single-threaded medians on these machines:

| Machine | Hardware |
|---|---|
| M1 | Cloud VM, 2 vCPUs, Xeon 2.8 GHz, 8 GB |
| M2 | Laptop VM, 2 vCPUs, i9-13900HX, 3 GB |
| M3 | 2 vCPUs, Xeon 2.1 GHz |

Sizes, reveal counts and gas are machine-independent.

## Reproducing the results

### Certificates (`pqcert/`)

```bash
cd pqcert
cargo test --release                 # unit tests: |P| <= k_rev, unused reveals, FIPS 204 round trip
cargo build --release
./run_bench.sh                       # sizes and times, Fig. 2, Tables 5 and 7 -> results/bench_cloud.jsonl
./run_fips204_crosscheck.sh          # round-3 Dilithium2 vs FIPS 204 ML-DSA-44 -> results/fips204_crosscheck.jsonl
./run_h384.sh                        # Keccak-384 vs Keccak-256, Table 6 -> results/h384.jsonl
./target/release/sigbench            # per-signature costs -> results/sigbench.jsonl
```

To run a single configuration, use `./target/release/bench <D2|D3|D5|F512|M44> <N> <signed fraction> <uniform|lognormal|zipf> <proven fraction or 1/3> <classical|qrom> <reps>`.

Every run prints negative tests (tampered signature, shifted interval, dropped reveal, signed weight above `W`, extra unused reveal). All must be `true`.

The reported sizes come from runs with `proven = floor(0.3333 W)`. `run_bench.sh` now passes `1/3` (`floor(W/3)`). This yields the same `k_rev` in all 40 configurations but different coins, so a rerun gives slightly different reveal sets: for example, 81 instead of 94 distinct reveals at N = 2^8. The checks `|P| <= k_rev` and "no unused reveal" were added after the size runs, so `bench_cloud.jsonl` has no `neg_extra_unused_reveal` field.

### Hash-based baseline (`hsbench/`)

```bash
cd hsbench && ./run.sh               # clones b-wagn/hash-sig next to this folder, pinned commit
```

### Network experiment and light clients (`net/`)

```bash
cd net
./run_net.sh                         # N = 128...2048, 5 rounds each -> net_results.jsonl (Sec. 9.4)
python3 verify_bench.py cloud        # light-client verification -> vb_*.jsonl
```

### L1 vault and gas (`vault/`)

```bash
cd vault && ./setup_and_test.sh
```

The script:

1. clones ZKNOX ETHDILITHIUM at the measured commits (NIST verifier `f9f4fe1`, packed verifier `f85ca80`);
2. generates a real ML-DSA-44 certificate over a 2^16-position attestor list (`gen_vectors.py`, about 45 s);
3. runs the 17 Foundry tests per verifier;
4. checks that every gas line equals `results/vault_*_v3.txt`.

If `binaries.soliditylang.org` is blocked, set `SOLC=/path/to/solc-0.8.30 FORGE_FLAGS=--offline`. `vault/README.md` documents the contract API and the manual steps. `results/previous/` holds the outputs of earlier contract versions.

### Leader election (`sim/`)

```bash
python3 sim/qpos_sim.py              # fairness, Sybil splitting, steering, epoch-seed bias -> sim/qpos_results.json
python3 sim/reveal_order_sim.py      # Prop. 13 and Thm. 11: reveal order, steered epochs, fallback -> sim/reveal_order_results.json
```

Both simulations use fixed seeds. `reveal_order_sim.py` reproduces its JSON exactly.

### Analysis and figures (`analysis/`)

```bash
python3 analysis/grind.py            # empirical grinding cost vs p^-k -> analysis/grind.json
python3 analysis/gas_model.py        # L1 gas model -> analysis/gas.json
python3 analysis/figs.py             # all figures -> paper/figs/ (or $FIG_OUT)
```

`figs.py` reads only the stored results, so it regenerates the paper's figures without rerunning any experiment.

### Paper

```bash
cd paper && pdflatex PQ-Vault && bibtex PQ-Vault && pdflatex PQ-Vault && pdflatex PQ-Vault
```

`paper/` holds the preprint (main paper with the supplementary material as appendices S1–S7). `analysis/figs.py` writes its figures to `paper/figs/`.

## Verified for this release (October 2026)

| Component | Check | Result |
|---|---|---|
| `pqcert` | `cargo test --release` | 2/2 pass |
| `pqcert` | Spot runs of `bench` with D2 and M44 | All negative tests true |
| `vault` | `setup_and_test.sh` | 17/17 tests per verifier; gas identical to `results/vault_*_v3.txt` |
| `net` | `netexp.py 64 1` | All light clients accept |
| `net` | `verify_bench.run(n=128)` | Accepts, with the verifier-state checks (`W`, `N`) enabled |
| `hsbench` | Build | Builds against hash-sig `e66a485` |
| `sim`, `analysis` | `reveal_order_sim.py`, `gas_model.py`, `figs.py` | Reproduce the stored JSON and figures |

## License

MIT, see [LICENSE](LICENSE).

Third-party code is fetched, not vendored. The ZKNOX ETHDILITHIUM verifiers and the hash-sig reference implementation keep their own licenses. `paper/IEEEtran.cls` and `paper/IEEEtran.bst` are distributed under the LPPL.

## Citation

See [CITATION.cff](CITATION.cff).
