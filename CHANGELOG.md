# Changelog

## 1.0.0 (October 2026): artifact of the TDSC submission

### Certificates (`pqcert`, `net/pycert.py`)

- The verifier follows Alg. 1 of the paper exactly:
  - QROM reveal rule `k_rev = ceil((lambda + 2 log2 q + 4) / log2(Ws/Wp))`;
  - `(1+delta) Wp <= Ws <= W`, with `W` and `N` taken from the verifier's state;
  - `1 <= |P| <= k_rev` and positions in `[N]`;
  - every coin is covered and every reveal covers a coin;
  - positive weights, intervals inside `[0, Ws)`;
  - ML-DSA checks and both multiproofs.
- Three omissions of the earlier prototype (our 2025 post-quantum sidechain prototype) are fixed. Each one alone made certificates forgeable:
  - coin coverage was not checked;
  - intervals were accumulated over all attestors and not checked;
  - a heuristic `k_rev` was used.
- New backend: FIPS 204 ML-DSA-44 (`ml-dsa` =0.1.1), next to the round-3 Dilithium backend of the prototype. Round-3 schemes are now labelled `Dilithium{2,3,5}-r3`.
- `bench` accepts the proven fraction `1/3` (integer `floor(W/3)`) and adds the negative test `neg_extra_unused_reveal`.
- `run_h384.sh` reproduces the Keccak-384 comparison.
- `net/`: the light clients pass the verifier state (`W`, `N`) to `pycert.verify`.

### Vault (`vault/PQVault.sol`)

- Dispute state machine:
  - strict challenge deadline, inclusive response and posting deadlines;
  - finalization waits for every open dispute;
  - bond-free open-all, once per proposal;
  - stale proposals;
  - re-proposal after a rejection.
- The vault recomputes the signed checkpoint message `M_e` from the header. This binds the chain id, the vault address, the epoch, the parent, `omega_e`, the next attestor root, `W` and `N`.
- Withdrawals are leaves of `omega_e` with a global nullifier. Bonds and rewards are pull payments.
- 17 Foundry tests per verifier. `setup_and_test.sh` reproduces all gas numbers exactly (forge 1.5.1, solc 0.8.30, ZKNOX `f9f4fe1` and `f85ca80`).

### Leader election (`sim/`)

- `reveal_order_sim.py` (new) checks, at model level:
  - the random reveal order (`P[c >= x] <= alpha^x` under Sybil splitting);
  - consecutive steered epochs (`E[2^c] <= mu`) and target-slot capture;
  - the probability that a slot is not guaranteed under denial of service.

### Reproducibility

- All scripts use paths relative to the repository; the absolute paths of the development machine are gone.
- `analysis/figs.py` regenerates the figures from the stored results.
