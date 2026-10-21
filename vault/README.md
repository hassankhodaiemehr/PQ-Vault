# PQVault Solidity prototype (gas measurements, Table 8 of the paper)

Research prototype, not audited. Built on top of ZKNOX ETHDILITHIUM (https://github.com/ZKNoxHQ/ETHDILITHIUM).

## Reproducing the measurements

Automated: `./setup_and_test.sh` performs the steps below at the measured ZKNOX commits and checks that the gas lines equal `results/vault_*_v3.txt`.

Manual steps:

1. Clone ETHDILITHIUM (main branch for the NIST verifier; branch `exp/packed-verifier` for the packed verifier), then `git submodule update --init`.
2. Copy `src/PQVault.sol` into its `src/`, and `test/PQVault_nist.t.sol` (main) or `test/PQVault_packed.t.sol` (packed) into its `test/`. Copy `gen_vectors.py` into a new `vault/` folder.
3. Add `fs_permissions = [{ access = "read", path = "./vault" }]` to `foundry.toml`. The packed branch also needs read access to `./test`.
4. Set up the ZKNOX python signer: `cd pythonref && python3 -m venv myenv && myenv/bin/pip install -r requirements.txt` (plus `eth_abi pycryptodome` if missing).
5. Generate a real certificate: `pythonref/myenv/bin/python vault/gen_vectors.py 1024` (1024 attestors, 2^16-leaf tree, about 45 s).
   The withdrawal leaves bind the vault address and chain id; the tests deploy PQVault at the fixed address
   `0x00000000000000000000000000000000000Fa017` (`deployCodeTo`) on chain id 31337, matching `gen_vectors.py`.
6. Run `forge test --match-path test/PQVault*.t.sol -vv --gas-limit 300000000000` (solc 0.8.30). The lines starting with `GAS` give exec gas, calldata bytes, and the transaction total under EIP-7623; the `OPENALL` lines give the totals for posting all k records under a 128 KB per-transaction calldata limit.

The `results/` folder contains the raw outputs used in the paper (`vault_*_v3.txt` for the current contract; `previous/` holds earlier versions: `v2` = dispute state machine without header binding, unversioned = first prototype).

## Contract API

Constructor: `PQVault(mldsa, rAtt, W, N)`; `Wp = W/3` (floor) and `depth = ceil(log2 N)` are derived. `W, Wp, N, depth, rAtt` are storage and are replaced at every finalization by the header's `Wnext, Nnext, rAttNext`; each proposal snapshots them at propose time and uses the snapshot throughout.

The signed message is recomputed on chain (`checkpointMsg`):
`M = keccak256(abi.encode("PQV-CP", chainid, vault, e, lastM, hBlock, stateRoot, omega, rAttNext, bindRoot, Wnext, Nnext))`,
where `lastM` is the M of the latest finalized checkpoint (0 at deployment). Coins and ML-DSA checks use this M.

Bonds and rewards are pull payments: they are credited to `owed[addr]` and withdrawn with `claim()`.

Proposals carry ids; several proposals for the same epoch may be pending, and a rejected epoch can be re-proposed.

| function | who | effect |
|---|---|---|
| `propose(Header h, rSig, Ws, k, cCert)` + `BOND_R`, `Header = (e, hBlock, stateRoot, omega, rAttNext, bindRoot, Wnext, Nnext)` | relayer | requires `e == lastFinal + 1`, `Wp*1.1 <= Ws <= W`, `k == ceil(260 / log2fp(Ws/Wp))` exactly, `k <= KMAX`, `Wnext >= 3`, `1 <= Nnext <= 2^32`; computes M; snapshots `rAtt, W, Wp, N, depth`; returns `id` |
| `challenge(id, j)` + `BOND_C` | anyone | `j < k`, once per index, before `challengeDeadline(id)`; response deadline `now + D_RESP` |
| `respond(id, record, pkAddr)` | anyone | (1) record not in `cCert` (leaf binds all fields incl. both paths; cert path length `ceil(log2 k)`) → revert; (2) committed record fails Local (interval, coin, `pos < N`, sig length, path lengths, `R_sig`/`R_att` paths) → reject; (3) `pkAddr.codehash != pkHash` → revert; (4) ML-DSA fails → reject, else the challenge is closed and `BOND_C` is credited to the relayer |
| `timeout(id, j)` | anyone | challenge open past its deadline → reject, `BOND_R + BOND_C` credited to the challenger |
| `challengeAll(id)` | anyone, no bond, once | all k records must be posted within `D_OPEN = 1 day` |
| `postRecords(id, records[])` | anyone | posts committed records as calldata (membership in `cCert` only); when all k are posted the challenge window becomes `max(proposedAt + T_CH, postedAt + D_POST)`, `D_POST = 2 days` |
| `timeoutAll(id)` | anyone | records not all posted by the open-all deadline → reject, `BOND_R` to the `challengeAll` caller |
| `finalize(id)` | anyone | after `challengeDeadline(id)`, no open challenge, no pending open-all: status 2, `lastFinal = e`, `lastM = M`, `rAtt = rAttNext`, `W = Wnext`, `Wp = Wnext/3`, `N = Nnext`, `depth = ceil(log2 Nnext)` (or status 4, stale, if another proposal for `e` was finalized first); `BOND_R` credited to the relayer |
| `claim()` | anyone | pays `owed[msg.sender]` (zeroed before the call) |
| `withdraw(id, recipient, amount, nonce, index, path)` | anyone | leaf `keccak256(0x00 ‖ vault ‖ chainid ‖ recipient ‖ amount ‖ nonce)`, index-aware path of depth `WDEPTH = 20` to `omega` of a finalized proposal; each leaf pays once |
| `refundChallenge(id, j)` | anyone | returns `BOND_C` of a challenge still open when the proposal was rejected by another path |
| `verifyDirect(id, records[], pkAddrs[])` | view | non-optimistic check of all k records (ordered by j), for comparison |

`status(id)`: 1 pending, 2 finalized, 3 rejected, 4 stale (bond refunded).
