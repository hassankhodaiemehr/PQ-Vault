#!/usr/bin/env bash
# Reproduce the L1 gas table of the paper (Table "Measured L1 gas of PQVault").
#
# Clones the ZKNOX ETHDILITHIUM verifiers at the commits we measured with, copies PQVault and its
# tests into them, generates a real ML-DSA-44 certificate (1,024 attestors, 2^16-leaf list) and runs
# the Foundry tests for the NIST and the packed verifier.
#
# Requirements: git, python3 (with venv), Foundry (forge 1.5.1; https://book.getfoundry.sh) and
# network access to GitHub and PyPI. solc 0.8.30 is fetched by forge; to use a local binary instead,
# set SOLC=/path/to/solc-0.8.30 (and FORGE_FLAGS=--offline if binaries.soliditylang.org is blocked).
#
# Output: results/vault_nist_local.txt and results/vault_packed_local.txt. The GAS/OPENALL lines must
# match results/vault_nist_v3.txt and results/vault_packed_v3.txt (checked at the end).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="${WORK:-$HERE/_build}"
NIST_COMMIT=f9f4fe1d84e68304b425e054c273c276fe44ba11     # ETHDILITHIUM main, 2026-09-16
PACKED_COMMIT=f85ca80c446c2d59fcd68b5efe565275599bb1f9   # ETHDILITHIUM exp/packed-verifier, 2026-09-09
REPO=https://github.com/ZKNoxHQ/ETHDILITHIUM.git
USE=(); [ -n "${SOLC:-}" ] && USE=(--use "$SOLC")
read -r -a EXTRA <<< "${FORGE_FLAGS:-}"

mkdir -p "$WORK" "$HERE/results"

prepare() {  # $1 = dir, $2 = branch, $3 = commit, $4 = test file, $5 = fs_permissions line
  local d="$WORK/$1"
  if [ ! -d "$d" ]; then git clone -q -b "$2" "$REPO" "$d"; fi
  git -C "$d" checkout -q "$3"
  git -C "$d" submodule update --init --recursive -q
  cp "$HERE/src/PQVault.sol" "$d/src/"
  cp "$HERE/test/$4" "$d/test/"
  mkdir -p "$d/vault"
  cp "$HERE/gen_vectors.py" "$d/vault/"
  grep -q '^fs_permissions' "$d/foundry.toml" || sed -i "/^ffi = true/a $5" "$d/foundry.toml"
}

prepare nist main "$NIST_COMMIT" PQVault_nist.t.sol \
  'fs_permissions = [{ access = "read", path = "./vault" }]'
prepare packed exp/packed-verifier "$PACKED_COMMIT" PQVault_packed.t.sol \
  'fs_permissions = [{ access = "read", path = "./vault" }, { access = "read", path = "./test" }]'

# ZKNOX python signer, used by gen_vectors.py
PY="$WORK/nist/pythonref/myenv/bin/python"
if [ ! -x "$PY" ]; then
  python3 -m venv "$WORK/nist/pythonref/myenv"
  "$WORK/nist/pythonref/myenv/bin/pip" install -q -r "$WORK/nist/pythonref/requirements.txt" eth_abi pycryptodome
fi
if [ ! -f "$WORK/nist/vault/vectors.bin" ]; then
  (cd "$WORK/nist" && "$PY" vault/gen_vectors.py 1024)       # about 45 s
fi
cmp -s <(python3 -m json.tool "$WORK/nist/vault/vectors_meta.json") <(python3 -m json.tool "$HERE/vectors_meta.json") \
  && echo "vectors match vectors_meta.json" || echo "WARNING: generated vectors differ from vectors_meta.json"
cp "$WORK/nist/vault/vectors.bin" "$WORK/nist/vault/vectors_meta.json" "$WORK/packed/vault/"

run() {  # $1 = dir, $2 = test file, $3 = output
  (cd "$WORK/$1" && forge test "${USE[@]}" "${EXTRA[@]}" --match-path "test/$2" -vv --gas-limit 300000000000) | tee "$HERE/results/$3"
}
run nist PQVault_nist.t.sol vault_nist_local.txt
run packed PQVault_packed.t.sol vault_packed_local.txt

strip() { grep -E 'GAS|OPENALL|\[PASS\]|\[FAIL' "$1" | sed 's/ (gas: [0-9]*)//'; }
for v in nist packed; do
  if diff <(strip "$HERE/results/vault_${v}_local.txt") <(strip "$HERE/results/vault_${v}_v3.txt") >/dev/null; then
    echo "$v: gas identical to results/vault_${v}_v3.txt"
  else
    echo "$v: gas differs from results/vault_${v}_v3.txt"; exit 1
  fi
done
