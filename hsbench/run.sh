#!/bin/bash
# Hash-based (generalized XMSS, target-sum) signature baseline of Drake et al. (paper, table of signature baselines).
# Cargo.toml expects the reference implementation next to this folder: ../hash-sig
set -e
HS_COMMIT=e66a48565d73c4d83d54e1b28fe249ab8c0d8542   # b-wagn/hash-sig, 2025-12-18 (builds with this crate)
[ -d ../hash-sig ] || git clone https://github.com/b-wagn/hash-sig.git ../hash-sig
git -C ../hash-sig checkout -q $HS_COMMIT
cargo build --release
OUT=results_hs.jsonl; : > $OUT
for s in l18 l32h l32t l32s; do ./target/release/hsbench $s >> $OUT; done   # L2^32 key generation takes about 1 min each
