#!/bin/bash
# Keccak-384 vs Keccak-256 commitments (paper, table "Keccak-384 vs. Keccak-256 commitments").
# Each line of results/h384.jsonl is {"h":<bits>} followed by the bench output of that build.
set -e
cargo build --release --bin bench && cp target/release/bench target/release/bench256
cargo build --release --features h384 --bin bench && cp target/release/bench target/release/bench384
OUT=results/h384.jsonl; : > $OUT
for n in 4096 16384 65536; do
  for h in 256 384; do printf '{"h":%s}' $h >> $OUT; ./target/release/bench$h D2 $n 0.85 lognormal 0.3333 qrom 5 >> $OUT; done
done
for h in 256 384; do printf '{"h":%s}' $h >> $OUT; ./target/release/bench$h F512 65536 0.85 lognormal 0.3333 qrom 5 >> $OUT; done
