#!/bin/bash
# FIPS 204 ML-DSA-44 (M44, RustCrypto ml-dsa) vs round-3 Dilithium2 (D2, crystals-dilithium), same harness and machine.
set -e
B=./target/release/bench
mkdir -p results
OUT=results/fips204_crosscheck.jsonl; : > $OUT
{ echo "date: $(date -u +%FT%TZ)"; echo "uname: $(uname -srm)"; lscpu | grep -E "Model name|^CPU\(s\)|Thread|Core|Socket|MHz|L3"; echo "nproc: $(nproc)"; echo "rustc: $(rustc --version)"; } > results/fips204_crosscheck_machine.txt
for n in 256 1024 4096 16384 65536; do for s in D2 M44; do $B $s $n 0.85 lognormal 1/3 qrom 5 >> $OUT; done; done
for s in D2 M44; do $B $s 65536 0.85 lognormal 1/3 classical 5 >> $OUT; done
