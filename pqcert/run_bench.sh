#!/bin/bash
B=./target/release/bench
OUT=results/bench_cloud.jsonl; : > $OUT
for dist in uniform lognormal zipf; do for n in 256 1024 4096 16384 65536; do for model in classical qrom; do
  $B D2 $n 0.85 $dist 1/3 $model 5 >> $OUT; done; done; done
for s in D3 D5 F512; do for model in classical qrom; do $B $s 4096 0.85 lognormal 1/3 $model 5 >> $OUT; done; done
for n in 256 1024 16384 65536; do $B F512 $n 0.85 lognormal 1/3 qrom 5 >> $OUT; done
for pf in 0.5 0.6667; do for model in classical qrom; do $B D2 4096 0.85 lognormal $pf $model 5 >> $OUT; done; done
echo DONE > results/bench_done
