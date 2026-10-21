for n in 128 512 1024 2048; do timeout 1500 python3 netexp.py $n 5 >> net_results.jsonl 2>> net.err; done; echo DONE > net_done
