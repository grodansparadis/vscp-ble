#!/bin/sh
# Build and run the libFuzzer target (needs clang).
#   tests/fuzz/run.sh [seconds]       default 60 s
set -e
cd "$(dirname "$0")/../.."
out=build-fuzz
mkdir -p $out/corpus
python3 -B tests/fuzz/seeds.py $out/corpus
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -Isrc \
  tests/fuzz/fuzz-receive.c src/vscp-ble-common.c src/vscp-ble-counter.c src/vscp-ble-e1.c \
  src/vscp-ble-l0.c src/vscp-ble-a2.c src/vscp-ble-f1.c src/vscp-ble-g1.c src/vscp-ble-crypto-reference.c \
  -o $out/fuzz-receive
$out/fuzz-receive -max_total_time="${1:-60}" -max_len=4096 -print_final_stats=1 $out/corpus
