#!/bin/sh
# End-to-end test of the erasure coded inject/fetch path on a two node ring.
set -e
export PATH=/mingw64/bin:/usr/bin:$PATH
cd /d/icss
BIN=./icss.exe
WORK=/tmp/icss-ec-test
rm -rf "$WORK"
mkdir -p "$WORK"

# Build a test payload that spans several shards.
head -c 2000 /dev/urandom > "$WORK/input.bin"
INPUT_HASH=$($BIN hash "$WORK/input.bin")
echo "input sha256: $INPUT_HASH"
echo "input bytes : $(wc -c < "$WORK/input.bin")"

# Two node ring, chunk size 256 bytes, 2 data shards + 2 parity shards.
$BIN node --listen 20001 --next 127.0.0.1:20002 --chunk-size 256 \
    --queue-depth 64 --index-path "$WORK/a.idx" > "$WORK/a.out" 2> "$WORK/a.err" &
NODE_A=$!
$BIN node --listen 20002 --next 127.0.0.1:20001 --chunk-size 256 \
    --queue-depth 64 --index-path "$WORK/b.idx" > "$WORK/b.out" 2> "$WORK/b.err" &
NODE_B=$!
sleep 2

echo "--- injecting with erasure coding (k=2, m=2) ---"
$BIN inject "$WORK/input.bin" 127.0.0.1:20001 --chunk-size 256 \
    --data-shards 2 --parity-shards 2 2> "$WORK/inject.err"
grep -o '{"file_sha256.*}' "$WORK/inject.err" || true

echo "--- fetching (plaintext) ---"
$BIN fetch "$INPUT_HASH" "$WORK/output.bin" 127.0.0.1:20001 2> "$WORK/fetch.err"
OUTPUT_HASH=$($BIN hash "$WORK/output.bin")
if [ "$INPUT_HASH" = "$OUTPUT_HASH" ]; then
    echo "PLAIN RESULT: MATCH"
else
    echo "PLAIN RESULT: MISMATCH"
    exit 1
fi

echo "--- injecting a second dataset with encryption + erasure coding ---"
head -c 1500 /dev/urandom > "$WORK/enc-input.bin"
ENC_HASH=$($BIN hash "$WORK/enc-input.bin")
openssl rand -out "$WORK/key.bin" 32
$BIN inject "$WORK/enc-input.bin" 127.0.0.1:20001 --chunk-size 256 \
    --data-shards 3 --parity-shards 3 --key "$WORK/key.bin" 2> "$WORK/inject-enc.err"
grep -o '{"file_sha256.*}' "$WORK/inject-enc.err" || true

echo "--- fetching the encrypted dataset ---"
$BIN fetch "$ENC_HASH" "$WORK/enc-output.bin" 127.0.0.1:20001 \
    --key "$WORK/key.bin" 2> "$WORK/fetch-enc.err"
ENC_OUTPUT_HASH=$($BIN hash "$WORK/enc-output.bin")
if [ "$ENC_HASH" = "$ENC_OUTPUT_HASH" ]; then
    echo "ENCRYPTED RESULT: MATCH"
else
    echo "ENCRYPTED RESULT: MISMATCH"
    exit 1
fi

echo "--- fetching the encrypted dataset with the wrong key must fail ---"
openssl rand -out "$WORK/wrong-key.bin" 32
if $BIN fetch "$ENC_HASH" "$WORK/bad.bin" 127.0.0.1:20001 \
    --key "$WORK/wrong-key.bin" > /dev/null 2> "$WORK/fetch-bad.err"; then
    echo "WRONG KEY RESULT: UNEXPECTED SUCCESS"
    exit 1
else
    echo "WRONG KEY RESULT: correctly rejected"
fi

echo "--- status of the ring ---"
$BIN status 127.0.0.1:20001 --list-files

kill $NODE_A $NODE_B 2>/dev/null || true
wait $NODE_A $NODE_B 2>/dev/null || true
