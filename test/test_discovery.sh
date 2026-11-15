#!/bin/sh
# Test the UDP based auto discovery, the ring topology and the failover.
set -e
export PATH=/mingw64/bin:/usr/bin:$PATH
cd /d/icss
BIN=./icss.exe
WORK=/tmp/icss-disc-test
rm -rf "$WORK"
mkdir -p "$WORK"

echo "--- starting three nodes with UDP auto discovery ---"
$BIN node --listen 21001 --broadcast-port 21777 --chunk-size 256 \
    --queue-depth 32 --index-path "$WORK/a.idx" > "$WORK/a.out" 2> "$WORK/a.err" &
A=$!
$BIN node --listen 21002 --broadcast-port 21777 --chunk-size 256 \
    --queue-depth 32 --index-path "$WORK/b.idx" > "$WORK/b.out" 2> "$WORK/b.err" &
B=$!
$BIN node --listen 21003 --broadcast-port 21777 --chunk-size 256 \
    --queue-depth 32 --index-path "$WORK/c.idx" > "$WORK/c.out" 2> "$WORK/c.err" &
C=$!
sleep 12

echo "--- topology learned by each node ---"
for port in 21001 21002 21003; do
    echo "node $port:"
    $BIN status 127.0.0.1:$port | tr ',' '\n' | grep -E "online_nodes|downstream|upstream"
done

echo "--- injecting into the discovered ring (erasure coded k=2 m=2) ---"
head -c 800 /dev/urandom > "$WORK/input.bin"
HASH=$($BIN hash "$WORK/input.bin")
$BIN inject "$WORK/input.bin" 127.0.0.1:21001 --chunk-size 256 \
    --data-shards 2 --parity-shards 2 2> "$WORK/inject.err"
grep -o '{"file_sha256.*}' "$WORK/inject.err" || true

echo "--- fetching through the ring ---"
$BIN fetch "$HASH" "$WORK/output.bin" 127.0.0.1:21001 2> "$WORK/fetch.err"
OUT=$($BIN hash "$WORK/output.bin")
if [ "$HASH" = "$OUT" ]; then
    echo "RING RESULT: MATCH"
else
    echo "RING RESULT: MISMATCH"
    exit 1
fi

echo "--- killing node 21003 to trigger the topology rebuild ---"
kill $C 2>/dev/null || true
wait $C 2>/dev/null || true
# The peer timeout is 30 seconds, so the ring only rebuilds after that.
echo "waiting for the peer timeout to expire..."
sleep 40

echo "--- topology after the failure ---"
for port in 21001 21002; do
    echo "node $port:"
    $BIN status 127.0.0.1:$port | tr ',' '\n' | grep -E "online_nodes|downstream|upstream"
done

echo "--- the ring must still forward after the rebuild ---"
$BIN fetch "$HASH" "$WORK/output2.bin" 127.0.0.1:21001 2> "$WORK/fetch2.err"
OUT2=$($BIN hash "$WORK/output2.bin")
if [ "$HASH" = "$OUT2" ]; then
    echo "FAILOVER RESULT: MATCH"
else
    echo "FAILOVER RESULT: MISMATCH"
    exit 1
fi

kill $A $B 2>/dev/null || true
wait $A $B 2>/dev/null || true
