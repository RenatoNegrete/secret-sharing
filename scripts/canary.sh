#!/usr/bin/env bash
# Mirror of the hidden suite's "no plaintext at rest" + "log hygiene" checks:
# create Secrets carrying a random canary and passphrase, exercise every path,
# then dump Redis and the app filesystem via docker exec and grep them and
# the container logs for anything sensitive. Exits non-zero on any hit.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE="${BASE_URL:-http://localhost:8080}"
CANARY="CANARY-$(openssl rand -hex 12)"
PASS="PASS-$(openssl rand -hex 12)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

post() { curl -sf -X POST "$BASE/secrets" -H 'Content-Type: application/json' -d "$1"; }
field() { sed -E "s/.*\"$1\":\"([^\"]+)\".*/\1/"; }

needles=("$CANARY" "$PASS")

# 1. plain Secret, left unread (stays in Redis)
r=$(post "{\"content\":\"$CANARY-a\",\"ttl_seconds\":300,\"max_views\":3}")
needles+=("$(echo "$r" | field id)" "$(echo "$r" | field deletion_token)")
# 2. passphrase Secret: one wrong guess (via query), one right read, still alive
r=$(post "{\"content\":\"$CANARY-b\",\"ttl_seconds\":300,\"max_views\":2,\"passphrase\":\"$PASS\"}")
id=$(echo "$r" | field id); needles+=("$id" "$(echo "$r" | field deletion_token)")
curl -s -o /dev/null "$BASE/s/$id?passphrase=wrong-$PASS"
curl -s -o /dev/null -H "X-Passphrase: $PASS" "$BASE/s/$id"
# 3. consumed Secret
r=$(post "{\"content\":\"$CANARY-c\",\"ttl_seconds\":300,\"max_views\":1}")
id=$(echo "$r" | field id); needles+=("$id")
curl -s -o /dev/null "$BASE/s/$id"
# 4. revoked Secret (deletion token via query, the riskiest channel)
r=$(post "{\"content\":\"$CANARY-d\",\"ttl_seconds\":300}")
id=$(echo "$r" | field id); dt=$(echo "$r" | field deletion_token); needles+=("$id" "$dt")
curl -s -o /dev/null -X DELETE "$BASE/s/$id?deletion_token=$dt"
# 5. passphrase in a GET body
r=$(post "{\"content\":\"$CANARY-e\",\"ttl_seconds\":300,\"passphrase\":\"$PASS\"}")
id=$(echo "$r" | field id); needles+=("$id")
curl -s -o /dev/null -X GET -H 'Content-Type: application/json' -d "{\"passphrase\":\"$PASS\"}" "$BASE/s/$id"

curl -s "$BASE/metrics" > "$WORK/metrics.txt"

# Redis: every key, every field, raw; plus a full RDB dump
docker compose exec -T redis sh -c \
  'redis-cli --scan | while read -r k; do echo "$k"; redis-cli --no-raw HGETALL "$k"; done' > "$WORK/redis-hashes.txt"
docker compose exec -T redis sh -c 'redis-cli --rdb /data/harness.rdb >/dev/null && cat /data/harness.rdb && rm -f /data/harness.rdb' > "$WORK/redis.rdb"
# App container filesystem (as the harness would, via its shell)
docker compose exec -T app sh -c \
  "grep -rIl -e '$CANARY' -e '$PASS' / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null || true" > "$WORK/app-fs.txt"
docker compose logs --no-color > "$WORK/logs.txt" 2>&1

fail=0
for n in "${needles[@]}"; do
  for f in redis-hashes.txt redis.rdb logs.txt metrics.txt; do
    if grep -qaF -- "$n" "$WORK/$f"; then echo "LEAK: ${n:0:12}… found in $f"; fail=1; fi
  done
done
# Lookup IDs: the first 22 base64 chars of each Share Token must not appear either
for n in "${needles[@]}"; do
  [ ${#n} -eq 64 ] || continue
  if grep -qaF -- "${n:0:22}" "$WORK/redis-hashes.txt" "$WORK/logs.txt" "$WORK/metrics.txt"; then
    echo "LEAK: Lookup ID prefix of ${n:0:12}…"; fail=1
  fi
done
if [ -s "$WORK/app-fs.txt" ]; then echo "LEAK: app filesystem:"; cat "$WORK/app-fs.txt"; fail=1; fi

keys=$(grep -c '^s:' "$WORK/redis-hashes.txt" || true)
echo "checked ${#needles[@]} needles across $keys live Redis keys, RDB ($(wc -c < "$WORK/redis.rdb") bytes), app fs, logs, metrics"
if [ "$fail" -eq 0 ]; then echo "PASS: nothing sensitive at rest or in logs"; else echo "FAIL"; exit 1; fi
