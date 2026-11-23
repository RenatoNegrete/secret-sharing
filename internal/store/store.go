// Package store keeps sealed Secrets in Redis (ADR 0002).
//
// Each Secret is one hash under "s:" + hex(SHA-256(LookupID)) — raw Lookup IDs
// never appear in storage — with fields:
//
//	c  ciphertext     n  nonce       s  salt
//	p  "1" if a Passphrase is required
//	v  Views left     f  Failed Unlocks so far
//	r  Failed Unlock slots reserved by unlock attempts still in flight
//	d  SHA-256(Deletion Token)
//
// Expiry is native (PEXPIRE). Every state change after creation is a single
// atomic Lua call scoped to one key: no global lock.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"secret-sharing/internal/seal"
)

// MaxFailedUnlocks is the Failed Unlock that destroys a Secret.
const MaxFailedUnlocks = 5

// ErrFull means Redis hit maxmemory (noeviction) and refused the write.
var ErrFull = errors.New("store: full")

// Every script declares allow-oom: the counters below must keep moving when
// Redis is at maxmemory. Without the flag a full store rejects HINCRBY/HSET,
// so Failed Unlocks would go uncounted and multi-View reads would fail.

// peekScript fetches a Secret and, when ARGV[1] is "1" and the Secret needs a
// Passphrase, reserves one of its Failed Unlock slots before any key
// derivation happens. A slot is free while failed + reserved < ARGV[2].
// Returns false if the Secret is Gone.
var peekScript = redis.NewScript(`#!lua flags=allow-oom
local h = redis.call('HMGET', KEYS[1], 'c', 'n', 's', 'p', 'f', 'r')
if not h[1] then return false end
local reserved = 0
if ARGV[1] == '1' and h[4] == '1'
   and (tonumber(h[5]) or 0) + (tonumber(h[6]) or 0) < tonumber(ARGV[2]) then
  redis.call('HINCRBY', KEYS[1], 'r', 1)
  reserved = 1
end
return {h[1], h[2], h[3], h[4], reserved}
`)

// consumeScript spends one View and, when ARGV[1] is "1", hands back the
// caller's reserved slot. Returns -1 if the Secret is Gone, otherwise the
// Views left after this one (0 means it was the last and the key is deleted).
var consumeScript = redis.NewScript(`#!lua flags=allow-oom
local v = redis.call('HGET', KEYS[1], 'v')
if not v then return -1 end
v = tonumber(v) - 1
if v <= 0 then
  redis.call('DEL', KEYS[1])
  return 0
end
redis.call('HSET', KEYS[1], 'v', v)
if ARGV[1] == '1' then redis.call('HINCRBY', KEYS[1], 'r', -1) end
return v
`)

// failScript turns the caller's reserved slot into a Failed Unlock. Returns -1
// if the Secret is Gone, otherwise the Failed Unlock count; at ARGV[1] the key
// is deleted.
var failScript = redis.NewScript(`#!lua flags=allow-oom
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
redis.call('HINCRBY', KEYS[1], 'r', -1)
local f = redis.call('HINCRBY', KEYS[1], 'f', 1)
if f >= tonumber(ARGV[1]) then redis.call('DEL', KEYS[1]) end
return f
`)

// noopScript is one round trip of the same shape as the scripts above, used
// to keep the number of Redis round trips equal on every read/revoke path.
var noopScript = redis.NewScript(`#!lua flags=allow-oom
return 0
`)

// Record is a stored Secret as returned by Peek.
type Record struct {
	Sealed        seal.Sealed
	HasPassphrase bool
	// Reserved is true when Peek reserved a Failed Unlock slot for this
	// attempt. The caller must settle it with Consume or FailUnlock.
	Reserved bool
}

// New is everything needed to store a fresh Secret.
type New struct {
	Sealed        seal.Sealed
	HasPassphrase bool
	MaxViews      int
	DeletionHash  []byte
	TTL           time.Duration
}

// Store is the Redis-backed Secret store.
type Store struct{ rdb *redis.Client }

// Open wraps a Redis client.
func Open(rdb *redis.Client) *Store { return &Store{rdb: rdb} }

func key(lookupID []byte) string {
	sum := sha256.Sum256(lookupID)
	return "s:" + hex.EncodeToString(sum[:])
}

// Create stores a Secret and its expiry atomically.
func (s *Store) Create(ctx context.Context, lookupID []byte, n New) error {
	k := key(lookupID)
	p := "0"
	if n.HasPassphrase {
		p = "1"
	}
	_, err := s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HSet(ctx, k, map[string]any{
			"c": n.Sealed.Ciphertext,
			"n": n.Sealed.Nonce,
			"s": n.Sealed.Salt,
			"p": p,
			"v": n.MaxViews,
			"f": 0,
			"d": n.DeletionHash,
		})
		pipe.PExpire(ctx, k, n.TTL)
		return nil
	})
	return classify(err)
}

// Peek fetches a Secret. found is false if it is Gone. With attempt set, a
// Secret that needs a Passphrase has one Failed Unlock slot reserved in the
// same atomic step (Record.Reserved); if every slot is already failed or in
// flight, Reserved stays false and the caller must not try the Passphrase.
func (s *Store) Peek(ctx context.Context, lookupID []byte, attempt bool) (rec Record, found bool, err error) {
	vals, err := peekScript.Run(ctx, s.rdb, []string{key(lookupID)}, flag(attempt), MaxFailedUnlocks).Slice()
	if errors.Is(err, redis.Nil) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, classify(err)
	}
	if len(vals) != 5 {
		return Record{}, false, nil
	}
	c, ok1 := vals[0].(string)
	n, ok2 := vals[1].(string)
	salt, ok3 := vals[2].(string)
	p, ok4 := vals[3].(string)
	reserved, ok5 := vals[4].(int64)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return Record{}, false, nil
	}
	return Record{
		Sealed:        seal.Sealed{Ciphertext: []byte(c), Nonce: []byte(n), Salt: []byte(salt)},
		HasPassphrase: p == "1",
		Reserved:      reserved == 1,
	}, true, nil
}

// Consume spends one View. reserved says whether Peek reserved a slot for this
// read, which is handed back. granted is false if the Secret became Gone first.
func (s *Store) Consume(ctx context.Context, lookupID []byte, reserved bool) (viewsLeft int, granted bool, err error) {
	n, err := consumeScript.Run(ctx, s.rdb, []string{key(lookupID)}, flag(reserved)).Int()
	if err != nil {
		return 0, false, classify(err)
	}
	if n < 0 {
		return 0, false, nil
	}
	return n, true, nil
}

// FailUnlock turns a slot reserved by Peek into a Failed Unlock. found is
// false if the Secret became Gone first; destroyed is true when this one
// reached the limit.
func (s *Store) FailUnlock(ctx context.Context, lookupID []byte) (failed int, destroyed, found bool, err error) {
	n, err := failScript.Run(ctx, s.rdb, []string{key(lookupID)}, MaxFailedUnlocks).Int()
	if err != nil {
		return 0, false, false, classify(err)
	}
	if n < 0 {
		return 0, false, false, nil
	}
	return n, n >= MaxFailedUnlocks, true, nil
}

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Noop performs one Lua round trip that changes nothing.
func (s *Store) Noop(ctx context.Context) error {
	return classify(noopScript.Run(ctx, s.rdb, []string{"noop"}).Err())
}

// DeletionHash returns the stored SHA-256 of the Secret's Deletion Token.
func (s *Store) DeletionHash(ctx context.Context, lookupID []byte) (hash []byte, found bool, err error) {
	v, err := s.rdb.HGet(ctx, key(lookupID), "d").Result()
	if errors.Is(err, redis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, classify(err)
	}
	return []byte(v), true, nil
}

// Delete removes a Secret immediately.
func (s *Store) Delete(ctx context.Context, lookupID []byte) error {
	return classify(s.rdb.Del(ctx, key(lookupID)).Err())
}

// Ping checks Redis liveness.
func (s *Store) Ping(ctx context.Context) error {
	return classify(s.rdb.Ping(ctx).Err())
}

func classify(err error) error {
	if err == nil || errors.Is(err, redis.Nil) {
		return nil
	}
	// Queued inside MULTI, an OOM rejection can surface as EXECABORT carrying the OOM text.
	if strings.Contains(err.Error(), "OOM") {
		return ErrFull
	}
	return fmt.Errorf("store: %w", err)
}
