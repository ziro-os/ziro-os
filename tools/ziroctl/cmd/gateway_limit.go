package cmd

import (
	"context"
	"crypto/sha256"
	"math"
	"strings"
	"sync"
	"time"
)

// ---- rate limiting ----

const (
	limitShards   = 64
	limitShardCap = 16384 // client entries per shard: about 1M clients per route
)

// tokenBucket allows rate requests/second with a burst of max(rate, 10) per client. State is
// sharded by key so unrelated clients never contend, and it is bounded: full buckets are
// equivalent to absent ones and are swept, and a shard at its cap evicts one entry per insert.
type tokenBucket struct {
	rate, burst float64
	shards      [limitShards]limitShard
}

type limitShard struct {
	mu      sync.Mutex
	clients map[string]*bucketState
	_       [24]byte // keep neighbouring shards on separate cache lines
}

type bucketState struct {
	tokens float64
	last   time.Time
}

func newTokenBucket(rps int) *tokenBucket {
	return &tokenBucket{rate: float64(rps), burst: math.Max(float64(rps), 10)}
}

// fnv32 is FNV-1a over a string, without allocating.
func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h = (h ^ uint32(s[i])) * 16777619
	}
	return h
}

func (b *tokenBucket) shard(key string) *limitShard { return &b.shards[fnv32(key)%limitShards] }

// allow takes a token for key.
func (b *tokenBucket) allow(key string, now time.Time) bool {
	ok, _ := b.take(key, now)
	return ok
}

// take takes a token for key and reports the tokens left.
func (b *tokenBucket) take(key string, now time.Time) (bool, float64) {
	s := b.shard(key)
	s.mu.Lock()
	if s.clients == nil {
		s.clients = make(map[string]*bucketState)
	}
	st := s.clients[key]
	if st == nil {
		if len(s.clients) >= limitShardCap {
			for k := range s.clients { // bounded memory under a flood of distinct clients
				delete(s.clients, k)
				break
			}
		}
		st = &bucketState{tokens: b.burst, last: now}
		s.clients[strings.Clone(key)] = st // the key may alias a request's RemoteAddr
	}
	st.tokens = math.Min(b.burst, st.tokens+now.Sub(st.last).Seconds()*b.rate)
	st.last = now
	ok := st.tokens >= 1
	if ok {
		st.tokens--
	}
	left := st.tokens
	s.mu.Unlock()
	return ok, left
}

// has reports whether key has a token, without taking one.
func (b *tokenBucket) has(key string, now time.Time) bool {
	s := b.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.clients[key]
	return st == nil || st.tokens+now.Sub(st.last).Seconds()*b.rate >= 1
}

// sweep drops buckets that have refilled completely.
func (b *tokenBucket) sweep(now time.Time) {
	for i := range b.shards {
		s := &b.shards[i]
		s.mu.Lock()
		for k, st := range s.clients {
			if st.tokens+now.Sub(st.last).Seconds()*b.rate >= b.burst {
				delete(s.clients, k)
			}
		}
		s.mu.Unlock()
	}
}

// size is the number of tracked clients (tests and metrics).
func (b *tokenBucket) size() int {
	n := 0
	for i := range b.shards {
		s := &b.shards[i]
		s.mu.Lock()
		n += len(s.clients)
		s.mu.Unlock()
	}
	return n
}

// ---- basic auth: verified-credential cache ----

const (
	authCacheShards = 16
	authCacheCap    = 1024 // entries per shard
	authCacheTTL    = 5 * time.Minute
)

// authCache remembers credentials bcrypt has already accepted, so a client making many requests
// pays for the hash once. The key is a digest of user, password and stored hash: changing the
// password or removing the user can never be answered from the cache.
type authCache struct {
	shards [authCacheShards]authShard
}

type authShard struct {
	mu sync.Mutex
	m  map[[32]byte]int64 // digest -> expiry (unix nanoseconds)
	_  [48]byte
}

func authDigest(user, pass, hash string) [32]byte {
	h := sha256.New()
	for _, s := range [...]string{user, pass, hash} {
		var n [4]byte
		n[0], n[1], n[2], n[3] = byte(len(s)>>24), byte(len(s)>>16), byte(len(s)>>8), byte(len(s))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	var d [32]byte
	h.Sum(d[:0])
	return d
}

func (c *authCache) shard(d [32]byte) *authShard { return &c.shards[int(d[0])%authCacheShards] }

func (c *authCache) ok(d [32]byte, now time.Time) bool {
	s := c.shard(d)
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, found := s.m[d]
	if found && now.UnixNano() >= exp {
		delete(s.m, d)
		return false
	}
	return found
}

func (c *authCache) put(d [32]byte, now time.Time) {
	s := c.shard(d)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil || len(s.m) >= authCacheCap {
		s.m = make(map[[32]byte]int64)
	}
	s.m[d] = now.Add(authCacheTTL).UnixNano()
}

// janitor trims limiter state that has nothing left to remember, until ctx ends.
func (g *gatewayServer) janitor(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, r := range g.tbl.Load().all {
				if r.limiter != nil {
					r.limiter.sweep(now)
				}
				if r.authFail != nil {
					r.authFail.sweep(now)
				}
			}
			g.leafLimit.sweep(now)
		}
	}
}
