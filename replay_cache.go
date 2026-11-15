package ssu2path

import (
	"sync"
	"time"
)

// replayCache is a small bounded, TTL-expiring set of message identifiers used
// to suppress replays (PATH-007). Signature verification plus the ±MaxClockSkew
// wall-clock window in checkTimestampSkew bounds a message's *age*, but nothing
// previously rejected a *duplicate*: a captured Hole Punch or Relay Response is
// re-accepted for ~2×MaxClockSkew (~10 min), re-setting coordinator state and
// rewriting RemoteAddr. Recording the identifier of every accepted message for
// the duration of the skew window closes that gap.
//
// The cache is bounded on two axes so it cannot itself become a memory-DoS
// vector: entries older than ttl are dropped, and once max entries are held the
// oldest are evicted. Because the ttl is set to at least the skew window, a
// genuine retransmit (which carries a *different* signature) is never suppressed
// — only an exact replay of an already-accepted message is.
//
// Thread-safe: all operations take the internal lock, so the cache can be shared
// across the coordinator's unlocked verify path.
type replayCache struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	ttl     time.Duration
	max     int
	nowFunc func() time.Time // overridable for tests
}

// newReplayCache returns a cache that remembers identifiers for ttl and holds at
// most max entries. max <= 0 disables the cache (every check reports "not seen",
// i.e. replay suppression is off), which lets callers opt out.
func newReplayCache(ttl time.Duration, max int) *replayCache {
	if max <= 0 {
		return &replayCache{ttl: ttl, max: max, nowFunc: time.Now}
	}
	return &replayCache{
		seen:    make(map[string]time.Time, min(max, 64)),
		ttl:     ttl,
		max:     max,
		nowFunc: time.Now,
	}
}

// checkAndRecord reports whether key was already accepted within the ttl window.
// When it returns false (not a replay) it also records key as seen, so a
// subsequent identical message is reported as a replay. This check-then-record
// is performed atomically under the lock to avoid a TOCTOU race between two
// concurrent copies of the same message.
func (c *replayCache) checkAndRecord(key string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Decide enable/disable *inside* the lock: c.max and c.seen are mutated by
	// setMax under the same lock, so reading them here (rather than in a
	// pre-lock guard) avoids both a data race on c.max and a TOCTOU window where
	// setMax(<=0) could nil c.seen between the guard and the insert below.
	if c.max <= 0 || c.seen == nil {
		return false // cache disabled
	}

	now := c.nowFunc()
	if exp, ok := c.seen[key]; ok && now.Before(exp) {
		return true // replay within the window
	}
	c.insert(key, now)
	return false
}

// setMax overrides the cache bound. max <= 0 disables the cache (and frees the
// backing map); max > 0 enables it, allocating the map if it was previously
// disabled. When the bound shrinks below the current occupancy the map is
// trimmed immediately so the new max is enforced at once and memory is freed,
// rather than lingering until TTL expiry. Safe to call concurrently with
// checkAndRecord.
func (c *replayCache) setMax(max int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.max = max
	switch {
	case max <= 0:
		c.seen = nil
	case c.seen == nil:
		c.seen = make(map[string]time.Time, min(max, 64))
	default:
		// Bound shrank below current occupancy: evict down to the new max now.
		for len(c.seen) > max {
			if !c.evictOldest() {
				break
			}
		}
	}
}

// insert records key with an expiry of now+ttl, evicting expired entries and,
// if still at or over capacity, enough of the oldest entries to make room. It
// guarantees len(c.seen) <= c.max on return. Caller must hold c.mu.
func (c *replayCache) insert(key string, now time.Time) {
	// Opportunistically drop expired entries to keep the map near its working set.
	for k, exp := range c.seen {
		if !now.Before(exp) {
			delete(c.seen, k)
		}
	}
	// Evict until there is room for the new key. Normally a single iteration;
	// more only when the map is transiently over capacity (e.g. right after
	// setMax shrank the bound), which keeps the bound enforced regardless of how
	// the map got over capacity.
	for len(c.seen) >= c.max {
		if !c.evictOldest() {
			break
		}
	}
	c.seen[key] = now.Add(c.ttl)
}

// evictOldest removes the entry with the earliest expiry (approximate LRU, since
// all entries share the same ttl the earliest expiry is the oldest). It returns
// false when the map is empty. Caller must hold c.mu.
func (c *replayCache) evictOldest() bool {
	var oldestKey string
	var oldestExp time.Time
	first := true
	for k, exp := range c.seen {
		if first || exp.Before(oldestExp) {
			oldestKey, oldestExp, first = k, exp, false
		}
	}
	if first {
		return false
	}
	delete(c.seen, oldestKey)
	return true
}
