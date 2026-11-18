package ssu2path

import (
	"container/list"
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
// PATH-002: checkAndRecord runs on the hot verify path for every accepted
// message, so it must be O(1). The earlier implementation walked the whole map
// twice per insert — once to sweep expired entries and once to find the oldest
// entry to evict — which at the default 8192 cap cost ~725µs/msg and serialized
// the verify path. Because every entry shares the same ttl, insertion order is
// identical to expiry order (the first entry inserted always expires first). We
// exploit that invariant with an insertion-order FIFO (c.order): expired entries
// are popped from the front, and eviction drops the front. Both are O(1), so
// checkAndRecord is amortized O(1) and the map is never walked.
//
// Thread-safe: all operations take the internal lock, so the cache can be shared
// across the coordinator's unlocked verify path.
type replayCache struct {
	mu      sync.Mutex
	seen    map[string]replayEntry
	order   *list.List // front = oldest / earliest expiry, back = newest
	ttl     time.Duration
	max     int
	nowFunc func() time.Time // overridable for tests
}

// replayEntry is a map value: the moment the identifier expires, plus a pointer
// to its position in c.order. Holding the element pointer lets us remove a
// specific entry from the FIFO in O(1) (e.g. when an expired key is re-added or
// when the bound shrinks), keeping the list and map in lockstep.
type replayEntry struct {
	expiry time.Time
	elem   *list.Element
}

// newReplayCache returns a cache that remembers identifiers for ttl and holds at
// most max entries. max <= 0 disables the cache (every check reports "not seen",
// i.e. replay suppression is off), which lets callers opt out.
func newReplayCache(ttl time.Duration, max int) *replayCache {
	if max <= 0 {
		return &replayCache{ttl: ttl, max: max, nowFunc: time.Now}
	}
	return &replayCache{
		seen:    make(map[string]replayEntry, min(max, 64)),
		order:   list.New(),
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
	// Drop every entry whose window has elapsed. Because entries expire in
	// insertion order, they sit contiguously at the front, so this pops only
	// what is actually expired and stops at the first live entry (amortized O(1)
	// across the run: each entry is popped at most once).
	c.expireFront(now)

	// Any entry still in the map is unexpired (expireFront removed the rest), so
	// a hit is a genuine replay within the window.
	if _, ok := c.seen[key]; ok {
		return true
	}
	c.insert(key, now)
	return false
}

// setMax overrides the cache bound. max <= 0 disables the cache (and frees the
// backing map and queue); max > 0 enables it, allocating them if the cache was
// previously disabled. When the bound shrinks below the current occupancy the
// map is trimmed immediately so the new max is enforced at once and memory is
// freed, rather than lingering until TTL expiry. Trimming evicts from the front,
// so the freshest entries survive. Safe to call concurrently with checkAndRecord.
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
		c.order = nil
	case c.seen == nil:
		c.seen = make(map[string]replayEntry, min(max, 64))
		c.order = list.New()
	default:
		// Bound shrank below current occupancy: evict the oldest down to the new
		// max now.
		for len(c.seen) > max {
			if !c.evictFront() {
				break
			}
		}
	}
}

// insert records key with an expiry of now+ttl, evicting from the front if the
// map is at capacity. It guarantees len(c.seen) <= c.max on return. Caller must
// hold c.mu.
func (c *replayCache) insert(key string, now time.Time) {
	// If the key is somehow already present (its entry expired but was not yet
	// popped, or a caller re-inserts), drop its stale queue element first so the
	// list and map stay in lockstep. Normally a no-op: checkAndRecord expires and
	// checks before calling insert.
	if old, ok := c.seen[key]; ok {
		c.order.Remove(old.elem)
	}
	// Make room for the new key. Normally a single eviction; more only when the
	// map is transiently over capacity (e.g. right after setMax shrank the
	// bound), which keeps the bound enforced regardless of how it got over.
	for len(c.seen) >= c.max {
		if !c.evictFront() {
			break
		}
	}
	elem := c.order.PushBack(key)
	c.seen[key] = replayEntry{expiry: now.Add(c.ttl), elem: elem}
}

// expireFront removes entries from the front of the queue whose expiry has
// elapsed, deleting their map entries too. Since all entries share the same ttl
// they expire in insertion order, so expired entries are contiguous at the
// front: the walk stops at the first still-live entry. Caller must hold c.mu.
func (c *replayCache) expireFront(now time.Time) {
	for {
		elem := c.order.Front()
		if elem == nil {
			return
		}
		key := elem.Value.(string)
		if now.Before(c.seen[key].expiry) {
			return // front is live, so every later entry is live too
		}
		c.order.Remove(elem)
		delete(c.seen, key)
	}
}

// evictFront removes the front (oldest / earliest-expiry) entry from both the
// queue and the map. It returns false when the cache is empty. Caller must hold
// c.mu.
func (c *replayCache) evictFront() bool {
	elem := c.order.Front()
	if elem == nil {
		return false
	}
	key := elem.Value.(string)
	c.order.Remove(elem)
	delete(c.seen, key)
	return true
}
