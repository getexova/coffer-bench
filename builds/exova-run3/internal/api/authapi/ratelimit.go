package authapi

import (
	"container/list"
	"sync"
	"time"
)

// Bounds on the in-process state. Every key here is attacker-controlled, so every
// map is an LRU with a hard capacity: an unbounded map keyed by a submitted email
// or a source address is a memory-exhaustion bug, not a cache.
const (
	// failureWindowCapacity is how many accounts keep a failure history. It is
	// far more than one deployment has users, so a legitimate lockout is never
	// forgotten, and bounded, so a spray of invented addresses cannot grow it.
	failureWindowCapacity = 4096

	// ipBucketCapacity is how many source addresses keep a token bucket.
	ipBucketCapacity = 8192
)

// Lockout policy (SPEC §4): 5 failures within 15 minutes locks the account until
// the window passes, even for the correct password.
const (
	lockoutThreshold = 5
	lockoutWindow    = 15 * time.Minute
)

// Per-IP login throttle. Only FAILED attempts consume it, so a legitimate flow
// that logs in many times from one address is never throttled, while an online
// guessing attack from one address is. The per-account lockout is the primary
// control; this is the anti-spraying control beside it, sized so that a test
// harness running dozens of logins from 127.0.0.1 never trips it.
const (
	loginIPBurst  = 100
	loginIPRefill = 10 // tokens per second
)

// Denial-flush rate limit (SPEC §4 audit, brief): 10/s burst 50 per source IP and a
// 100/s global cap. Overflow is counted and dropped, never one audit row per
// dropped denial.
const (
	denialIPBurst      = 50
	denialIPRefill     = 10
	denialGlobalBurst  = 100
	denialGlobalRefill = 100
	denialReportEvery  = 10 * time.Second
)

// keyedLRU is a bounded map with least-recently-used eviction. Values are mutated
// in place under the lock by the callback passed to update.
type keyedLRU[V any] struct {
	mu    sync.Mutex
	cap   int
	order *list.List
	index map[string]*list.Element
}

type lruItem[V any] struct {
	key string
	val *V
}

func newKeyedLRU[V any](capacity int) *keyedLRU[V] {
	if capacity < 1 {
		capacity = 1
	}
	return &keyedLRU[V]{
		cap:   capacity,
		order: list.New(),
		index: make(map[string]*list.Element, capacity),
	}
}

// update runs fn with the current value for key, creating a zero value when the
// key is absent, and stores the result. fn returns false to drop the entry. The
// key is moved to the front on every access, which is what makes eviction
// least-recently-used.
func (l *keyedLRU[V]) update(key string, fn func(v *V, exists bool) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if el, ok := l.index[key]; ok {
		l.order.MoveToFront(el)
		item := el.Value.(*lruItem[V])
		if !fn(item.val, true) {
			l.order.Remove(el)
			delete(l.index, key)
		}
		return
	}

	var zero V
	v := &zero
	if !fn(v, false) {
		return
	}
	l.index[key] = l.order.PushFront(&lruItem[V]{key: key, val: v})
	for l.order.Len() > l.cap {
		oldest := l.order.Back()
		if oldest == nil {
			break
		}
		l.order.Remove(oldest)
		delete(l.index, oldest.Value.(*lruItem[V]).key)
	}
}

// view runs fn with the current value for key without creating it. The key is
// touched, so an account under active attack keeps its history.
func (l *keyedLRU[V]) view(key string, fn func(v *V, exists bool)) {
	l.mu.Lock()
	defer l.mu.Unlock()

	el, ok := l.index[key]
	if !ok {
		var zero V
		fn(&zero, false)
		return
	}
	l.order.MoveToFront(el)
	fn(el.Value.(*lruItem[V]).val, true)
}

// delete drops one entry.
func (l *keyedLRU[V]) delete(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if el, ok := l.index[key]; ok {
		l.order.Remove(el)
		delete(l.index, key)
	}
}

// failureRecord is the failure history of one account.
type failureRecord struct {
	times []time.Time
}

// lockout tracks failed logins per email address.
//
// The rule is literal (SPEC §4): once five failures fall inside a 15-minute
// window, the account is locked until the OLDEST of those five ages out, so a
// correct password does not get in either. Other accounts keep their own history
// and are unaffected.
//
// Consequence, accepted and documented rather than papered over: an unknown email
// that has been failed five times is locked exactly like a real one, so a 429 on
// login is evidence that the account exists. Returning a uniform 429 for unknown
// emails would be a different lie — it would claim a lockout that is not there and
// would make the rate limiter's state depend on a check the spec does not ask for.
type lockout struct {
	records *keyedLRU[failureRecord]
}

func newLockout() *lockout {
	return &lockout{records: newKeyedLRU[failureRecord](failureWindowCapacity)}
}

// prune drops timestamps that have aged out of the window and returns the retained
// slice.
func prune(times []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-lockoutWindow)
	i := 0
	for i < len(times) && !times[i].After(cutoff) {
		i++
	}
	return times[i:]
}

// locked reports whether email is currently locked and how long is left.
func (l *lockout) locked(email string, now time.Time) (bool, time.Duration) {
	var (
		locked bool
		wait   time.Duration
	)
	l.records.view(email, func(rec *failureRecord, exists bool) {
		if !exists {
			return
		}
		rec.times = prune(rec.times, now)
		if len(rec.times) < lockoutThreshold {
			return
		}
		locked = true
		wait = rec.times[0].Add(lockoutWindow).Sub(now)
		if wait < 0 {
			wait = 0
		}
	})
	return locked, wait
}

// fail records one failed login for email and reports the resulting lock state.
func (l *lockout) fail(email string, now time.Time) (bool, time.Duration) {
	var (
		locked bool
		wait   time.Duration
	)
	l.records.update(email, func(rec *failureRecord, exists bool) bool {
		rec.times = prune(append(rec.times, now), now)
		// Only the last threshold+1 timestamps can matter: the lock lifts when the
		// oldest retained one ages out, so older ones are dead weight.
		if len(rec.times) > lockoutThreshold+1 {
			rec.times = rec.times[len(rec.times)-lockoutThreshold-1:]
		}
		if len(rec.times) >= lockoutThreshold {
			locked = true
			wait = rec.times[0].Add(lockoutWindow).Sub(now)
			if wait < 0 {
				wait = 0
			}
		}
		return true
	})
	return locked, wait
}

// reset forgets an account's failures, which a successful login does.
func (l *lockout) reset(email string) {
	l.records.delete(email)
}

// tokenBucket is a refilling bucket for one key.
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// throttle is a per-key token bucket with a bounded key space.
type throttle struct {
	buckets *keyedLRU[tokenBucket]
	burst   float64
	refill  float64 // tokens per second
}

func newThrottle(capacity int, burst, refill float64) *throttle {
	return &throttle{
		buckets: newKeyedLRU[tokenBucket](capacity),
		burst:   burst,
		refill:  refill,
	}
}

// allow consumes one token for key and reports whether one was available.
func (t *throttle) allow(key string, now time.Time) bool {
	allowed := false
	t.buckets.update(key, func(b *tokenBucket, exists bool) bool {
		if !exists || b.last.IsZero() {
			b.tokens = t.burst
		} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = min(t.burst, b.tokens+elapsed*t.refill)
		}
		b.last = now
		if b.tokens >= 1 {
			b.tokens--
			allowed = true
		}
		return true
	})
	return allowed
}

// limiter bundles every rate limit this slice owns.
type limiter struct {
	lockout *lockout
	loginIP *throttle
	denials *denialLimiter
}

func newLimiter() *limiter {
	return &limiter{
		lockout: newLockout(),
		loginIP: newThrottle(ipBucketCapacity, loginIPBurst, loginIPRefill),
		denials: newDenialLimiter(),
	}
}

// denialLimiter enforces the audit-flush budget: per source IP and globally.
type denialLimiter struct {
	mu       sync.Mutex
	perIP    *throttle
	global   *throttle
	dropped  int64
	lastNote time.Time
}

func newDenialLimiter() *denialLimiter {
	return &denialLimiter{
		perIP:  newThrottle(ipBucketCapacity, denialIPBurst, denialIPRefill),
		global: newThrottle(1, denialGlobalBurst, denialGlobalRefill),
	}
}

// allow reports whether a denial event may be written for sourceIP. A refusal
// increments the dropped counter; the counter is reported in aggregate so a flood
// cannot turn into a flood of log lines.
func (d *denialLimiter) allow(sourceIP string, now time.Time) (bool, int64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.global.allow("global", now) {
		d.dropped++
		return false, 0
	}
	if sourceIP != "" && !d.perIP.allow(sourceIP, now) {
		d.dropped++
		return false, 0
	}

	var report int64
	if d.dropped > 0 && now.Sub(d.lastNote) >= denialReportEvery {
		report = d.dropped
		d.dropped = 0
		d.lastNote = now
	}
	return true, report
}

// takeDropped returns the number of dropped denials since the last report, for the
// periodic aggregate log line.
func (d *denialLimiter) takeDropped(now time.Time) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dropped == 0 || now.Sub(d.lastNote) < denialReportEvery {
		return 0
	}
	n := d.dropped
	d.dropped = 0
	d.lastNote = now
	return n
}
