package audit

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Beginner starts transactions (pgxpool.Pool satisfies it).
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Appender commits standalone audit events (reads, denials, logins) with
// per-chain group commit: concurrent events for the same chain share one
// transaction and one fsync, preserving order. Append returns only after the
// event is durably committed (or with an error).
type Appender struct {
	db       Beginner
	mu       sync.Mutex
	chains   map[string]*chainQueue
	wg       sync.WaitGroup
	closed   bool
	maxBatch int
}

type pending struct {
	events []*Event
	done   chan error
}

type chainQueue struct {
	queue    []*pending
	flushing bool
}

// NewAppender returns an Appender writing through db.
func NewAppender(db Beginner) *Appender {
	return &Appender{db: db, chains: map[string]*chainQueue{}, maxBatch: 1000}
}

// ErrClosed is returned after Close.
var ErrClosed = errors.New("audit: appender closed")

// Append durably appends events (which must share a chain) and waits for
// the commit. If ctx ends first an error is returned; the events may still
// be committed (an extra audit record is acceptable, a missing one is not
// reported as success).
func (a *Appender) Append(ctx context.Context, events ...*Event) error {
	if len(events) == 0 {
		return nil
	}
	chain := events[0].Chain
	for _, e := range events {
		if e.Chain != chain {
			return errors.New("audit: Append events must share a chain")
		}
	}
	p := &pending{events: events, done: make(chan error, 1)}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return ErrClosed
	}
	q := a.chains[chain]
	if q == nil {
		q = &chainQueue{}
		a.chains[chain] = q
	}
	q.queue = append(q.queue, p)
	if !q.flushing {
		q.flushing = true
		a.wg.Add(1)
		go a.flush(chain, q)
	}
	a.mu.Unlock()

	select {
	case err := <-p.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Appender) flush(chain string, q *chainQueue) {
	defer a.wg.Done()
	for {
		a.mu.Lock()
		if len(q.queue) == 0 {
			q.flushing = false
			delete(a.chains, chain)
			a.mu.Unlock()
			return
		}
		var batch []*pending
		n := 0
		for len(q.queue) > 0 && (n == 0 || n+len(q.queue[0].events) <= a.maxBatch) {
			batch = append(batch, q.queue[0])
			n += len(q.queue[0].events)
			q.queue = q.queue[1:]
		}
		a.mu.Unlock()

		err := a.commit(batch)
		for _, p := range batch {
			p.done <- err
		}
	}
}

func (a *Appender) commit(batch []*pending) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var events []*Event
	for _, p := range batch {
		events = append(events, p.events...)
	}
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := AppendTx(ctx, tx, events...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Close waits for in-flight flushes and rejects new appends.
func (a *Appender) Close() {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	a.wg.Wait()
}
