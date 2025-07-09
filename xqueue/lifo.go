package xqueue

import (
	"errors"
	"fmt"
	"iter"
	"math"
	"sync"
)

var (
	ErrQueueClosed = errors.New("queue is closed")
)

type lifo[T any] struct {
	rwmPut      sync.RWMutex
	rwmStack    sync.RWMutex
	stack       []T
	put         func(T) bool
	maxCapacity int
	closed      bool
}

type LIFO[T any] interface {
	Get() (T, bool)
	Put(T) bool
	IntoIter() iter.Seq[T]
	WithWriteLock(func(*[]T))
	Close() error
}

type lifoConfig[T any] struct {
	initialCapacity    int
	maxCapacity        int
	cappedBuffer       []T
	initialCapacitySet bool
	maxCapacitySet     bool
	cappedBufferSet    bool
}

func (cfg *lifoConfig[T]) validate() error {
	if cfg.cappedBufferSet {

		if len(cfg.cappedBuffer) == 0 {
			return errors.New("cappedBuffer length must be greater than 0")
		}

		if cfg.initialCapacitySet || cfg.maxCapacitySet {
			return errors.New("cannot set buffer and (initialCapacity or maxCapacity) at the same time")
		}

		n := len(cfg.cappedBuffer)
		cfg.maxCapacity = n
		cfg.cappedBuffer = cfg.cappedBuffer[0:n:n]
	} else if !cfg.maxCapacitySet {
		if cfg.initialCapacitySet {
			cfg.maxCapacity = cfg.initialCapacity
		} else {
			cfg.maxCapacity = math.MaxInt
		}
	}

	if cfg.initialCapacity < 0 {
		return errors.New("initialCapacity must be greater than or equal to 0")
	}

	if cfg.maxCapacity <= 0 || cfg.maxCapacity < cfg.initialCapacity {
		return errors.New("maxCapacity must be greater than zero and greater than or equal to initialCapacity")
	}

	return nil
}

type LIFOOption[T any] func(*lifoConfig[T])

type lifoOptions[T any] struct{}

func (lifoOptions[T]) InitialCapacity(n int) LIFOOption[T] {
	return func(cfg *lifoConfig[T]) {
		cfg.initialCapacity = n
		cfg.initialCapacitySet = true
	}
}

func (lifoOptions[T]) MaxCapacity(n int) LIFOOption[T] {
	return func(cfg *lifoConfig[T]) {
		cfg.maxCapacity = n
		cfg.maxCapacitySet = true
	}
}

func (lifoOptions[T]) CappedBuffer(p []T) LIFOOption[T] {
	return func(cfg *lifoConfig[T]) {
		cfg.cappedBuffer = p
		cfg.cappedBufferSet = true
	}
}

func LIFOOpts[T any]() lifoOptions[T] {
	return lifoOptions[T]{}
}

func NewLIFO[T any](options ...LIFOOption[T]) (LIFO[T], error) {
	cfg := lifoConfig[T]{}

	for _, op := range options {
		op(&cfg)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid LIFO config: %w", err)
	}

	stack := cfg.cappedBuffer
	if stack == nil && cfg.initialCapacity > 0 {
		stack = make([]T, 0, cfg.initialCapacity)
	}

	q := &lifo[T]{
		stack:       stack,
		maxCapacity: cfg.maxCapacity,
	}

	q.put = q.openPut

	return q, nil
}

func (q *lifo[T]) IntoIter() iter.Seq[T] {
	return q.iter
}

func (q *lifo[T]) iter(yield func(v T) bool) {
	q.rwmStack.RLock()
	defer q.rwmStack.RUnlock()

	for i := len(q.stack) - 1; i >= 0; i-- {
		if !yield(q.stack[i]) {
			return
		}
	}
}

func (q *lifo[T]) Get() (T, bool) {
	var zeroVal T

	q.rwmStack.Lock()
	defer q.rwmStack.Unlock()

	i := len(q.stack) - 1
	if i == -1 {
		return zeroVal, false
	}

	v := q.stack[i]
	q.stack[i] = zeroVal
	q.stack = q.stack[:i]

	return v, true
}

func (q *lifo[T]) Put(v T) bool {
	q.rwmPut.RLock()
	defer q.rwmPut.RUnlock()

	return q.put(v)
}

func (q *lifo[T]) openPut(v T) bool {
	q.rwmStack.Lock()
	defer q.rwmStack.Unlock()

	if len(q.stack) == q.maxCapacity {
		return false
	}

	q.stack = append(q.stack, v)
	if cap(q.stack) > q.maxCapacity {
		newStack := make([]T, len(q.stack), q.maxCapacity)
		copy(newStack, q.stack)
		q.stack = newStack
	}

	return true
}

func (q *lifo[T]) closedPut(v T) bool {
	return false
}

// Close closes the queue, preventing any further puts.
//
// Subsequent calls to Close will return ErrQueueClosed if the queue is already closed.
//
// Currently, close always returns nil the first time it is called.
func (q *lifo[T]) Close() error {
	if q.closed {
		return ErrQueueClosed
	}

	//
	// TODO: use a singleflight operation here to avoid concurrent executors since they should all use the same result
	//

	q.rwmPut.RLock()
	unlocker := q.rwmPut.RUnlock
	defer func() {
		if f := unlocker; f != nil {
			f()
		}
	}()

	if q.closed {
		return ErrQueueClosed
	}

	{
		f := unlocker
		unlocker = nil
		f()

		unlocker = q.rwmPut.Unlock
		q.rwmPut.Lock()
	}

	if q.closed {
		return ErrQueueClosed
	}

	q.put = q.closedPut
	q.closed = true

	return nil
}

func (q *lifo[T]) WithWriteLock(f func(*[]T)) {
	q.rwmStack.Lock()
	defer q.rwmStack.Unlock()

	f(&q.stack)
}
