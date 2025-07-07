package xsync

import (
	"sync"
)

type syncMap[K comparable, V any] struct {
	m sync.Map
}

func (s *syncMap[K, V]) Load(key K) (V, bool) {
	val, ok := s.m.Load(key)
	if !ok {
		var zeroVal V
		return zeroVal, false
	}

	return val.(V), true
}

func (s *syncMap[K, V]) Range(f func(key K, value V) bool) {
	s.m.Range(func(k, v any) bool {
		return f(k.(K), v.(V))
	})
}

func (s *syncMap[K, V]) Store(key K, value V) {
	s.m.Store(key, value)
}

func (s *syncMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	v, loaded := s.m.LoadOrStore(key, value)
	return v.(V), loaded
}

func (s *syncMap[K, V]) Delete(key K) {
	s.m.Delete(key)
}

type Map[K comparable, V any] interface {
	Load(key K) (V, bool)
	Range(f func(key K, value V) bool)
	Store(key K, value V)
	LoadOrStore(key K, value V) (actual V, loaded bool)
	Delete(key K)
}

func NewMap[K comparable, V any]() Map[K, V] {
	return &syncMap[K, V]{}
}

// lockMap wraps a syncMap and provides optional coarse-grained locking semantics.
//
// Unlike traditional maps, syncMap is safe for concurrent use but allows racy writes.
// lockMap does not attempt to eliminate those races in its standard methods (Store, Delete, etc.).
// Instead, it offers a coordination mechanism using an RWMutex (`racyRWM`) to control access
// when stricter guarantees are needed.
//
// Individual write methods (Store, Delete, LoadOrStore) acquire a read lock to block only
// while a WithWriteLock call is active. This ensures that while WithWriteLock holds the
// write lock, no racy writes can interleave.
//
// To perform multi-step or consistency-sensitive operations, use WithWriteLock to obtain
// full mutual exclusion over the map.
//
// WARNING: Standard write methods are still racy with respect to each other — this is by design.
// They rely on sync.Map’s internal safety and are only blocked during WithWriteLock execution.
type lockMap[K comparable, V any] struct {
	// racyRWM coordinates racy write operations and enforces mutual exclusion during WithWriteLock.
	// It is not used for protecting syncMap itself, which remains race-tolerant.
	racyRWM sync.RWMutex
	m       syncMap[K, V]
}

// Load retrieves the value for the given key.
//
// This is safe under Map semantics but does NOT provide full mutual exclusion.
// Use WithWriteLock for atomic multi-key updates.
func (s *lockMap[K, V]) Load(key K) (V, bool) {
	return s.m.Load(key)
}

// Ranges over all key-value pairs in a non-locking manner.
//
// This is safe under Map semantics but does NOT provide full mutual exclusion.
// Use WithWriteLock for atomic multi-key updates.
func (s *lockMap[K, V]) Range(f func(key K, value V) bool) {
	s.m.Range(f)
}

// Store stores the key-value pair.
//
// This is safe under Map semantics but does NOT provide full mutual exclusion.
// Use WithWriteLock for atomic multi-key updates.
func (s *lockMap[K, V]) Store(key K, value V) {
	s.racyRWM.RLock()
	defer s.racyRWM.RUnlock()

	s.m.Store(key, value)
}

// LoadOrStore loads the value for the key if it exists, or stores the value if it does not.
//
// This is safe under Map semantics but does NOT provide full mutual exclusion.
// Use WithWriteLock for atomic multi-key updates.
func (s *lockMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	s.racyRWM.RLock()
	defer s.racyRWM.RUnlock()

	return s.m.LoadOrStore(key, value)
}

// Delete removes the key-value pair for the given key.
//
// This is safe under Map semantics but does NOT provide full mutual exclusion.
// Use WithWriteLock for atomic multi-key updates.
func (s *lockMap[K, V]) Delete(key K) {
	s.racyRWM.RLock()
	defer s.racyRWM.RUnlock()

	s.m.Delete(key)
}

// WithWriteLock executes the provided function with a write lock on the map.
// no other write operations on the LockableMap can be performed while the lock is held.
//
// This allows for complex operations that require exclusive access to the map.
func (s *lockMap[K, V]) WithWriteLock(f func(Map[K, V])) {
	s.racyRWM.Lock()
	defer s.racyRWM.Unlock()

	f(&s.m)
}

// LockableMap wraps a Map to allow optional coarse-grained locking.
//
// This method is useful for scenarios where you want to perform multiple operations
// atomically, such as updating multiple keys, or inserting a value once and only once
// where all other insertions would use this same method to attempt to do so atomically.
//
// By default, operations like Store/Delete/LoadOrStore use RLock, which does not
// prevent concurrent writes but offers a minimal sync barrier.
//
// For strict mutual exclusion across multiple operations, use WithWriteLock.
// This allows the caller to perform complex logic with full exclusive access.
//
// WARNING: Individual Store/Delete calls may race, just as they would using Map directly.
// If exclusive consistency is required, use WithWriteLock.
type LockableMap[K comparable, V any] interface {
	Map[K, V]
	WithWriteLock(f func(Map[K, V]))
}

func NewLockableMap[K comparable, V any]() LockableMap[K, V] {
	return &lockMap[K, V]{}
}
