package lru

import "container/list"

// Cache is a generic LRU cache. Not safe for concurrent use — callers must synchronize.
type Cache[K comparable, V any] struct {
	cap   int
	items map[K]*list.Element
	order *list.List
}

type entry[K comparable, V any] struct {
	key   K
	value V
}

// New creates a new LRU cache with the given capacity.
func New[K comparable, V any](capacity int) *Cache[K, V] {
	return &Cache[K, V]{
		cap:   capacity,
		items: make(map[K]*list.Element, capacity),
		order: list.New(),
	}
}

// Get returns the value and true if found, moving it to the front.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)

		e, _ := el.Value.(*entry[K, V])

		return e.value, true
	}

	var zero V
	return zero, false
}

// Put inserts or updates a key-value pair. Evicts the oldest entry if at capacity.
func (c *Cache[K, V]) Put(key K, value V) {
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)

		e, _ := el.Value.(*entry[K, V])
		e.value = value

		return
	}

	if c.order.Len() >= c.cap {
		c.evictOldest()
	}

	el := c.order.PushFront(&entry[K, V]{key: key, value: value})
	c.items[key] = el
}

// Delete removes a key from the cache.
func (c *Cache[K, V]) Delete(key K) {
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

// Len returns the number of entries in the cache.
func (c *Cache[K, V]) Len() int {
	return c.order.Len()
}

func (c *Cache[K, V]) evictOldest() {
	el := c.order.Back()
	if el == nil {
		return
	}

	c.order.Remove(el)

	e, _ := el.Value.(*entry[K, V])
	delete(c.items, e.key)
}
