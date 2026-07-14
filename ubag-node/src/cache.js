'use strict';

/**
 * Small bounded TTL cache (LRU eviction). Mirrors ubag-python/src/ubag/_cache.py.
 * Bounded on BOTH time and size — a TTL alone leaks memory under crawl traffic,
 * so entries are also LRU-evicted once the cache is full. Used to cache origin
 * HTML fetched for Branch B extraction.
 */
class TTLCache {
  constructor(maxSize = 256, ttl = 300) {
    this.maxSize = Math.max(1, maxSize);
    this.ttl = ttl;
    this._store = new Map(); // Map preserves insertion order → cheap LRU
  }

  get(key) {
    const item = this._store.get(key);
    if (item === undefined) return undefined;
    const [expiry, value] = item;
    if (Date.now() / 1000 >= expiry) {
      this._store.delete(key);
      return undefined;
    }
    this._store.delete(key);
    this._store.set(key, item); // move to most-recently-used
    return value;
  }

  set(key, value) {
    if (this._store.has(key)) this._store.delete(key);
    this._store.set(key, [Date.now() / 1000 + this.ttl, value]);
    while (this._store.size > this.maxSize) {
      this._store.delete(this._store.keys().next().value); // evict LRU
    }
  }

  clear() {
    this._store.clear();
  }
}

module.exports = { TTLCache };
