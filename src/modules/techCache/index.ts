/**
 * Unified Cache
 *
 * Simple LRU cache with TTL support for caching API responses,
 * tech detection results, and other data.
 */

import { LRUCache } from 'lru-cache';

export interface CacheOptions {
  maxEntries?: number;
  maxMemoryMB?: number;
  defaultTtlMs?: number;
}

export class UnifiedCache<V = unknown> {
  private cache: LRUCache<string, { value: V; expiry: number }>;
  private defaultTtlMs: number;

  constructor(options: CacheOptions = {}) {
    const { maxEntries = 1000, maxMemoryMB = 50, defaultTtlMs = 3600000 } = options;

    this.defaultTtlMs = defaultTtlMs;
    this.cache = new LRUCache<string, { value: V; expiry: number }>({
      max: maxEntries,
      maxSize: maxMemoryMB * 1024 * 1024,
      sizeCalculation: (entry) => {
        // Rough size estimation
        return JSON.stringify(entry).length * 2;
      },
    });
  }

  /**
   * Get a value from the cache
   */
  get(key: string): V | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    // Check if expired
    if (Date.now() > entry.expiry) {
      this.cache.delete(key);
      return undefined;
    }

    return entry.value;
  }

  /**
   * Set a value in the cache
   */
  set(key: string, value: V, ttlMs?: number): void {
    const expiry = Date.now() + (ttlMs ?? this.defaultTtlMs);
    this.cache.set(key, { value, expiry });
  }

  /**
   * Check if a key exists and is not expired
   */
  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  /**
   * Delete a key from the cache
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  stats(): { size: number; maxSize: number } {
    return {
      size: this.cache.size,
      maxSize: this.cache.max,
    };
  }

  /**
   * Get or fetch a value, caching the result
   */
  async getOrFetch<T extends V>(
    key: string,
    fetcher: () => Promise<T>,
    ttlMs?: number
  ): Promise<T> {
    const cached = this.get(key);
    if (cached !== undefined) {
      return cached as T;
    }

    const value = await fetcher();
    this.set(key, value, ttlMs);
    return value;
  }
}

// Default instance for shared use
export const globalCache = new UnifiedCache();

export default UnifiedCache;
