export class FixedWindowRateLimiter {
  constructor({ limit, windowMs, backoffMs }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.backoffMs = backoffMs;
    this.buckets = new Map();
  }

  consume(key, now = Date.now()) {
    const current = this.buckets.get(key);
    if (current && current.penaltyUntil > now) {
      return { allowed: false, retryAfterMs: current.penaltyUntil - now };
    }

    if (!current || current.resetAt <= now) {
      this.buckets.set(key, {
        count: 1,
        resetAt: now + this.windowMs,
        penaltyUntil: 0
      });
      return { allowed: true, retryAfterMs: 0 };
    }

    if (current.count >= this.limit) {
      current.penaltyUntil = now + this.backoffMs;
      return { allowed: false, retryAfterMs: this.backoffMs };
    }

    current.count += 1;
    return { allowed: true, retryAfterMs: 0 };
  }

  cleanup(now = Date.now()) {
    for (const [key, entry] of this.buckets.entries()) {
      if (entry.resetAt <= now && entry.penaltyUntil <= now) {
        this.buckets.delete(key);
      }
    }
  }
}
