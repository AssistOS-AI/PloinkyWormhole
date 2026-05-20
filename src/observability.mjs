function ensureLimit(limit, fallback) {
  return Number.isInteger(limit) && limit > 0 ? limit : fallback;
}

function trimArray(array, limit) {
  while (array.length > limit) {
    array.shift();
  }
}

function statusBucket(statusCode) {
  const prefix = Math.floor(Number(statusCode || 0) / 100);
  return `${prefix || 0}xx`;
}

function evictOldest(map) {
  let oldestKey = null;
  let oldestAt = Infinity;
  for (const [key, value] of map.entries()) {
    if (value.last_seen_ms < oldestAt) {
      oldestAt = value.last_seen_ms;
      oldestKey = key;
    }
  }
  if (oldestKey) {
    map.delete(oldestKey);
  }
}

class RollingCounter {
  constructor(windowMs, bucketMs = 1000) {
    this.windowMs = windowMs;
    this.bucketMs = bucketMs;
    this.bucketCount = Math.max(1, Math.ceil(windowMs / bucketMs));
    this.buckets = Array.from({ length: this.bucketCount }, () => ({ slot: -1, value: 0 }));
  }

  add(now = Date.now(), amount = 1) {
    const slot = Math.floor(now / this.bucketMs);
    const index = slot % this.bucketCount;
    const bucket = this.buckets[index];
    if (bucket.slot !== slot) {
      bucket.slot = slot;
      bucket.value = 0;
    }
    bucket.value += amount;
  }

  total(now = Date.now()) {
    const cutoff = now - this.windowMs;
    let total = 0;
    for (const bucket of this.buckets) {
      if (bucket.slot < 0) {
        continue;
      }
      const bucketTime = bucket.slot * this.bucketMs;
      if (bucketTime > cutoff) {
        total += bucket.value;
      }
    }
    return total;
  }
}

export class ObservabilityStore {
  constructor(config) {
    this.startedAt = Date.now();
    this.eventLimit = ensureLimit(config.securityEventBufferSize, 500);
    this.maxTrackedOffenders = ensureLimit(config.maxTrackedOffenders, 2048);
    this.offenseDecayMs = config.offenseDecayMs;
    this.autoBlockThreshold = config.autoBlockThreshold;
    this.autoBlockTtlMs = config.autoBlockTtlMs;
    this.recentEvents = [];
    this.requestTotals = {
      total: 0,
      by_status: {
        '2xx': 0,
        '3xx': 0,
        '4xx': 0,
        '5xx': 0
      }
    };
    this.routeMetrics = new Map();
    this.offenders = new Map();
    this.autoBlocks = new Map();
    this.requestWindow = new RollingCounter(60_000);
    this.offenseWindow = new RollingCounter(60_000);
  }

  recordRequest({ method, route, statusCode, durationMs }) {
    const now = Date.now();
    const key = `${method.toUpperCase()} ${route}`;
    const bucket = statusBucket(statusCode);
    this.requestTotals.total += 1;
    this.requestTotals.by_status[bucket] += 1;
    this.requestWindow.add(now, 1);

    const current = this.routeMetrics.get(key) ?? {
      method: method.toUpperCase(),
      route,
      count: 0,
      by_status: {
        '2xx': 0,
        '3xx': 0,
        '4xx': 0,
        '5xx': 0
      },
      total_duration_ms: 0,
      max_duration_ms: 0,
      last_seen_at: null
    };

    current.count += 1;
    current.by_status[bucket] += 1;
    current.total_duration_ms += durationMs;
    current.max_duration_ms = Math.max(current.max_duration_ms, durationMs);
    current.last_seen_at = new Date(now).toISOString();
    this.routeMetrics.set(key, current);
  }

  recordSecurityEvent(event) {
    this.recentEvents.push({
      ...event,
      observed_at: event.observed_at ?? new Date().toISOString()
    });
    trimArray(this.recentEvents, this.eventLimit);
  }

  recordOffense({ requestId, ip, verifiedDid, route, reason, weight, statusCode, message }) {
    const now = Date.now();
    this.offenseWindow.add(now, weight);

    this.recordSecurityEvent({
      kind: 'offense',
      request_id: requestId,
      principal: ip ? { type: 'ip', value: ip } : null,
      verified_did: verifiedDid ?? null,
      route,
      reason,
      weight,
      status_code: statusCode,
      message
    });

    this.#applyOffense(now, 'ip', ip, reason, weight, route);
    if (verifiedDid) {
      this.#applyOffense(now, 'did', verifiedDid, reason, weight, route);
    }
  }

  #applyOffense(now, type, value, reason, weight, route) {
    if (!value) {
      return;
    }

    const key = `${type}:${value}`;
    const current = this.offenders.get(key) ?? {
      type,
      value,
      score: 0,
      event_count: 0,
      last_reason: null,
      last_route: null,
      last_seen_ms: 0
    };

    if (current.last_seen_ms && now - current.last_seen_ms > this.offenseDecayMs) {
      current.score = 0;
      current.event_count = 0;
    }

    current.score += weight;
    current.event_count += 1;
    current.last_reason = reason;
    current.last_route = route;
    current.last_seen_ms = now;
    this.offenders.set(key, current);

    if (this.offenders.size > this.maxTrackedOffenders) {
      evictOldest(this.offenders);
    }

    if (current.score >= this.autoBlockThreshold) {
      this.autoBlocks.set(key, {
        type,
        value,
        score: current.score,
        reason,
        created_at: new Date(now).toISOString(),
        expires_at: new Date(now + this.autoBlockTtlMs).toISOString()
      });
    }
  }

  isAutoBlocked(type, value, now = Date.now()) {
    if (!value) {
      return null;
    }
    const block = this.autoBlocks.get(`${type}:${value}`);
    if (!block) {
      return null;
    }
    if (new Date(block.expires_at).valueOf() <= now) {
      this.autoBlocks.delete(`${type}:${value}`);
      return null;
    }
    return block;
  }

  clearAutoBlock(type, value) {
    return this.autoBlocks.delete(`${type}:${value}`);
  }

  cleanup(now = Date.now()) {
    for (const [key, block] of this.autoBlocks.entries()) {
      if (new Date(block.expires_at).valueOf() <= now) {
        this.autoBlocks.delete(key);
      }
    }

    for (const [key, offender] of this.offenders.entries()) {
      if (now - offender.last_seen_ms > this.offenseDecayMs && !this.autoBlocks.has(key)) {
        this.offenders.delete(key);
      }
    }
  }

  attackLevel(now = Date.now()) {
    const recentOffenses = this.offenseWindow.total(now);
    const activeBlocks = this.autoBlocks.size;
    if (recentOffenses >= this.autoBlockThreshold * 2 || activeBlocks >= 3) {
      return 'under_attack';
    }
    if (recentOffenses >= this.autoBlockThreshold || activeBlocks >= 1) {
      return 'elevated';
    }
    return 'normal';
  }

  topOffenders(limit = 10) {
    return [...this.offenders.values()]
      .sort((left, right) => right.score - left.score || right.event_count - left.event_count)
      .slice(0, limit)
      .map((entry) => ({
        type: entry.type,
        value: entry.value,
        score: entry.score,
        event_count: entry.event_count,
        last_reason: entry.last_reason,
        last_route: entry.last_route,
        last_seen_at: new Date(entry.last_seen_ms).toISOString()
      }));
  }

  recentSecurityEvents(limit = this.eventLimit) {
    return this.recentEvents.slice(-limit).reverse();
  }

  metricsSnapshot({ didStates, queueSizes, replayCacheSize, relayCacheSize, blocklists }) {
    const now = Date.now();
    const routeMetrics = [...this.routeMetrics.values()]
      .sort((left, right) => right.count - left.count)
      .map((entry) => ({
        ...entry,
        avg_duration_ms: entry.count === 0 ? 0 : Math.round(entry.total_duration_ms / entry.count)
      }));

    return {
      uptime_ms: now - this.startedAt,
      attack_level: this.attackLevel(now),
      traffic_last_minute: this.requestWindow.total(now),
      offenses_last_minute: this.offenseWindow.total(now),
      requests: {
        total: this.requestTotals.total,
        by_status: this.requestTotals.by_status,
        routes: routeMetrics
      },
      did_states: didStates,
      queue_sizes: queueSizes,
      caches: {
        replay: replayCacheSize,
        relay: relayCacheSize
      },
      blocklists,
      auto_blocks: [...this.autoBlocks.values()].sort((left, right) => left.value.localeCompare(right.value)),
      top_offenders: this.topOffenders()
    };
  }
}
