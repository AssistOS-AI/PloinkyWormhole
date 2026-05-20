import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { createHttpError, assertDid, computeFingerprint, ensureStatus, parseDid } from './did.mjs';
import { canonicalSignaturePayload, buildReplayKey, ensureTimestampWithinSkew, verifySignature } from './signatures.mjs';
import { DidStateStore, requireDidState } from './storage.mjs';
import { FixedWindowRateLimiter } from './rate-limit.mjs';
import { limitsResponse } from './config.mjs';
import { AdminStateStore } from './admin-state.mjs';
import { ObservabilityStore } from './observability.mjs';

function normalizeIp(value) {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    return 'unknown';
  }
  if (normalized.startsWith('::ffff:')) {
    return normalized.slice(7);
  }
  return normalized;
}

function isLoopbackIp(ip) {
  return ip === '127.0.0.1' || ip === '::1';
}

function getClientIp(config, request) {
  const remoteIp = normalizeIp(request.socket.remoteAddress);
  if (!config.trustProxy) {
    return remoteIp;
  }

  const proxyTrusted = isLoopbackIp(remoteIp) || config.trustedProxyIps.has(remoteIp);
  if (!proxyTrusted) {
    return remoteIp;
  }

  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return normalizeIp(forwarded.split(',')[0]);
  }
  return remoteIp;
}

function routeLabel(method, pathname) {
  if (method === 'POST' && /^\/intent\/[^/]+\/seen$/.test(pathname)) {
    return '/intent/:intent_id/seen';
  }
  return pathname;
}

function applyBaseHeaders(response, requestId) {
  response.setHeader('x-request-id', requestId);
  response.setHeader('x-content-type-options', 'nosniff');
  response.setHeader('x-frame-options', 'DENY');
  response.setHeader('referrer-policy', 'no-referrer');
  response.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  response.setHeader('cross-origin-resource-policy', 'same-origin');
  response.setHeader('cache-control', 'no-store');
}

function json(response, statusCode, payload, requestId) {
  response.statusCode = statusCode;
  applyBaseHeaders(response, requestId);
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('content-security-policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  response.end(JSON.stringify(payload));
}

function html(response, statusCode, document, { requestId, nonce }) {
  response.statusCode = statusCode;
  applyBaseHeaders(response, requestId);
  response.setHeader('content-type', 'text/html; charset=utf-8');
  response.setHeader(
    'content-security-policy',
    `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; img-src 'self' data:; style-src 'unsafe-inline'; connect-src 'self'; script-src 'nonce-${nonce}'`
  );
  response.end(document);
}

async function readRawBody(request, maxBytes) {
  const chunks = [];
  let total = 0;

  for await (const chunk of request) {
    total += chunk.length;
    if (total > maxBytes) {
      throw createHttpError(413, 'Request body too large.', {
        offenseReason: 'oversized_body',
        offenseWeight: 3
      });
    }
    chunks.push(chunk);
  }

  return Buffer.concat(chunks).toString('utf8');
}

function parseJsonBody(rawBody) {
  if (!rawBody) {
    return {};
  }
  try {
    return JSON.parse(rawBody);
  } catch {
    throw createHttpError(400, 'Invalid JSON body.', {
      offenseReason: 'invalid_json',
      offenseWeight: 2
    });
  }
}

function toEpoch(dateString, fallbackMs) {
  if (!dateString) {
    return Date.now() + fallbackMs;
  }
  const value = new Date(dateString).valueOf();
  if (Number.isNaN(value)) {
    throw createHttpError(400, 'Invalid date format.', {
      offenseReason: 'invalid_date',
      offenseWeight: 1
    });
  }
  return value;
}

function requiresProtectedRead(pathname, method) {
  return (
    (pathname === '/intents' && method === 'GET') ||
    (pathname === '/intent-responses' && method === 'GET') ||
    (pathname === '/signals' && method === 'GET')
  );
}

function isLoopbackDomain(domain) {
  const lower = String(domain).toLowerCase();
  const host = lower.startsWith('[') ? lower.slice(1, lower.indexOf(']')) : lower.split(':')[0];
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

function buildRemoteBaseUrl(config, targetDomain) {
  const protocol = config.forwardProtocol;
  if (protocol !== 'https') {
    if (!config.allowInsecureForwarding || !isLoopbackDomain(targetDomain)) {
      throw createHttpError(500, 'Insecure forwarding protocol is not allowed.');
    }
  }
  return `${protocol}://${targetDomain}`;
}

async function forwardObject(config, targetDomain, path, body, incomingRelayId, incomingHop, headers = {}) {
  const relayId = incomingRelayId || randomUUID();
  const nextHop = incomingHop + 1;
  if (!Number.isInteger(nextHop) || nextHop < 0) {
    throw createHttpError(400, 'Invalid relay hop header.', {
      offenseReason: 'malformed_relay',
      offenseWeight: 4
    });
  }
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const response = await fetch(`${buildRemoteBaseUrl(config, targetDomain)}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-wormhole-relay-id': relayId,
      'x-wormhole-hop': String(nextHop),
      ...headers
    },
    body: raw
  });
  if (!response.ok) {
    const text = await response.text();
    throw createHttpError(502, `Forwarding failed: ${response.status} ${text}`);
  }
  return { relayId, hop: nextHop };
}

function signedForwardHeaders(request) {
  const keys = ['x-did', 'x-signature', 'x-timestamp', 'x-nonce'];
  const forwarded = {};
  for (const key of keys) {
    const value = request.headers[key];
    if (typeof value === 'string' && value) {
      forwarded[key] = value;
    }
  }
  return forwarded;
}

function ensureSizeLimit(value, maxBytes, field) {
  if (value === undefined || value === null) {
    return;
  }
  const bytes = Buffer.byteLength(typeof value === 'string' ? value : JSON.stringify(value), 'utf8');
  if (bytes > maxBytes) {
    throw createHttpError(413, `${field} exceeds max size.`, {
      offenseReason: `${field}_too_large`,
      offenseWeight: 3
    });
  }
}

function setIntentState(intent, state) {
  intent.state = state;
  intent.updated_at = new Date().toISOString();
}

function trimMap(map, maxEntries) {
  while (map.size >= maxEntries) {
    const oldestKey = map.keys().next().value;
    if (!oldestKey) {
      break;
    }
    map.delete(oldestKey);
  }
}

function toIntentStateFromResponse(responseValue) {
  if (responseValue === 'accept') return 'accepted';
  if (responseValue === 'reject') return 'rejected';
  return 'later';
}

function safeTokenEquals(expected, provided) {
  if (typeof expected !== 'string' || !expected || typeof provided !== 'string') {
    return false;
  }
  const expectedBytes = Buffer.from(expected, 'utf8');
  const providedBytes = Buffer.from(provided, 'utf8');
  if (expectedBytes.length !== providedBytes.length) {
    return false;
  }
  return timingSafeEqual(expectedBytes, providedBytes);
}

function validateBlocklistValue(type, value) {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw createHttpError(400, 'Blocklist value is required.');
  }
  if (type === 'did') {
    assertDid(normalized, 'value');
  }
  if (type === 'ip') {
    return normalizeIp(normalized);
  }
  return normalized;
}

function buildDashboardDocument(nonce) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ploinky Wormhole Admin Dashboard</title>
  <style>
    :root { color-scheme: light; font-family: Inter, Segoe UI, Roboto, Arial, sans-serif; line-height: 1.45; }
    body { margin: 0; padding: 1.5rem; background: #0f172a; color: #e2e8f0; }
    h1, h2 { margin-top: 0; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; }
    .panel { background: #111827; border: 1px solid #334155; border-radius: 10px; padding: 1rem; }
    label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
    input, select, button, textarea { width: 100%; box-sizing: border-box; margin-top: 0.25rem; padding: 0.6rem; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: inherit; }
    button { cursor: pointer; background: #2563eb; border-color: #2563eb; font-weight: 700; }
    button.secondary { background: #1f2937; border-color: #475569; }
    pre { white-space: pre-wrap; word-break: break-word; background: #020617; padding: 0.8rem; border-radius: 8px; min-height: 180px; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
    .summary { font-size: 1.05rem; font-weight: 700; }
  </style>
</head>
<body>
  <h1>Ploinky Wormhole Admin Dashboard</h1>
  <div class="grid">
    <section class="panel">
      <label>Admin token
        <input id="token" type="password" autocomplete="off" placeholder="Paste x-admin-token">
      </label>
      <button id="load">Load dashboard</button>
      <p id="status" class="summary">Token required to load admin data.</p>
    </section>
    <section class="panel">
      <h2>Manual blocklist</h2>
      <div class="row">
        <label>Type
          <select id="block-type">
            <option value="ip">IP</option>
            <option value="did">DID</option>
            <option value="domain">Domain</option>
          </select>
        </label>
        <label>Value
          <input id="block-value" type="text" autocomplete="off">
        </label>
      </div>
      <label>Reason
        <textarea id="block-reason" rows="2" placeholder="Operational note"></textarea>
      </label>
      <div class="row">
        <button id="block-add">Add block</button>
        <button id="block-remove" class="secondary">Remove block</button>
      </div>
    </section>
  </div>
  <div class="grid" style="margin-top: 1rem;">
    <section class="panel"><h2>Metrics</h2><pre id="metrics">No data loaded yet.</pre></section>
    <section class="panel"><h2>Events</h2><pre id="events">No data loaded yet.</pre></section>
    <section class="panel"><h2>Blocklists</h2><pre id="blocklists">No data loaded yet.</pre></section>
  </div>
  <script nonce="${nonce}">
    const statusEl = document.getElementById('status');
    const tokenEl = document.getElementById('token');
    const metricsEl = document.getElementById('metrics');
    const eventsEl = document.getElementById('events');
    const blocklistsEl = document.getElementById('blocklists');

    function adminFetch(path, options = {}) {
      const token = tokenEl.value.trim();
      return fetch(path, {
        ...options,
        headers: {
          'content-type': 'application/json',
          'x-admin-token': token,
          ...(options.headers || {})
        }
      });
    }

    async function refresh() {
      const token = tokenEl.value.trim();
      if (!token) {
        statusEl.textContent = 'Enter the admin token first.';
        return;
      }
      statusEl.textContent = 'Loading...';
      const [metrics, events, blocklists] = await Promise.all([
        adminFetch('/admin/metrics'),
        adminFetch('/admin/events?limit=25'),
        adminFetch('/admin/blocklist')
      ]);
      if (!metrics.ok || !events.ok || !blocklists.ok) {
        const payload = await metrics.json().catch(() => ({ error: 'Unable to load dashboard.' }));
        statusEl.textContent = payload.error || 'Unable to load dashboard.';
        return;
      }
      const metricsPayload = await metrics.json();
      const eventsPayload = await events.json();
      const blocklistPayload = await blocklists.json();
      statusEl.textContent = 'Dashboard loaded.';
      metricsEl.textContent = JSON.stringify(metricsPayload, null, 2);
      eventsEl.textContent = JSON.stringify(eventsPayload, null, 2);
      blocklistsEl.textContent = JSON.stringify(blocklistPayload, null, 2);
    }

    async function mutate(method) {
      const body = JSON.stringify({
        type: document.getElementById('block-type').value,
        value: document.getElementById('block-value').value,
        reason: document.getElementById('block-reason').value
      });
      const response = await adminFetch('/admin/blocklist', { method, body });
      const payload = await response.json().catch(() => ({ error: 'Unknown response.' }));
      statusEl.textContent = response.ok ? payload.status || 'Updated.' : payload.error || 'Operation failed.';
      if (response.ok) {
        await refresh();
      }
    }

    document.getElementById('load').addEventListener('click', refresh);
    document.getElementById('block-add').addEventListener('click', () => mutate('POST'));
    document.getElementById('block-remove').addEventListener('click', () => mutate('DELETE'));
  </script>
</body>
</html>`;
}

function readinessChecks(config) {
  const checks = [
    {
      name: 'bootstrap_token_strength',
      ok: config.bootstrapToken !== 'wormhole-bootstrap-token' && String(config.bootstrapToken || '').length >= 32,
      message: 'Set a non-default bootstrap token with at least 32 characters before production.'
    },
    {
      name: 'admin_token_strength',
      ok: String(config.adminToken || '').length >= 32,
      message: 'Configure an admin token with at least 32 characters for recovery and admin APIs.'
    },
    {
      name: 'forwarding_tls',
      ok: config.forwardProtocol === 'https' && !config.allowInsecureForwarding,
      message: 'Keep forwarding on HTTPS only and disable insecure forwarding in production.'
    },
    {
      name: 'trusted_proxy_mode',
      ok: !config.trustProxy || config.trustedProxyIps.size > 0 || isLoopbackDomain(config.host),
      message: 'When trust proxy mode is enabled, define trusted proxy IPs or keep the runtime loopback-bound.'
    },
    {
      name: 'request_timeouts',
      ok: config.requestTimeoutMs > 0 && config.headersTimeoutMs > 0 && config.keepAliveTimeoutMs > 0,
      message: 'Request, header, and keep-alive timeouts must remain enabled.'
    },
    {
      name: 'auto_blocking',
      ok: config.autoBlockThreshold > 0 && config.autoBlockTtlMs > 0,
      message: 'Automated blocking must remain enabled to slow repeated abuse.'
    }
  ];

  return {
    status: checks.every((check) => check.ok) ? 'ready' : 'degraded',
    warnings: checks.filter((check) => !check.ok).map((check) => check.message),
    checks
  };
}

function classifyOffense(error) {
  if (!error || error.skipOffense) {
    return null;
  }
  if (error.offenseReason) {
    return {
      reason: error.offenseReason,
      weight: error.offenseWeight ?? 1
    };
  }

  if (error.statusCode === 429) {
    return { reason: 'rate_limit_exceeded', weight: 4 };
  }
  if (error.statusCode === 409) {
    return { reason: 'replay_detected', weight: 5 };
  }
  if (error.statusCode === 413) {
    return { reason: 'oversized_body', weight: 3 };
  }
  if (error.statusCode === 401) {
    return { reason: 'authentication_failed', weight: 4 };
  }
  if (error.statusCode === 400) {
    return { reason: 'invalid_request', weight: 1 };
  }
  return null;
}

function countSignals(signals) {
  let total = 0;
  for (const byIntent of signals.values()) {
    for (const queue of byIntent.values()) {
      total += queue.length;
    }
  }
  return total;
}

function countNestedMaps(collection) {
  let total = 0;
  for (const bucket of collection.values()) {
    total += bucket.size;
  }
  return total;
}

function buildBlocklistSnapshot(config, adminState, observability) {
  const manual = adminState.snapshot();
  const autoBlocks = [...observability.autoBlocks.values()];
  const auto = {
    blocked_ips: autoBlocks.filter((entry) => entry.type === 'ip'),
    blocked_dids: autoBlocks.filter((entry) => entry.type === 'did')
  };

  return {
    configured: {
      blocked_ips: [...config.blocklistIps].sort(),
      blocked_dids: [...config.blocklistDids].sort(),
      blocked_domains: [...config.blocklistDomains].sort()
    },
    manual,
    auto,
    effective_counts: {
      ips: new Set([
        ...config.blocklistIps,
        ...manual.manual_blocked_ips.map((entry) => entry.value),
        ...auto.blocked_ips.map((entry) => entry.value)
      ]).size,
      dids: new Set([
        ...config.blocklistDids,
        ...manual.manual_blocked_dids.map((entry) => entry.value),
        ...auto.blocked_dids.map((entry) => entry.value)
      ]).size,
      domains: new Set([
        ...config.blocklistDomains,
        ...manual.manual_blocked_domains.map((entry) => entry.value)
      ]).size
    }
  };
}

function matchBlock(config, adminState, observability, ip, fromDid, toDid) {
  const now = Date.now();

  const autoIp = observability.isAutoBlocked('ip', ip, now);
  if (autoIp) {
    return { source: 'auto', type: 'ip', value: ip, record: autoIp };
  }
  if (config.blocklistIps.has(ip)) {
    return { source: 'configured', type: 'ip', value: ip };
  }
  if (adminState.has('ip', ip)) {
    return { source: 'manual', type: 'ip', value: ip, record: adminState.get('ip', ip) };
  }

  if (fromDid) {
    const autoDid = observability.isAutoBlocked('did', fromDid, now);
    if (autoDid) {
      return { source: 'auto', type: 'did', value: fromDid, record: autoDid };
    }
  }

  for (const did of [fromDid, toDid]) {
    if (!did) {
      continue;
    }
    if (config.blocklistDids.has(did)) {
      return { source: 'configured', type: 'did', value: did };
    }
    if (adminState.has('did', did)) {
      return { source: 'manual', type: 'did', value: did, record: adminState.get('did', did) };
    }
  }

  const domains = new Set();
  for (const did of [fromDid, toDid]) {
    const parsed = did ? parseDid(did) : null;
    if (parsed?.domain) {
      domains.add(parsed.domain);
    }
  }
  for (const domain of domains) {
    if (config.blocklistDomains.has(domain)) {
      return { source: 'configured', type: 'domain', value: domain };
    }
    if (adminState.has('domain', domain)) {
      return { source: 'manual', type: 'domain', value: domain, record: adminState.get('domain', domain) };
    }
  }

  return null;
}

function ensureNotBlocked(config, adminState, observability, ip, fromDid, toDid) {
  const blocked = matchBlock(config, adminState, observability, ip, fromDid, toDid);
  if (blocked) {
    throw createHttpError(403, `${blocked.type} is blocked.`, {
      skipOffense: true,
      blocked
    });
  }
}

function ensureLocalDidSubmission(config, didData, isForwarded, label = 'from_did') {
  if (!isForwarded && didData.domain !== config.serverDomain) {
    throw createHttpError(400, `${label} does not belong to this server domain.`, {
      offenseReason: 'nonlocal_submission',
      offenseWeight: 2
    });
  }
}

export async function createApp(config) {
  const didStore = new DidStateStore(config.didStateFile);
  const adminState = new AdminStateStore(config.adminStateFile);
  await Promise.all([didStore.load(), adminState.load()]);

  const intents = new Map();
  const intentStatusById = new Map();
  const intentResponses = new Map();
  const signals = new Map();
  const replayCache = new Map();
  const relayCache = new Map();
  const observability = new ObservabilityStore(config);

  const ipLimiter = new FixedWindowRateLimiter({
    limit: config.ratePerIp,
    windowMs: config.rateWindowMs,
    backoffMs: config.rateBackoffMs
  });
  const fromDidLimiter = new FixedWindowRateLimiter({
    limit: config.ratePerFromDid,
    windowMs: config.rateWindowMs,
    backoffMs: config.rateBackoffMs
  });
  const toDidLimiter = new FixedWindowRateLimiter({
    limit: config.ratePerToDid,
    windowMs: config.rateWindowMs,
    backoffMs: config.rateBackoffMs
  });

  function consumeRate(limiter, response, key, label) {
    if (!key) {
      return;
    }
    const result = limiter.consume(key);
    if (result.allowed) {
      return;
    }
    response.setHeader('retry-after', String(Math.ceil(result.retryAfterMs / 1000)));
    throw createHttpError(429, `Rate limit exceeded for ${label}.`, {
      offenseReason: 'rate_limit_exceeded',
      offenseWeight: 4
    });
  }

  async function loadDidStateForVerification(did) {
    const local = didStore.get(did);
    if (local) {
      return local;
    }
    const didData = assertDid(did, 'did');
    if (didData.domain === config.serverDomain) {
      throw createHttpError(404, 'DID state not found.');
    }
    let response;
    try {
      response = await fetch(
        `${buildRemoteBaseUrl(config, didData.domain)}/did-state?did=${encodeURIComponent(did)}`
      );
    } catch {
      throw createHttpError(401, 'Could not resolve DID state for signature verification.');
    }
    if (!response.ok) {
      throw createHttpError(401, 'Could not resolve DID state for signature verification.');
    }
    let remoteState;
    try {
      remoteState = await response.json();
    } catch {
      throw createHttpError(401, 'Could not resolve DID state for signature verification.');
    }
    if (!remoteState?.current_public_key || typeof remoteState.current_public_key !== 'string') {
      throw createHttpError(401, 'Resolved DID state is invalid.');
    }
    return remoteState;
  }

  async function verifyDidSignedRequest(request, rawBody, targetDid, context) {
    const did = request.headers['x-did'];
    const signature = request.headers['x-signature'];
    const timestamp = request.headers['x-timestamp'];
    const nonce = request.headers['x-nonce'] || '';

    if (!did || !signature || !timestamp) {
      throw createHttpError(401, 'Missing DID signature headers.', {
        offenseReason: 'missing_signature_headers',
        offenseWeight: 3
      });
    }
    if (did !== targetDid) {
      throw createHttpError(403, 'Signed DID does not match requested DID.');
    }

    ensureTimestampWithinSkew(timestamp, config.signatureSkewMs);
    const state = await loadDidStateForVerification(did);
    if (state.status !== 'active') {
      throw createHttpError(403, 'DID is not active.');
    }
    const payload = canonicalSignaturePayload({
      method: request.method,
      pathWithQuery: request.url,
      timestamp,
      nonce,
      bodyRaw: rawBody
    });
    const replayKey = buildReplayKey(did, signature);
    if (replayCache.has(replayKey)) {
      throw createHttpError(409, 'Replay detected.', {
        offenseReason: 'replay_detected',
        offenseWeight: 5
      });
    }

    const ok = verifySignature(state.current_public_key, payload, signature);
    if (!ok) {
      throw createHttpError(401, 'Invalid DID signature.', {
        offenseReason: 'invalid_signature',
        offenseWeight: 5
      });
    }

    trimMap(replayCache, config.maxReplayEntries);
    replayCache.set(replayKey, Date.now() + config.replayWindowMs);
    context.verifiedDid = did;
    return state;
  }

  function queueSizes() {
    return {
      intents_visible: countNestedMaps(intents),
      intent_status_records: intentStatusById.size,
      responses: countNestedMaps(intentResponses),
      signals: countSignals(signals)
    };
  }

  function cleanup() {
    const now = Date.now();

    for (const [key, until] of replayCache.entries()) {
      if (until <= now) replayCache.delete(key);
    }
    for (const [key, until] of relayCache.entries()) {
      if (until <= now) relayCache.delete(key);
    }
    observability.cleanup(now);
    ipLimiter.cleanup(now);
    fromDidLimiter.cleanup(now);
    toDidLimiter.cleanup(now);

    for (const [toDid, byId] of intents.entries()) {
      for (const [intentId, intent] of byId.entries()) {
        if (new Date(intent.expires_at).valueOf() <= now) {
          setIntentState(intent, 'expired');
          byId.delete(intentId);
        }
      }
      if (byId.size === 0) intents.delete(toDid);
    }

    for (const [intentId, intent] of intentStatusById.entries()) {
      if (new Date(intent.expires_at).valueOf() <= now) {
        setIntentState(intent, 'expired');
        intentStatusById.delete(intentId);
      }
    }

    for (const [toDid, byIntent] of intentResponses.entries()) {
      for (const [intentId, response] of byIntent.entries()) {
        if (new Date(response.expires_at).valueOf() <= now) byIntent.delete(intentId);
      }
      if (byIntent.size === 0) intentResponses.delete(toDid);
    }

    for (const [toDid, byIntent] of signals.entries()) {
      for (const [intentId, list] of byIntent.entries()) {
        byIntent.set(
          intentId,
          list.filter((signal) => new Date(signal.expires_at).valueOf() > now)
        );
        if (byIntent.get(intentId).length === 0) byIntent.delete(intentId);
      }
      if (byIntent.size === 0) signals.delete(toDid);
    }
  }

  const cleanupHandle = setInterval(cleanup, config.cleanupIntervalMs);
  cleanupHandle.unref();

  function close() {
    clearInterval(cleanupHandle);
  }

  function removeVisibleIntent(intentId, toDid) {
    const bucket = intents.get(toDid);
    if (!bucket) {
      return;
    }
    bucket.delete(intentId);
    if (bucket.size === 0) {
      intents.delete(toDid);
    }
  }

  function requireAdminAccess(request) {
    if (!config.adminToken) {
      throw createHttpError(503, 'Admin endpoints are disabled.');
    }
    if (!safeTokenEquals(config.adminToken, request.headers['x-admin-token'])) {
      throw createHttpError(401, 'Admin token required.', {
        offenseReason: 'admin_auth_failed',
        offenseWeight: 2
      });
    }
  }

  async function handler(request, response) {
    const startedAt = Date.now();
    const requestId = typeof request.headers['x-request-id'] === 'string' && request.headers['x-request-id']
      ? request.headers['x-request-id']
      : randomUUID();
    let route = request.url || '/';
    const context = {
      requestId,
      ip: normalizeIp(request.socket.remoteAddress),
      route,
      verifiedDid: null,
      fromDid: null,
      toDid: null
    };

    try {
      const rawBody = await readRawBody(request, config.maxBodyBytes);
      const body = parseJsonBody(rawBody);
      const url = new URL(request.url, 'http://localhost');
      route = routeLabel(request.method, url.pathname);
      context.route = route;
      context.ip = getClientIp(config, request);

      consumeRate(ipLimiter, response, context.ip, 'ip');

      const relayId = request.headers['x-wormhole-relay-id'] || '';
      const hopHeader = request.headers['x-wormhole-hop'];
      const hasHopHeader = hopHeader !== undefined && hopHeader !== null && String(hopHeader).length > 0;
      const hop = hasHopHeader ? Number(hopHeader) : 0;
      if (hasHopHeader && (!Number.isInteger(hop) || hop < 0)) {
        throw createHttpError(400, 'Invalid relay hop header.', {
          offenseReason: 'malformed_relay',
          offenseWeight: 4
        });
      }
      if (hop > config.maxRelayHops) {
        throw createHttpError(508, 'Relay hop limit exceeded.', {
          offenseReason: 'relay_hop_exceeded',
          offenseWeight: 4
        });
      }
      if (relayId) {
        if (relayCache.has(relayId)) {
          json(response, 202, { status: 'duplicate', relay_id: relayId }, requestId);
          return;
        }
        trimMap(relayCache, config.maxRelayEntries);
        relayCache.set(relayId, Date.now() + config.relayCacheTtlMs);
      }
      const isForwarded = relayId.length > 0 || hop > 0;

      if (request.method === 'GET' && url.pathname === '/health') {
        json(
          response,
          200,
          {
            status: 'ok',
            server_domain: config.serverDomain,
            did_states: didStore.states.size,
            uptime_ms: Date.now() - observability.startedAt,
            attack_level: observability.attackLevel()
          },
          requestId
        );
        return;
      }

      if (request.method === 'GET' && url.pathname === '/ready') {
        const readiness = readinessChecks(config);
        json(
          response,
          readiness.status === 'ready' ? 200 : 503,
          readiness,
          requestId
        );
        return;
      }

      if (request.method === 'GET' && url.pathname === '/limits') {
        json(response, 200, limitsResponse(config), requestId);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/admin/dashboard') {
        const nonce = randomBytes(12).toString('base64');
        html(response, 200, buildDashboardDocument(nonce), { requestId, nonce });
        return;
      }

      if (request.method === 'GET' && url.pathname === '/admin/metrics') {
        requireAdminAccess(request);
        json(
          response,
          200,
          {
            readiness: readinessChecks(config),
            metrics: observability.metricsSnapshot({
              didStates: didStore.states.size,
              queueSizes: queueSizes(),
              replayCacheSize: replayCache.size,
              relayCacheSize: relayCache.size,
              blocklists: buildBlocklistSnapshot(config, adminState, observability)
            })
          },
          requestId
        );
        return;
      }

      if (request.method === 'GET' && url.pathname === '/admin/events') {
        requireAdminAccess(request);
        const limit = Number(url.searchParams.get('limit') || '50');
        json(response, 200, { events: observability.recentSecurityEvents(Math.max(1, Math.min(limit, 200))) }, requestId);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/admin/blocklist') {
        requireAdminAccess(request);
        json(response, 200, buildBlocklistSnapshot(config, adminState, observability), requestId);
        return;
      }

      if ((request.method === 'POST' || request.method === 'DELETE') && url.pathname === '/admin/blocklist') {
        requireAdminAccess(request);
        const allowedTypes = new Set(['ip', 'did', 'domain']);
        if (!allowedTypes.has(body.type)) {
          throw createHttpError(400, 'Invalid blocklist type.');
        }
        const value = validateBlocklistValue(body.type, body.value);
        if (request.method === 'POST') {
          const record = await adminState.upsert(body.type, value, String(body.reason ?? '').trim());
          observability.recordSecurityEvent({
            kind: 'manual_block_added',
            request_id: requestId,
            principal: { type: body.type, value },
            message: 'Manual blocklist entry added.'
          });
          json(response, 201, { status: 'blocked', record }, requestId);
          return;
        }

        const removedManual = await adminState.remove(body.type, value);
        const removedAuto = observability.clearAutoBlock(body.type, value);
        if (!removedManual && !removedAuto) {
          throw createHttpError(404, 'Blocklist entry not found.');
        }
        observability.recordSecurityEvent({
          kind: 'manual_block_removed',
          request_id: requestId,
          principal: { type: body.type, value },
          message: 'Blocklist entry removed.'
        });
        json(response, 200, { status: 'unblocked', removed_manual: removedManual, removed_auto: removedAuto }, requestId);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/did-state') {
        const did = url.searchParams.get('did');
        assertDid(did, 'did');
        const state = requireDidState(didStore, did);
        json(response, 200, state, requestId);
        return;
      }

      if (request.method === 'PUT' && url.pathname === '/did-state') {
        const did = assertDid(body.did, 'did');
        context.fromDid = did.did;
        if (did.domain !== config.serverDomain) {
          throw createHttpError(400, 'DID domain does not belong to this server.');
        }
        const nextStatus = ensureStatus(body.status);
        const nowIso = new Date().toISOString();
        const existing = didStore.get(did.did);
        if (!body.current_public_key || typeof body.current_public_key !== 'string') {
          throw createHttpError(400, 'current_public_key is required.');
        }

        if (!existing) {
          if (!config.bootstrapToken || !safeTokenEquals(config.bootstrapToken, request.headers['x-bootstrap-token'])) {
            throw createHttpError(401, 'Bootstrap token required for first publish.');
          }
          const fingerprint = computeFingerprint(body.current_public_key);
          if (did.keyFingerprint && did.keyFingerprint !== fingerprint) {
            throw createHttpError(400, 'DID fingerprint does not match current_public_key.');
          }
          const created = {
            did: did.did,
            did_identifier: did.didIdentifier,
            current_public_key: body.current_public_key,
            current_fingerprint: fingerprint,
            status: nextStatus,
            updated_at: nowIso,
            key_history: [
              {
                public_key: body.current_public_key,
                fingerprint,
                valid_from: nowIso,
                valid_until: null,
                rotation_proof: body.rotation_proof ?? null
              }
            ]
          };
          await didStore.upsert(created);
          json(response, 201, created, requestId);
          return;
        }

        const isAdminRecovery =
          config.adminToken &&
          safeTokenEquals(config.adminToken, request.headers['x-admin-token']);

        if (!isAdminRecovery) {
          await verifyDidSignedRequest(request, rawBody, did.did, context);
        }

        const fingerprint = computeFingerprint(body.current_public_key);
        if (did.keyFingerprint && did.keyFingerprint !== fingerprint) {
          throw createHttpError(400, 'DID fingerprint does not match current_public_key.');
        }
        const updated = { ...existing };
        updated.status = nextStatus;
        updated.updated_at = nowIso;
        if (existing.current_fingerprint !== fingerprint) {
          updated.current_public_key = body.current_public_key;
          updated.current_fingerprint = fingerprint;
          updated.key_history = [...existing.key_history];
          const previous = updated.key_history.at(-1);
          if (previous && !previous.valid_until) {
            previous.valid_until = nowIso;
          }
          updated.key_history.push({
            public_key: body.current_public_key,
            fingerprint,
            valid_from: nowIso,
            valid_until: null,
            rotation_proof: body.rotation_proof ?? null
          });
        }
        await didStore.upsert(updated);
        json(response, 200, updated, requestId);
        return;
      }

      if (request.method === 'POST' && url.pathname === '/intent') {
        const fromDidData = assertDid(body.from_did, 'from_did');
        const fromDid = fromDidData.did;
        const toDidData = assertDid(body.to_did, 'to_did');
        const toDid = toDidData.did;
        context.fromDid = fromDid;
        context.toDid = toDid;
        const expiresAt = toEpoch(body.expires_at, config.intentTtlMs);
        if (expiresAt - Date.now() > config.intentTtlMs) {
          throw createHttpError(400, 'Intent expiry exceeds max TTL.', {
            offenseReason: 'ttl_exceeded',
            offenseWeight: 1
          });
        }
        if (expiresAt <= Date.now()) {
          throw createHttpError(400, 'Intent is already expired.', {
            offenseReason: 'expired_payload',
            offenseWeight: 1
          });
        }

        ensureLocalDidSubmission(config, fromDidData, isForwarded);
        ensureNotBlocked(config, adminState, observability, context.ip, fromDid, toDid);
        consumeRate(fromDidLimiter, response, fromDid, 'from_did');
        consumeRate(toDidLimiter, response, toDid, 'to_did');
        ensureSizeLimit(body.agent_envelope, config.maxIntentEnvelopeBytes, 'agent_envelope');

        const intent = {
          intent_id: body.intent_id || randomUUID(),
          from_did: fromDid,
          to_did: toDid,
          created_at: body.created_at || new Date().toISOString(),
          expires_at: new Date(expiresAt).toISOString(),
          nonce: body.nonce || randomUUID(),
          agent_envelope: body.agent_envelope ?? null,
          state: 'available',
          updated_at: new Date().toISOString()
        };

        if (toDidData.domain !== config.serverDomain) {
          try {
            await forwardObject(config, toDidData.domain, '/intent', intent, relayId, hop);
          } catch (error) {
            intent.state = 'failed';
            intent.updated_at = new Date().toISOString();
            throw error;
          }
          json(response, 202, { status: 'forwarded', intent_id: intent.intent_id }, requestId);
          return;
        }

        if (!intents.has(toDid)) intents.set(toDid, new Map());
        intents.get(toDid).set(intent.intent_id, intent);
        intentStatusById.set(intent.intent_id, intent);
        json(response, 202, { status: 'accepted', intent_id: intent.intent_id }, requestId);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/intents') {
        const toDid = assertDid(url.searchParams.get('to_did'), 'to_did').did;
        context.toDid = toDid;
        await verifyDidSignedRequest(request, rawBody, toDid, context);
        const entries = [...(intents.get(toDid)?.values() ?? [])].filter(
          (intent) => intent.state === 'available' || intent.state === 'seen'
        );
        json(response, 200, { to_did: toDid, intents: entries }, requestId);
        return;
      }

      if (request.method === 'POST' && /^\/intent\/[^/]+\/seen$/.test(url.pathname)) {
        const intentId = decodeURIComponent(url.pathname.split('/')[2]);
        const toDid = assertDid(body.to_did, 'to_did').did;
        context.toDid = toDid;
        await verifyDidSignedRequest(request, rawBody, toDid, context);

        const bucket = intents.get(toDid);
        const intent = bucket?.get(intentId);
        if (!intent) {
          throw createHttpError(404, 'Intent not found.');
        }
        if (intent.state === 'available') {
          setIntentState(intent, 'seen');
          if (intentStatusById.has(intentId)) {
            setIntentState(intentStatusById.get(intentId), 'seen');
          }
        }
        json(response, 200, { status: 'seen', intent_id: intentId }, requestId);
        return;
      }

      if (request.method === 'POST' && url.pathname === '/intent-response') {
        const allowedResponses = new Set(['accept', 'reject', 'later']);
        if (!allowedResponses.has(body.response)) {
          throw createHttpError(400, 'Invalid response value.');
        }
        if (!body.intent_id) {
          throw createHttpError(400, 'intent_id is required.');
        }

        const fromDidData = assertDid(body.from_did, 'from_did');
        const fromDid = fromDidData.did;
        const toDidData = assertDid(body.to_did, 'to_did');
        const toDid = toDidData.did;
        context.fromDid = fromDid;
        context.toDid = toDid;

        ensureLocalDidSubmission(config, fromDidData, isForwarded);
        ensureNotBlocked(config, adminState, observability, context.ip, fromDid, toDid);

        let localIntent = null;
        if (fromDidData.domain === config.serverDomain) {
          localIntent = intentStatusById.get(body.intent_id);
          if (!localIntent) {
            throw createHttpError(404, 'Intent not found.');
          }
          if (localIntent.to_did !== fromDid || localIntent.from_did !== toDid) {
            throw createHttpError(403, 'Intent participants do not match response payload.');
          }
          if (localIntent.state !== 'available' && localIntent.state !== 'seen') {
            throw createHttpError(409, 'Intent is not awaiting a response.');
          }
        }

        await verifyDidSignedRequest(request, rawBody, fromDid, context);
        consumeRate(fromDidLimiter, response, fromDid, 'from_did');
        consumeRate(toDidLimiter, response, toDid, 'to_did');
        ensureSizeLimit(body.agent_envelope, config.maxIntentEnvelopeBytes, 'agent_envelope');

        const expiresAt = toEpoch(body.expires_at, config.responseTtlMs);
        if (expiresAt - Date.now() > config.responseTtlMs) {
          throw createHttpError(400, 'Response expiry exceeds max TTL.', {
            offenseReason: 'ttl_exceeded',
            offenseWeight: 1
          });
        }
        if (expiresAt <= Date.now()) {
          throw createHttpError(400, 'Response is already expired.', {
            offenseReason: 'expired_payload',
            offenseWeight: 1
          });
        }

        const responsePayload = {
          intent_id: body.intent_id,
          from_did: fromDid,
          to_did: toDid,
          response: body.response,
          created_at: body.created_at || new Date().toISOString(),
          expires_at: new Date(expiresAt).toISOString(),
          agent_envelope: body.agent_envelope ?? null
        };

        if (toDidData.domain !== config.serverDomain) {
          await forwardObject(
            config,
            toDidData.domain,
            '/intent-response',
            rawBody,
            relayId,
            hop,
            signedForwardHeaders(request)
          );
        } else {
          if (!intentResponses.has(toDid)) intentResponses.set(toDid, new Map());
          intentResponses.get(toDid).set(responsePayload.intent_id, responsePayload);
        }

        if (localIntent) {
          const nextState = toIntentStateFromResponse(responsePayload.response);
          setIntentState(localIntent, nextState);
          removeVisibleIntent(responsePayload.intent_id, fromDid);
        }

        json(
          response,
          202,
          { status: toDidData.domain === config.serverDomain ? 'accepted' : 'forwarded', intent_id: responsePayload.intent_id },
          requestId
        );
        return;
      }

      if (request.method === 'GET' && url.pathname === '/intent-responses') {
        const toDid = assertDid(url.searchParams.get('to_did'), 'to_did').did;
        context.toDid = toDid;
        await verifyDidSignedRequest(request, rawBody, toDid, context);
        const entries = [...(intentResponses.get(toDid)?.values() ?? [])];
        json(response, 200, { to_did: toDid, responses: entries }, requestId);
        return;
      }

      if (request.method === 'POST' && url.pathname === '/signal') {
        const fromDidData = assertDid(body.from_did, 'from_did');
        const fromDid = fromDidData.did;
        const toDidData = assertDid(body.to_did, 'to_did');
        const toDid = toDidData.did;
        context.fromDid = fromDid;
        context.toDid = toDid;
        ensureLocalDidSubmission(config, fromDidData, isForwarded);
        ensureNotBlocked(config, adminState, observability, context.ip, fromDid, toDid);
        await verifyDidSignedRequest(request, rawBody, fromDid, context);
        consumeRate(fromDidLimiter, response, fromDid, 'from_did');
        consumeRate(toDidLimiter, response, toDid, 'to_did');
        ensureSizeLimit(body.payload, config.maxSignalPayloadBytes, 'payload');
        if (!body.intent_id) {
          throw createHttpError(400, 'intent_id is required.');
        }
        const allowedSignalTypes = new Set(['offer', 'answer', 'ice_candidate']);
        if (!allowedSignalTypes.has(body.signal_type)) {
          throw createHttpError(400, 'Invalid signal_type.');
        }

        const localIntent = intentStatusById.get(body.intent_id) ?? null;
        if (localIntent) {
          if (localIntent.from_did !== fromDid || localIntent.to_did !== toDid) {
            throw createHttpError(403, 'Intent participants do not match signaling payload.');
          }
          if (localIntent.state !== 'accepted') {
            throw createHttpError(409, 'Intent must be accepted before signaling.', {
              offenseReason: 'signal_before_accept',
              offenseWeight: 3
            });
          }
        } else if (toDidData.domain === config.serverDomain) {
          throw createHttpError(404, 'Intent not found.');
        }

        const expiresAt = toEpoch(body.expires_at, config.signalTtlMs);
        if (expiresAt - Date.now() > config.signalTtlMs) {
          throw createHttpError(400, 'Signal expiry exceeds max TTL.', {
            offenseReason: 'ttl_exceeded',
            offenseWeight: 1
          });
        }
        if (expiresAt <= Date.now()) {
          throw createHttpError(400, 'Signal is already expired.', {
            offenseReason: 'expired_payload',
            offenseWeight: 1
          });
        }
        const signal = {
          intent_id: body.intent_id,
          from_did: fromDid,
          to_did: toDid,
          signal_type: body.signal_type,
          payload: body.payload,
          created_at: body.created_at || new Date().toISOString(),
          expires_at: new Date(expiresAt).toISOString()
        };

        if (toDidData.domain !== config.serverDomain) {
          await forwardObject(config, toDidData.domain, '/signal', rawBody, relayId, hop, signedForwardHeaders(request));
          json(response, 202, { status: 'forwarded' }, requestId);
          return;
        }

        if (!signals.has(toDid)) signals.set(toDid, new Map());
        if (!signals.get(toDid).has(signal.intent_id)) {
          signals.get(toDid).set(signal.intent_id, []);
        }
        const queue = signals.get(toDid).get(signal.intent_id);
        if (queue.length >= config.maxSignalsPerIntent) {
          throw createHttpError(429, 'Signal queue limit reached for intent.', {
            offenseReason: 'signal_queue_limit',
            offenseWeight: 4
          });
        }
        queue.push(signal);
        json(response, 202, { status: 'accepted' }, requestId);
        return;
      }

      if (request.method === 'GET' && url.pathname === '/signals') {
        const toDid = assertDid(url.searchParams.get('to_did'), 'to_did').did;
        const intentId = url.searchParams.get('intent_id');
        context.toDid = toDid;
        if (!intentId) {
          throw createHttpError(400, 'intent_id is required.');
        }
        await verifyDidSignedRequest(request, rawBody, toDid, context);
        const queue = signals.get(toDid)?.get(intentId) ?? [];
        json(response, 200, { to_did: toDid, intent_id: intentId, signals: queue }, requestId);
        return;
      }

      if (requiresProtectedRead(url.pathname, request.method)) {
        throw createHttpError(401, 'Signed DID request is required.', {
          offenseReason: 'missing_signature_headers',
          offenseWeight: 3
        });
      }

      throw createHttpError(404, 'Endpoint not found.');
    } catch (error) {
      const offense = classifyOffense(error);
      if (error.blocked) {
        observability.recordSecurityEvent({
          kind: 'blocked_request',
          request_id: requestId,
          principal: { type: error.blocked.type, value: error.blocked.value },
          route: context.route,
          message: `${error.blocked.type} blocked by ${error.blocked.source} controls.`
        });
      } else if (offense) {
        observability.recordOffense({
          requestId,
          ip: context.ip,
          verifiedDid: context.verifiedDid,
          route: context.route,
          reason: offense.reason,
          weight: offense.weight,
          statusCode: error.statusCode || 500,
          message: error.message || 'Internal error'
        });
      }

      json(response, error.statusCode || 500, { error: error.message || 'Internal error' }, requestId);
    } finally {
      observability.recordRequest({
        method: request.method,
        route: context.route,
        statusCode: response.statusCode || 500,
        durationMs: Date.now() - startedAt
      });
    }
  }

  return { handler, close };
}
