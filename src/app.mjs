import { randomUUID } from 'node:crypto';
import { createHttpError, assertDid, computeFingerprint, ensureStatus } from './did.mjs';
import { canonicalSignaturePayload, buildReplayKey, ensureTimestampWithinSkew, verifySignature } from './signatures.mjs';
import { DidStateStore, requireDidState } from './storage.mjs';
import { FixedWindowRateLimiter } from './rate-limit.mjs';
import { limitsResponse } from './config.mjs';

function getClientIp(request) {
  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return request.socket.remoteAddress || 'unknown';
}

async function readRawBody(request, maxBytes) {
  const chunks = [];
  let total = 0;

  for await (const chunk of request) {
    total += chunk.length;
    if (total > maxBytes) {
      throw createHttpError(413, 'Request body too large.');
    }
    chunks.push(chunk);
  }

  return Buffer.concat(chunks).toString('utf8');
}

function json(response, statusCode, payload) {
  response.statusCode = statusCode;
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.end(JSON.stringify(payload));
}

function parseJsonBody(rawBody) {
  if (!rawBody) {
    return {};
  }
  try {
    return JSON.parse(rawBody);
  } catch {
    throw createHttpError(400, 'Invalid JSON body.');
  }
}

function toEpoch(dateString, fallbackMs) {
  if (!dateString) {
    return Date.now() + fallbackMs;
  }
  const value = new Date(dateString).valueOf();
  if (Number.isNaN(value)) {
    throw createHttpError(400, 'Invalid date format.');
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
    throw createHttpError(400, 'Invalid relay hop header.');
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
    throw createHttpError(413, `${field} exceeds max size.`);
  }
}

function ensureNotBlocked(config, ip, fromDid, toDid) {
  if (config.blocklistIps.has(ip)) {
    throw createHttpError(403, 'IP is blocked.');
  }
  if (fromDid && config.blocklistDids.has(fromDid)) {
    throw createHttpError(403, 'from_did is blocked.');
  }
  if (toDid && config.blocklistDids.has(toDid)) {
    throw createHttpError(403, 'to_did is blocked.');
  }
  if (toDid) {
    const parsed = assertDid(toDid, 'to_did');
    if (config.blocklistDomains.has(parsed.domain)) {
      throw createHttpError(403, 'Destination domain is blocked.');
    }
  }
}

function setIntentState(intent, state) {
  intent.state = state;
  intent.updated_at = new Date().toISOString();
}

function toIntentStateFromResponse(responseValue) {
  if (responseValue === 'accept') return 'accepted';
  if (responseValue === 'reject') return 'rejected';
  return 'later';
}

export async function createApp(config) {
  const didStore = new DidStateStore(config.didStateFile);
  await didStore.load();

  const intents = new Map();
  const intentStatusById = new Map();
  const intentResponses = new Map();
  const signals = new Map();
  const replayCache = new Map();
  const relayCache = new Map();

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
    const result = limiter.consume(key);
    if (result.allowed) {
      return;
    }
    response.setHeader('retry-after', String(Math.ceil(result.retryAfterMs / 1000)));
    throw createHttpError(429, `Rate limit exceeded for ${label}.`);
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

  async function verifyDidSignedRequest(request, rawBody, targetDid) {
    const did = request.headers['x-did'];
    const signature = request.headers['x-signature'];
    const timestamp = request.headers['x-timestamp'];
    const nonce = request.headers['x-nonce'] || '';

    if (!did || !signature || !timestamp) {
      throw createHttpError(401, 'Missing DID signature headers.');
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
      throw createHttpError(409, 'Replay detected.');
    }

    const ok = verifySignature(state.current_public_key, payload, signature);
    if (!ok) {
      throw createHttpError(401, 'Invalid DID signature.');
    }

    replayCache.set(replayKey, Date.now() + config.replayWindowMs);
    return state;
  }

  function cleanup() {
    const now = Date.now();

    for (const [key, until] of replayCache.entries()) {
      if (until <= now) replayCache.delete(key);
    }
    for (const [key, until] of relayCache.entries()) {
      if (until <= now) relayCache.delete(key);
    }
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

  async function handler(request, response) {
    try {
      const rawBody = await readRawBody(request, config.maxBodyBytes);
      const body = parseJsonBody(rawBody);
      const url = new URL(request.url, 'http://localhost');
      const ip = getClientIp(request);

      consumeRate(ipLimiter, response, ip, 'ip');

      const relayId = request.headers['x-wormhole-relay-id'] || '';
      const hopHeader = request.headers['x-wormhole-hop'];
      const hasHopHeader = hopHeader !== undefined && hopHeader !== null && String(hopHeader).length > 0;
      const hop = hasHopHeader ? Number(hopHeader) : 0;
      if (hasHopHeader && (!Number.isInteger(hop) || hop < 0)) {
        throw createHttpError(400, 'Invalid relay hop header.');
      }
      if (hop > config.maxRelayHops) {
        throw createHttpError(508, 'Relay hop limit exceeded.');
      }
      if (relayId) {
        if (relayCache.has(relayId)) {
          json(response, 202, { status: 'duplicate', relay_id: relayId });
          return;
        }
        relayCache.set(relayId, Date.now() + config.relayCacheTtlMs);
      }

      if (request.method === 'GET' && url.pathname === '/health') {
        json(response, 200, {
          status: 'ok',
          server_domain: config.serverDomain,
          did_states: didStore.states.size
        });
        return;
      }

      if (request.method === 'GET' && url.pathname === '/limits') {
        json(response, 200, limitsResponse(config));
        return;
      }

      if (request.method === 'GET' && url.pathname === '/did-state') {
        const did = url.searchParams.get('did');
        assertDid(did, 'did');
        const state = requireDidState(didStore, did);
        json(response, 200, state);
        return;
      }

      if (request.method === 'PUT' && url.pathname === '/did-state') {
        const did = assertDid(body.did, 'did');
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
          if (!config.bootstrapToken || request.headers['x-bootstrap-token'] !== config.bootstrapToken) {
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
          json(response, 201, created);
          return;
        }

        const isAdminRecovery =
          config.adminToken && request.headers['x-admin-token'] && request.headers['x-admin-token'] === config.adminToken;

        if (!isAdminRecovery) {
          await verifyDidSignedRequest(request, rawBody, did.did);
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
        json(response, 200, updated);
        return;
      }

      if (request.method === 'POST' && url.pathname === '/intent') {
        const fromDid = assertDid(body.from_did, 'from_did').did;
        const toDidData = assertDid(body.to_did, 'to_did');
        const toDid = toDidData.did;
        const expiresAt = toEpoch(body.expires_at, config.intentTtlMs);
        if (expiresAt - Date.now() > config.intentTtlMs) {
          throw createHttpError(400, 'Intent expiry exceeds max TTL.');
        }
        if (expiresAt <= Date.now()) {
          throw createHttpError(400, 'Intent is already expired.');
        }

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
        intentStatusById.set(intent.intent_id, intent);

        try {
          ensureNotBlocked(config, ip, fromDid, toDid);
          consumeRate(fromDidLimiter, response, fromDid, 'from_did');
          consumeRate(toDidLimiter, response, toDid, 'to_did');
          ensureSizeLimit(body.agent_envelope, config.maxIntentEnvelopeBytes, 'agent_envelope');
        } catch (error) {
          if (error.statusCode === 403 || error.statusCode === 429) {
            setIntentState(intent, 'blocked');
          }
          throw error;
        }

        if (toDidData.domain !== config.serverDomain) {
          try {
            await forwardObject(config, toDidData.domain, '/intent', intent, relayId, hop);
          } catch (error) {
            setIntentState(intent, 'failed');
            throw error;
          }
          json(response, 202, { status: 'forwarded', intent_id: intent.intent_id });
          return;
        }

        if (!intents.has(toDid)) intents.set(toDid, new Map());
        intents.get(toDid).set(intent.intent_id, intent);
        json(response, 202, { status: 'accepted', intent_id: intent.intent_id });
        return;
      }

      if (request.method === 'GET' && url.pathname === '/intents') {
        const toDid = assertDid(url.searchParams.get('to_did'), 'to_did').did;
        await verifyDidSignedRequest(request, rawBody, toDid);
        const entries = [...(intents.get(toDid)?.values() ?? [])];
        json(response, 200, { to_did: toDid, intents: entries });
        return;
      }

      if (request.method === 'POST' && /^\/intent\/[^/]+\/seen$/.test(url.pathname)) {
        const intentId = decodeURIComponent(url.pathname.split('/')[2]);
        const toDid = assertDid(body.to_did, 'to_did').did;
        await verifyDidSignedRequest(request, rawBody, toDid);

        const bucket = intents.get(toDid);
        const intent = bucket?.get(intentId);
        if (!intent) {
          throw createHttpError(404, 'Intent not found.');
        }
        setIntentState(intent, 'seen');
        if (intentStatusById.has(intentId)) {
          setIntentState(intentStatusById.get(intentId), 'seen');
        }
        json(response, 200, { status: 'seen', intent_id: intentId });
        return;
      }

      if (request.method === 'POST' && url.pathname === '/intent-response') {
        const allowedResponses = new Set(['accept', 'reject', 'later']);
        if (!allowedResponses.has(body.response)) {
          throw createHttpError(400, 'Invalid response value.');
        }
        const fromDid = assertDid(body.from_did, 'from_did').did;
        const toDidData = assertDid(body.to_did, 'to_did');
        ensureNotBlocked(config, ip, fromDid, toDidData.did);
        consumeRate(fromDidLimiter, response, fromDid, 'from_did');
        consumeRate(toDidLimiter, response, toDidData.did, 'to_did');
        await verifyDidSignedRequest(request, rawBody, fromDid);
        ensureSizeLimit(body.agent_envelope, config.maxIntentEnvelopeBytes, 'agent_envelope');

        const expiresAt = toEpoch(body.expires_at, config.responseTtlMs);
        if (expiresAt - Date.now() > config.responseTtlMs) {
          throw createHttpError(400, 'Response expiry exceeds max TTL.');
        }

        const responsePayload = {
          intent_id: body.intent_id,
          from_did: fromDid,
          to_did: toDidData.did,
          response: body.response,
          created_at: body.created_at || new Date().toISOString(),
          expires_at: new Date(expiresAt).toISOString(),
          agent_envelope: body.agent_envelope ?? null
        };

        if (!responsePayload.intent_id) {
          throw createHttpError(400, 'intent_id is required.');
        }

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
          json(response, 202, { status: 'forwarded', intent_id: responsePayload.intent_id });
          return;
        }

        if (!intentResponses.has(toDidData.did)) intentResponses.set(toDidData.did, new Map());
        intentResponses.get(toDidData.did).set(responsePayload.intent_id, responsePayload);

        const intentBucket = intents.get(fromDid);
        if (intentBucket?.has(responsePayload.intent_id)) {
          const nextState = toIntentStateFromResponse(responsePayload.response);
          setIntentState(intentBucket.get(responsePayload.intent_id), nextState);
          if (intentStatusById.has(responsePayload.intent_id)) {
            setIntentState(intentStatusById.get(responsePayload.intent_id), nextState);
          }
        }

        json(response, 202, { status: 'accepted', intent_id: responsePayload.intent_id });
        return;
      }

      if (request.method === 'GET' && url.pathname === '/intent-responses') {
        const toDid = assertDid(url.searchParams.get('to_did'), 'to_did').did;
        await verifyDidSignedRequest(request, rawBody, toDid);
        const entries = [...(intentResponses.get(toDid)?.values() ?? [])];
        json(response, 200, { to_did: toDid, responses: entries });
        return;
      }

      if (request.method === 'POST' && url.pathname === '/signal') {
        const fromDid = assertDid(body.from_did, 'from_did').did;
        const toDidData = assertDid(body.to_did, 'to_did');
        const toDid = toDidData.did;
        ensureNotBlocked(config, ip, fromDid, toDid);
        await verifyDidSignedRequest(request, rawBody, fromDid);
        ensureSizeLimit(body.payload, config.maxSignalPayloadBytes, 'payload');
        if (!body.intent_id) {
          throw createHttpError(400, 'intent_id is required.');
        }
        const allowedSignalTypes = new Set(['offer', 'answer', 'ice_candidate']);
        if (!allowedSignalTypes.has(body.signal_type)) {
          throw createHttpError(400, 'Invalid signal_type.');
        }
        consumeRate(fromDidLimiter, response, fromDid, 'from_did');
        consumeRate(toDidLimiter, response, toDid, 'to_did');

        const expiresAt = toEpoch(body.expires_at, config.signalTtlMs);
        if (expiresAt - Date.now() > config.signalTtlMs) {
          throw createHttpError(400, 'Signal expiry exceeds max TTL.');
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
          json(response, 202, { status: 'forwarded' });
          return;
        }

        if (!signals.has(toDid)) signals.set(toDid, new Map());
        if (!signals.get(toDid).has(signal.intent_id)) {
          signals.get(toDid).set(signal.intent_id, []);
        }
        const queue = signals.get(toDid).get(signal.intent_id);
        if (queue.length >= config.maxSignalsPerIntent) {
          throw createHttpError(429, 'Signal queue limit reached for intent.');
        }
        queue.push(signal);
        json(response, 202, { status: 'accepted' });
        return;
      }

      if (request.method === 'GET' && url.pathname === '/signals') {
        const toDid = assertDid(url.searchParams.get('to_did'), 'to_did').did;
        const intentId = url.searchParams.get('intent_id');
        if (!intentId) {
          throw createHttpError(400, 'intent_id is required.');
        }
        await verifyDidSignedRequest(request, rawBody, toDid);
        const queue = signals.get(toDid)?.get(intentId) ?? [];
        json(response, 200, { to_did: toDid, intent_id: intentId, signals: queue });
        return;
      }

      if (requiresProtectedRead(url.pathname, request.method)) {
        throw createHttpError(401, 'Signed DID request is required.');
      }

      throw createHttpError(404, 'Endpoint not found.');
    } catch (error) {
      json(response, error.statusCode || 500, { error: error.message || 'Internal error' });
    }
  }

  return { handler, close };
}
