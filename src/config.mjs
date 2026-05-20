const DEFAULTS = {
  host: '127.0.0.1',
  port: 7070,
  serverDomain: 'localhost:7070',
  forwardProtocol: 'https',
  trustProxy: false,
  maxBodyBytes: 64 * 1024,
  maxIntentEnvelopeBytes: 4 * 1024,
  maxSignalPayloadBytes: 16 * 1024,
  maxSignalsPerIntent: 64,
  intentTtlMs: 10 * 60 * 1000,
  responseTtlMs: 5 * 60 * 1000,
  signalTtlMs: 2 * 60 * 1000,
  cleanupIntervalMs: 15 * 1000,
  signatureSkewMs: 2 * 60 * 1000,
  replayWindowMs: 2 * 60 * 1000,
  maxReplayEntries: 4096,
  relayCacheTtlMs: 10 * 60 * 1000,
  maxRelayEntries: 4096,
  maxRelayHops: 2,
  rateWindowMs: 60 * 1000,
  ratePerIp: 120,
  ratePerFromDid: 120,
  ratePerToDid: 240,
  rateBackoffMs: 20 * 1000,
  offenseDecayMs: 10 * 60 * 1000,
  autoBlockThreshold: 12,
  autoBlockTtlMs: 15 * 60 * 1000,
  securityEventBufferSize: 500,
  maxTrackedOffenders: 2048,
  bootstrapToken: 'wormhole-bootstrap-token',
  adminToken: '',
  didStateFile: 'data/did-states.json',
  adminStateFile: 'data/admin-state.json',
  requestTimeoutMs: 30 * 1000,
  headersTimeoutMs: 15 * 1000,
  keepAliveTimeoutMs: 5 * 1000,
  socketTimeoutMs: 30 * 1000,
  maxRequestsPerSocket: 1000
};

function toNumber(value, fallback) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toSet(value) {
  if (!value) {
    return new Set();
  }
  return new Set(
    String(value)
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)
  );
}

function toBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') {
    return true;
  }
  if (normalized === 'false' || normalized === '0' || normalized === 'no') {
    return false;
  }
  return fallback;
}

export function loadConfig(env = process.env) {
  return {
    host: env.HOST || DEFAULTS.host,
    port: toNumber(env.PORT, DEFAULTS.port),
    serverDomain: env.SERVER_DOMAIN || DEFAULTS.serverDomain,
    forwardProtocol: env.FORWARD_PROTOCOL || DEFAULTS.forwardProtocol,
    allowInsecureForwarding: toBoolean(env.ALLOW_INSECURE_FORWARDING, false),
    trustProxy: toBoolean(env.TRUST_PROXY, DEFAULTS.trustProxy),
    maxBodyBytes: toNumber(env.MAX_BODY_BYTES, DEFAULTS.maxBodyBytes),
    maxIntentEnvelopeBytes: toNumber(env.MAX_INTENT_ENVELOPE_BYTES, DEFAULTS.maxIntentEnvelopeBytes),
    maxSignalPayloadBytes: toNumber(env.MAX_SIGNAL_PAYLOAD_BYTES, DEFAULTS.maxSignalPayloadBytes),
    maxSignalsPerIntent: toNumber(env.MAX_SIGNALS_PER_INTENT, DEFAULTS.maxSignalsPerIntent),
    intentTtlMs: toNumber(env.INTENT_TTL_MS, DEFAULTS.intentTtlMs),
    responseTtlMs: toNumber(env.RESPONSE_TTL_MS, DEFAULTS.responseTtlMs),
    signalTtlMs: toNumber(env.SIGNAL_TTL_MS, DEFAULTS.signalTtlMs),
    cleanupIntervalMs: toNumber(env.CLEANUP_INTERVAL_MS, DEFAULTS.cleanupIntervalMs),
    signatureSkewMs: toNumber(env.SIGNATURE_SKEW_MS, DEFAULTS.signatureSkewMs),
    replayWindowMs: toNumber(env.REPLAY_WINDOW_MS, DEFAULTS.replayWindowMs),
    maxReplayEntries: toNumber(env.MAX_REPLAY_ENTRIES, DEFAULTS.maxReplayEntries),
    relayCacheTtlMs: toNumber(env.RELAY_CACHE_TTL_MS, DEFAULTS.relayCacheTtlMs),
    maxRelayEntries: toNumber(env.MAX_RELAY_ENTRIES, DEFAULTS.maxRelayEntries),
    maxRelayHops: toNumber(env.MAX_RELAY_HOPS, DEFAULTS.maxRelayHops),
    rateWindowMs: toNumber(env.RATE_WINDOW_MS, DEFAULTS.rateWindowMs),
    ratePerIp: toNumber(env.RATE_PER_IP, DEFAULTS.ratePerIp),
    ratePerFromDid: toNumber(env.RATE_PER_FROM_DID, DEFAULTS.ratePerFromDid),
    ratePerToDid: toNumber(env.RATE_PER_TO_DID, DEFAULTS.ratePerToDid),
    rateBackoffMs: toNumber(env.RATE_BACKOFF_MS, DEFAULTS.rateBackoffMs),
    offenseDecayMs: toNumber(env.OFFENSE_DECAY_MS, DEFAULTS.offenseDecayMs),
    autoBlockThreshold: toNumber(env.AUTO_BLOCK_THRESHOLD, DEFAULTS.autoBlockThreshold),
    autoBlockTtlMs: toNumber(env.AUTO_BLOCK_TTL_MS, DEFAULTS.autoBlockTtlMs),
    securityEventBufferSize: toNumber(env.SECURITY_EVENT_BUFFER_SIZE, DEFAULTS.securityEventBufferSize),
    maxTrackedOffenders: toNumber(env.MAX_TRACKED_OFFENDERS, DEFAULTS.maxTrackedOffenders),
    bootstrapToken: env.BOOTSTRAP_TOKEN ?? DEFAULTS.bootstrapToken,
    adminToken: env.ADMIN_TOKEN ?? DEFAULTS.adminToken,
    didStateFile: env.DID_STATE_FILE || DEFAULTS.didStateFile,
    adminStateFile: env.ADMIN_STATE_FILE || DEFAULTS.adminStateFile,
    requestTimeoutMs: toNumber(env.REQUEST_TIMEOUT_MS, DEFAULTS.requestTimeoutMs),
    headersTimeoutMs: toNumber(env.HEADERS_TIMEOUT_MS, DEFAULTS.headersTimeoutMs),
    keepAliveTimeoutMs: toNumber(env.KEEP_ALIVE_TIMEOUT_MS, DEFAULTS.keepAliveTimeoutMs),
    socketTimeoutMs: toNumber(env.SOCKET_TIMEOUT_MS, DEFAULTS.socketTimeoutMs),
    maxRequestsPerSocket: toNumber(env.MAX_REQUESTS_PER_SOCKET, DEFAULTS.maxRequestsPerSocket),
    blocklistIps: toSet(env.BLOCKLIST_IPS),
    blocklistDids: toSet(env.BLOCKLIST_DIDS),
    blocklistDomains: toSet(env.BLOCKLIST_DOMAINS),
    trustedProxyIps: toSet(env.TRUSTED_PROXY_IPS)
  };
}

export function limitsResponse(config) {
  return {
    max_body_bytes: config.maxBodyBytes,
    max_intent_envelope_bytes: config.maxIntentEnvelopeBytes,
    max_signal_payload_bytes: config.maxSignalPayloadBytes,
    max_signals_per_intent: config.maxSignalsPerIntent,
    intent_ttl_ms: config.intentTtlMs,
    response_ttl_ms: config.responseTtlMs,
    signal_ttl_ms: config.signalTtlMs,
    signature_skew_ms: config.signatureSkewMs,
    replay_window_ms: config.replayWindowMs,
    max_replay_entries: config.maxReplayEntries,
    rate_window_ms: config.rateWindowMs,
    offense_decay_ms: config.offenseDecayMs,
    auto_block_threshold: config.autoBlockThreshold,
    auto_block_ttl_ms: config.autoBlockTtlMs,
    trust_proxy: config.trustProxy,
    rate_limits: {
      per_ip: config.ratePerIp,
      per_from_did: config.ratePerFromDid,
      per_to_did: config.ratePerToDid
    },
    max_relay_entries: config.maxRelayEntries,
    max_relay_hops: config.maxRelayHops,
    request_timeout_ms: config.requestTimeoutMs,
    headers_timeout_ms: config.headersTimeoutMs,
    keep_alive_timeout_ms: config.keepAliveTimeoutMs,
    max_requests_per_socket: config.maxRequestsPerSocket
  };
}
