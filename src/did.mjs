import { createHash } from 'node:crypto';

const DID_PATTERN = /^did:wormhole:([^:]+(?::\d+)?):([^:]+)(?::([^:]+))?$/;
const STATUS = new Set(['active', 'disabled', 'revoked']);

export function parseDid(did) {
  const match = DID_PATTERN.exec(String(did ?? '').trim());
  if (!match) {
    return null;
  }
  return {
    did: match[0],
    domain: match[1],
    didIdentifier: match[2],
    keyFingerprint: match[3] ?? null
  };
}

export function assertDid(did, label = 'did') {
  const parsed = parseDid(did);
  if (!parsed) {
    throw createHttpError(400, `Invalid ${label} format.`);
  }
  return parsed;
}

export function ensureStatus(status) {
  const normalized = (status ?? 'active').toLowerCase();
  if (!STATUS.has(normalized)) {
    throw createHttpError(400, 'Invalid DID status.');
  }
  return normalized;
}

export function computeFingerprint(publicKeyPem) {
  return createHash('sha256').update(publicKeyPem, 'utf8').digest('hex');
}

export function createHttpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}
