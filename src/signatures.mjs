import { createHash, createPublicKey, verify } from 'node:crypto';
import { createHttpError } from './did.mjs';

const EMPTY_HASH = createHash('sha256').update('').digest('hex');

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalSignaturePayload({ method, pathWithQuery, timestamp, nonce, bodyRaw }) {
  const bodyHash = bodyRaw ? sha256Hex(bodyRaw) : EMPTY_HASH;
  return [method.toUpperCase(), pathWithQuery, timestamp, nonce || '', bodyHash].join('\n');
}

export function ensureTimestampWithinSkew(timestamp, maxSkewMs) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.valueOf())) {
    throw createHttpError(400, 'Invalid x-timestamp header.');
  }
  const delta = Math.abs(Date.now() - date.valueOf());
  if (delta > maxSkewMs) {
    throw createHttpError(401, 'Signature timestamp outside accepted skew.');
  }
}

function tryVerify(publicKey, payload, signature) {
  const keyObject = createPublicKey(publicKey);
  const signed = Buffer.from(signature, 'base64');
  const bytes = Buffer.from(payload, 'utf8');
  return verify(null, bytes, keyObject, signed) || verify('sha256', bytes, keyObject, signed);
}

export function verifySignature(publicKey, payload, signature) {
  if (!signature) {
    return false;
  }
  try {
    return tryVerify(publicKey, payload, signature);
  } catch {
    return false;
  }
}

export function buildReplayKey(did, signature) {
  return `${did}:${signature}`;
}
