import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { startServer } from '../src/server.mjs';

function canonicalPayload({ method, pathWithQuery, timestamp, nonce, bodyRaw }) {
  const bodyHash = createHash('sha256').update(bodyRaw || '').digest('hex');
  return [method.toUpperCase(), pathWithQuery, timestamp, nonce, bodyHash].join('\n');
}

function signedHeaders({ did, privateKey, method, pathWithQuery, bodyRaw = '', timestamp = new Date().toISOString(), nonce = 'n1' }) {
  const payload = canonicalPayload({ method, pathWithQuery, timestamp, nonce, bodyRaw });
  const signature = sign(null, Buffer.from(payload), privateKey).toString('base64');
  return {
    'x-did': did,
    'x-signature': signature,
    'x-timestamp': timestamp,
    'x-nonce': nonce
  };
}

async function readJson(response) {
  return response.json();
}

async function findFreePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(address.port);
      });
    });
    server.on('error', reject);
  });
}

async function startFixture(t, overrides = {}) {
  const tempDir = await mkdtemp(join(tmpdir(), 'wormhole-'));
  const didStateFile = join(tempDir, 'did-states.json');
  const selectedPort = overrides.port ?? 0;
  const selectedDomain = overrides.serverDomain ?? 'test.local';
  const instance = await startServer({
    host: '127.0.0.1',
    port: selectedPort,
    serverDomain: selectedDomain,
    forwardProtocol: 'http',
    bootstrapToken: 'boot',
    didStateFile,
    intentTtlMs: 5_000,
    responseTtlMs: 5_000,
    signalTtlMs: 5_000,
    signatureSkewMs: 60_000,
    replayWindowMs: 60_000,
    ...overrides
  });
  const port = instance.server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  t.after(async () => {
    await instance.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  return { baseUrl };
}

async function publishDid(baseUrl, did, publicKeyPem) {
  const response = await fetch(`${baseUrl}/did-state`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      'x-bootstrap-token': 'boot'
    },
    body: JSON.stringify({
      did,
      current_public_key: publicKeyPem,
      status: 'active'
    })
  });
  assert.equal(response.status, 201);
}

test('DID state publish, read, and signed key rotation', async (t) => {
  const { baseUrl } = await startFixture(t);
  const did = 'did:wormhole:test.local:alice';
  const pairV1 = generateKeyPairSync('ed25519');
  const pairV2 = generateKeyPairSync('ed25519');
  const pubV1 = pairV1.publicKey.export({ type: 'spki', format: 'pem' });
  const pubV2 = pairV2.publicKey.export({ type: 'spki', format: 'pem' });

  await publishDid(baseUrl, did, pubV1);

  const read = await fetch(`${baseUrl}/did-state?did=${encodeURIComponent(did)}`);
  assert.equal(read.status, 200);
  const before = await readJson(read);
  assert.equal(before.key_history.length, 1);

  const rotatePath = '/did-state';
  const rotateBody = JSON.stringify({
    did,
    current_public_key: pubV2,
    status: 'active',
    rotation_proof: 'proof-v1-to-v2'
  });
  const headers = signedHeaders({
    did,
    privateKey: pairV1.privateKey,
    method: 'PUT',
    pathWithQuery: rotatePath,
    bodyRaw: rotateBody
  });
  const rotate = await fetch(`${baseUrl}${rotatePath}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', ...headers },
    body: rotateBody
  });
  assert.equal(rotate.status, 200);
  const after = await readJson(rotate);
  assert.equal(after.key_history.length, 2);
});

test('intents require DID-protected reads and seen acknowledgments', async (t) => {
  const { baseUrl } = await startFixture(t);
  const alice = generateKeyPairSync('ed25519');
  const bob = generateKeyPairSync('ed25519');
  const aliceDid = 'did:wormhole:test.local:alice';
  const bobDid = 'did:wormhole:test.local:bob';
  const alicePub = alice.publicKey.export({ type: 'spki', format: 'pem' });
  const bobPub = bob.publicKey.export({ type: 'spki', format: 'pem' });

  await publishDid(baseUrl, aliceDid, alicePub);
  await publishDid(baseUrl, bobDid, bobPub);

  const intent = await fetch(`${baseUrl}/intent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      intent_id: 'intent-1',
      from_did: aliceDid,
      to_did: bobDid,
      nonce: 'nonce-1'
    })
  });
  assert.equal(intent.status, 202);

  const unsigned = await fetch(`${baseUrl}/intents?to_did=${encodeURIComponent(bobDid)}`);
  assert.equal(unsigned.status, 401);

  const getPath = `/intents?to_did=${encodeURIComponent(bobDid)}`;
  const getHeaders = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'GET',
    pathWithQuery: getPath
  });
  const signed = await fetch(`${baseUrl}${getPath}`, { headers: getHeaders });
  assert.equal(signed.status, 200);
  const list = await readJson(signed);
  assert.equal(list.intents.length, 1);
  assert.equal(list.intents[0].state, 'available');

  const seenPath = '/intent/intent-1/seen';
  const seenBody = JSON.stringify({ to_did: bobDid });
  const seenHeaders = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'POST',
    pathWithQuery: seenPath,
    bodyRaw: seenBody
  });
  const seen = await fetch(`${baseUrl}${seenPath}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...seenHeaders },
    body: seenBody
  });
  assert.equal(seen.status, 200);
});

test('signed signaling send and receive succeeds', async (t) => {
  const { baseUrl } = await startFixture(t);
  const alice = generateKeyPairSync('ed25519');
  const bob = generateKeyPairSync('ed25519');
  const aliceDid = 'did:wormhole:test.local:alice';
  const bobDid = 'did:wormhole:test.local:bob';
  const alicePub = alice.publicKey.export({ type: 'spki', format: 'pem' });
  const bobPub = bob.publicKey.export({ type: 'spki', format: 'pem' });

  await publishDid(baseUrl, aliceDid, alicePub);
  await publishDid(baseUrl, bobDid, bobPub);

  const sendPath = '/signal';
  const sendBody = JSON.stringify({
    intent_id: 'intent-22',
    from_did: aliceDid,
    to_did: bobDid,
    signal_type: 'offer',
    payload: { sdp: 'v=0' }
  });
  const sendHeaders = signedHeaders({
    did: aliceDid,
    privateKey: alice.privateKey,
    method: 'POST',
    pathWithQuery: sendPath,
    bodyRaw: sendBody
  });
  const sent = await fetch(`${baseUrl}${sendPath}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...sendHeaders },
    body: sendBody
  });
  assert.equal(sent.status, 202);

  const getPath = `/signals?to_did=${encodeURIComponent(bobDid)}&intent_id=intent-22`;
  const getHeaders = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'GET',
    pathWithQuery: getPath
  });
  const got = await fetch(`${baseUrl}${getPath}`, { headers: getHeaders });
  assert.equal(got.status, 200);
  const payload = await readJson(got);
  assert.equal(payload.signals.length, 1);
  assert.equal(payload.signals[0].signal_type, 'offer');
});

test('replayed signed request is rejected', async (t) => {
  const { baseUrl } = await startFixture(t);
  const bob = generateKeyPairSync('ed25519');
  const bobDid = 'did:wormhole:test.local:bob';
  const bobPub = bob.publicKey.export({ type: 'spki', format: 'pem' });
  await publishDid(baseUrl, bobDid, bobPub);

  const getPath = `/intents?to_did=${encodeURIComponent(bobDid)}`;
  const fixedTimestamp = new Date().toISOString();
  const headers = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'GET',
    pathWithQuery: getPath,
    timestamp: fixedTimestamp,
    nonce: 'replay-nonce'
  });

  const first = await fetch(`${baseUrl}${getPath}`, { headers });
  assert.equal(first.status, 200);
  const second = await fetch(`${baseUrl}${getPath}`, { headers });
  assert.equal(second.status, 409);
});

test('accepts DID domain with host:port', async (t) => {
  const port = await findFreePort();
  const domain = `127.0.0.1:${port}`;
  const { baseUrl } = await startFixture(t, { port, serverDomain: domain });
  const pair = generateKeyPairSync('ed25519');
  const did = `did:wormhole:${domain}:alice`;
  const pub = pair.publicKey.export({ type: 'spki', format: 'pem' });

  await publishDid(baseUrl, did, pub);
  const read = await fetch(`${baseUrl}/did-state?did=${encodeURIComponent(did)}`);
  assert.equal(read.status, 200);
});

test('forwards intent response and signal with preserved DID signatures', async (t) => {
  const portA = await findFreePort();
  const portB = await findFreePort();
  const domainA = `127.0.0.1:${portA}`;
  const domainB = `127.0.0.1:${portB}`;
  const a = await startFixture(t, { port: portA, serverDomain: domainA });
  const b = await startFixture(t, { port: portB, serverDomain: domainB });

  const alice = generateKeyPairSync('ed25519');
  const bob = generateKeyPairSync('ed25519');
  const aliceDid = `did:wormhole:${domainA}:alice`;
  const bobDid = `did:wormhole:${domainB}:bob`;
  const alicePub = alice.publicKey.export({ type: 'spki', format: 'pem' });
  const bobPub = bob.publicKey.export({ type: 'spki', format: 'pem' });

  await publishDid(a.baseUrl, aliceDid, alicePub);
  await publishDid(b.baseUrl, bobDid, bobPub);

  const createIntent = await fetch(`${a.baseUrl}/intent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      intent_id: 'cross-intent-1',
      from_did: aliceDid,
      to_did: bobDid
    })
  });
  assert.equal(createIntent.status, 202);

  const intentsPath = `/intents?to_did=${encodeURIComponent(bobDid)}`;
  const intentsHeaders = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'GET',
    pathWithQuery: intentsPath
  });
  const intentsOnB = await fetch(`${b.baseUrl}${intentsPath}`, { headers: intentsHeaders });
  assert.equal(intentsOnB.status, 200);
  const intentsPayload = await readJson(intentsOnB);
  assert.equal(intentsPayload.intents.length, 1);

  const responsePath = '/intent-response';
  const responseBody = JSON.stringify({
    intent_id: 'cross-intent-1',
    from_did: bobDid,
    to_did: aliceDid,
    response: 'accept'
  });
  const responseHeaders = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'POST',
    pathWithQuery: responsePath,
    bodyRaw: responseBody
  });
  const responsePost = await fetch(`${b.baseUrl}${responsePath}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...responseHeaders },
    body: responseBody
  });
  assert.equal(responsePost.status, 202);

  const responsesPath = `/intent-responses?to_did=${encodeURIComponent(aliceDid)}`;
  const responsesHeaders = signedHeaders({
    did: aliceDid,
    privateKey: alice.privateKey,
    method: 'GET',
    pathWithQuery: responsesPath
  });
  const responsesOnA = await fetch(`${a.baseUrl}${responsesPath}`, { headers: responsesHeaders });
  assert.equal(responsesOnA.status, 200);
  const responsesPayload = await readJson(responsesOnA);
  assert.equal(responsesPayload.responses.length, 1);
  assert.equal(responsesPayload.responses[0].response, 'accept');

  const signalPath = '/signal';
  const signalBody = JSON.stringify({
    intent_id: 'cross-intent-1',
    from_did: aliceDid,
    to_did: bobDid,
    signal_type: 'offer',
    payload: { sdp: 'v=0 cross' }
  });
  const signalHeaders = signedHeaders({
    did: aliceDid,
    privateKey: alice.privateKey,
    method: 'POST',
    pathWithQuery: signalPath,
    bodyRaw: signalBody
  });
  const signalPost = await fetch(`${a.baseUrl}${signalPath}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...signalHeaders },
    body: signalBody
  });
  assert.equal(signalPost.status, 202);

  const signalsPath = `/signals?to_did=${encodeURIComponent(bobDid)}&intent_id=cross-intent-1`;
  const signalsHeaders = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'GET',
    pathWithQuery: signalsPath
  });
  const signalsOnB = await fetch(`${b.baseUrl}${signalsPath}`, { headers: signalsHeaders });
  assert.equal(signalsOnB.status, 200);
  const signalsPayload = await readJson(signalsOnB);
  assert.equal(signalsPayload.signals.length, 1);
  assert.equal(signalsPayload.signals[0].signal_type, 'offer');
});

test('rejects forged relay headers without DID signature headers', async (t) => {
  const { baseUrl } = await startFixture(t);
  const alice = generateKeyPairSync('ed25519');
  const bob = generateKeyPairSync('ed25519');
  const aliceDid = 'did:wormhole:test.local:alice';
  const bobDid = 'did:wormhole:remote.example:bob';
  const alicePub = alice.publicKey.export({ type: 'spki', format: 'pem' });
  const bobPub = bob.publicKey.export({ type: 'spki', format: 'pem' });
  await publishDid(baseUrl, aliceDid, alicePub);
  await publishDid(baseUrl, 'did:wormhole:test.local:bob', bobPub);

  const responseAttempt = await fetch(`${baseUrl}/intent-response`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-wormhole-relay-id': 'fake-relay-1',
      'x-wormhole-hop': '1'
    },
    body: JSON.stringify({
      intent_id: 'fake',
      from_did: bobDid,
      to_did: aliceDid,
      response: 'accept'
    })
  });
  assert.equal(responseAttempt.status, 401);

  const signalAttempt = await fetch(`${baseUrl}/signal`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-wormhole-relay-id': 'fake-relay-2',
      'x-wormhole-hop': '1'
    },
    body: JSON.stringify({
      intent_id: 'fake',
      from_did: bobDid,
      to_did: aliceDid,
      signal_type: 'offer',
      payload: { sdp: 'v=0' }
    })
  });
  assert.equal(signalAttempt.status, 401);
});

test('revoked DID cannot authenticate protected reads', async (t) => {
  const { baseUrl } = await startFixture(t);
  const bob = generateKeyPairSync('ed25519');
  const bobDid = 'did:wormhole:test.local:bob';
  const bobPub = bob.publicKey.export({ type: 'spki', format: 'pem' });
  await publishDid(baseUrl, bobDid, bobPub);

  const revokePath = '/did-state';
  const revokeBody = JSON.stringify({
    did: bobDid,
    current_public_key: bobPub,
    status: 'revoked'
  });
  const revokeHeaders = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'PUT',
    pathWithQuery: revokePath,
    bodyRaw: revokeBody
  });
  const revoke = await fetch(`${baseUrl}${revokePath}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', ...revokeHeaders },
    body: revokeBody
  });
  assert.equal(revoke.status, 200);

  const getPath = `/intents?to_did=${encodeURIComponent(bobDid)}`;
  const getHeaders = signedHeaders({
    did: bobDid,
    privateKey: bob.privateKey,
    method: 'GET',
    pathWithQuery: getPath
  });
  const read = await fetch(`${baseUrl}${getPath}`, { headers: getHeaders });
  assert.equal(read.status, 403);
});

test('rejects DID state publish when did fingerprint suffix mismatches key', async (t) => {
  const { baseUrl } = await startFixture(t);
  const alice = generateKeyPairSync('ed25519');
  const alicePub = alice.publicKey.export({ type: 'spki', format: 'pem' });
  const mismatchedDid = 'did:wormhole:test.local:alice:deadbeef';

  const response = await fetch(`${baseUrl}/did-state`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      'x-bootstrap-token': 'boot'
    },
    body: JSON.stringify({
      did: mismatchedDid,
      current_public_key: alicePub,
      status: 'active'
    })
  });
  assert.equal(response.status, 400);
});
