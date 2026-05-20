import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

const TYPES = new Set(['ip', 'did', 'domain']);

function assertType(type) {
  if (!TYPES.has(type)) {
    throw new Error(`Unsupported blocklist type: ${type}`);
  }
}

function serialize(map) {
  return [...map.values()].sort((left, right) => left.value.localeCompare(right.value));
}

export class AdminStateStore {
  constructor(filePath) {
    this.filePath = resolve(filePath);
    this.writeChain = Promise.resolve();
    this.blocklists = {
      ip: new Map(),
      did: new Map(),
      domain: new Map()
    };
  }

  async load() {
    await mkdir(dirname(this.filePath), { recursive: true });
    try {
      const content = await readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(content);
      this.#loadList('ip', parsed.manual_blocked_ips);
      this.#loadList('did', parsed.manual_blocked_dids);
      this.#loadList('domain', parsed.manual_blocked_domains);
    } catch (error) {
      if (error.code === 'ENOENT') {
        await this.persist();
        return;
      }
      throw error;
    }
  }

  #loadList(type, entries) {
    const bucket = this.blocklists[type];
    for (const entry of entries ?? []) {
      if (!entry?.value) {
        continue;
      }
      bucket.set(entry.value, {
        type,
        value: entry.value,
        reason: entry.reason ?? '',
        created_at: entry.created_at ?? new Date().toISOString(),
        updated_at: entry.updated_at ?? entry.created_at ?? new Date().toISOString()
      });
    }
  }

  list(type) {
    assertType(type);
    return serialize(this.blocklists[type]);
  }

  get(type, value) {
    assertType(type);
    return this.blocklists[type].get(value) ?? null;
  }

  has(type, value) {
    return this.get(type, value) !== null;
  }

  async upsert(type, value, reason = '') {
    assertType(type);
    const normalized = String(value ?? '').trim();
    if (!normalized) {
      throw new Error('Blocklist value is required.');
    }
    const now = new Date().toISOString();
    const previous = this.blocklists[type].get(normalized);
    const record = {
      type,
      value: normalized,
      reason,
      created_at: previous?.created_at ?? now,
      updated_at: now
    };
    this.blocklists[type].set(normalized, record);
    await this.persist();
    return record;
  }

  async remove(type, value) {
    assertType(type);
    const normalized = String(value ?? '').trim();
    const deleted = this.blocklists[type].delete(normalized);
    if (deleted) {
      await this.persist();
    }
    return deleted;
  }

  snapshot() {
    return {
      manual_blocked_ips: serialize(this.blocklists.ip),
      manual_blocked_dids: serialize(this.blocklists.did),
      manual_blocked_domains: serialize(this.blocklists.domain)
    };
  }

  async persist() {
    const data = JSON.stringify(this.snapshot(), null, 2);
    this.writeChain = this.writeChain.then(async () => {
      const tempFile = `${this.filePath}.${randomUUID()}.tmp`;
      await writeFile(tempFile, `${data}\n`, 'utf8');
      await rename(tempFile, this.filePath);
    });
    await this.writeChain;
  }
}
