import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createHttpError } from './did.mjs';

export class DidStateStore {
  constructor(filePath) {
    this.filePath = resolve(filePath);
    this.states = new Map();
    this.writeChain = Promise.resolve();
  }

  async load() {
    await mkdir(dirname(this.filePath), { recursive: true });
    try {
      const content = await readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(content);
      for (const entry of parsed) {
        if (entry?.did) {
          this.states.set(entry.did, entry);
        }
      }
    } catch (error) {
      if (error.code === 'ENOENT') {
        await this.persist();
        return;
      }
      throw error;
    }
  }

  get(did) {
    return this.states.get(did) ?? null;
  }

  async upsert(nextState) {
    this.states.set(nextState.did, nextState);
    await this.persist();
    return nextState;
  }

  async persist() {
    const data = JSON.stringify([...this.states.values()], null, 2);
    this.writeChain = this.writeChain.then(async () => {
      const tempFile = `${this.filePath}.${randomUUID()}.tmp`;
      await writeFile(tempFile, `${data}\n`, 'utf8');
      await rename(tempFile, this.filePath);
    });
    await this.writeChain;
  }
}

export function requireDidState(store, did) {
  const state = store.get(did);
  if (!state) {
    throw createHttpError(404, 'DID state not found.');
  }
  return state;
}
