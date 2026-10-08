import { describe, it, expect, vi } from 'vitest';
import type { TableClient } from '@azure/data-tables';
import { MemoryStorage } from '../src/storage/memory-storage.js';
import { TableStorage } from '../src/storage/table-storage.js';
import type { TokenBinding } from '../src/storage/oauth-storage.js';

function tableStore() {
  const entries = new Map<string, Record<string, unknown>>();
  const client = {
    createEntity: vi.fn(async (entry: Record<string, unknown>) => {
      const key = `${entry.partitionKey}:${entry.rowKey}`;
      if (entries.has(key)) throw { statusCode: 409 };
      entries.set(key, { ...entry, etag: crypto.randomUUID() });
    }),
    getEntity: vi.fn(async (partition: string, row: string) => {
      const entry = entries.get(`${partition}:${row}`);
      if (!entry) throw { statusCode: 404 };
      return { ...entry };
    }),
    deleteEntity: vi.fn(async (partition: string, row: string, options: { etag: string }) => {
      const key = `${partition}:${row}`;
      const entry = entries.get(key);
      if (!entry) throw { statusCode: 404 };
      if (!options.etag || options.etag !== entry.etag) throw { statusCode: 412 };
      entries.delete(key);
    }),
  };
  return new TableStorage(client as unknown as TableClient);
}

for (const [name, create] of [
  ['memory', () => new MemoryStorage()],
  ['table', tableStore],
] as const) {
  describe(`${name} token binding storage`, () => {
    const binding: TokenBinding = {
      kind: 'refresh',
      tokenHash: 'digest',
      clientId: 'owner',
      resource: 'https://mcp.example/mcp',
      scope: 'access_as_user',
      expiresAt: Date.now() + 60_000,
    };
    it('does not consume another client or resource grant', async () => {
      const store = create();
      await store.saveTokenBinding(binding);
      expect(
        await store.consumeTokenBinding('refresh', 'digest', 'attacker', binding.resource)
      ).toBeNull();
      expect(
        await store.consumeTokenBinding('refresh', 'digest', 'owner', 'other-resource')
      ).toBeNull();
      expect(
        await store.consumeTokenBinding('device', 'digest', 'owner', binding.resource)
      ).toBeNull();
      expect(
        await store.consumeTokenBinding('refresh', 'digest', 'owner', binding.resource)
      ).toMatchObject(binding);
      expect(
        await store.consumeTokenBinding('refresh', 'digest', 'owner', binding.resource)
      ).toBeNull();
    });
    it('atomically consumes a grant once across concurrent requests', async () => {
      const store = create();
      await store.saveTokenBinding(binding);
      const consume = () =>
        store.consumeTokenBinding('refresh', 'digest', 'owner', binding.resource);
      const results = await Promise.all([consume(), consume(), consume()]);
      expect(results.filter(Boolean)).toHaveLength(1);
    });
    it('rejects expired and unknown grants', async () => {
      const store = create();
      await store.saveTokenBinding({ ...binding, expiresAt: Date.now() - 1 });
      expect(
        await store.getTokenBinding('refresh', 'digest', 'owner', binding.resource)
      ).toBeNull();
      expect(
        await store.consumeTokenBinding('refresh', 'digest', 'owner', binding.resource)
      ).toBeNull();
      expect(
        await store.consumeTokenBinding('refresh', 'unknown', 'owner', binding.resource)
      ).toBeNull();
    });
    it('does not overwrite an existing grant with a new owner', async () => {
      const store = create();
      await store.saveTokenBinding(binding);
      await expect(
        store.saveTokenBinding({ ...binding, clientId: 'attacker' })
      ).rejects.toBeDefined();
      expect(
        await store.getTokenBinding('refresh', 'digest', 'owner', binding.resource)
      ).toMatchObject(binding);
    });
  });
}
