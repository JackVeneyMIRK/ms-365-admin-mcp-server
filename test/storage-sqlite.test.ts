import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SQLiteStorage } from '../src/storage/sqlite-storage.js';
import { hashClientSecret, verifyClientSecret } from '../src/storage/oauth-storage.js';
import type { PkceEntry, TokenBinding } from '../src/storage/oauth-storage.js';

let directory: string;
let path: string;
let stores: SQLiteStorage[];
function open() {
  const store = new SQLiteStorage(path);
  stores.push(store);
  return store;
}
const client = {
  clientId: 'registered-client',
  clientSecretHash: hashClientSecret('synthetic-client-secret'),
  redirectUris: ['https://client.example/callback', 'http://localhost:3000/cb'],
  createdAt: 1_700_000_000_000,
};
function pkce(overrides: Partial<PkceEntry> = {}): PkceEntry {
  return {
    clientChallenge: 'challenge',
    serverVerifier: 'verifier',
    clientId: client.clientId,
    redirectUri: client.redirectUris[0],
    clientState: 'state',
    resource: 'https://mcp.example/mcp',
    scope: 'access_as_user',
    expiresAt: Date.now() + 60_000,
    ...overrides,
  };
}
function binding(kind: TokenBinding['kind'] = 'refresh'): TokenBinding {
  return {
    kind,
    tokenHash: hashClientSecret('synthetic-upstream-token'),
    clientId: client.clientId,
    resource: 'https://mcp.example/mcp',
    scope: 'access_as_user',
    expiresAt: Date.now() + 60_000,
  };
}
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'oauth-sqlite-'));
  path = join(directory, 'private', 'oauth.sqlite');
  stores = [];
});
afterEach(() => {
  vi.useRealTimers();
  for (const store of stores) store.close();
  rmSync(directory, { recursive: true, force: true });
});

describe('SQLite OAuth persistence', () => {
  it('retains registrations, PKCE and both token kinds through close and reopen', async () => {
    const first = open();
    const bridge = pkce();
    await first.saveClient(client);
    await first.savePkce(bridge);
    for (const kind of ['refresh', 'device'] as const) await first.saveTokenBinding(binding(kind));
    first.close();
    const second = open();
    expect(await second.getClient(client.clientId)).toEqual(client);
    expect(await second.getClient('unknown')).toBeNull();
    expect(await second.consumePkce('challenge')).toEqual(bridge);
    for (const kind of ['refresh', 'device'] as const) {
      const grant = binding(kind);
      expect(
        await second.getTokenBinding(kind, grant.tokenHash, grant.clientId, grant.resource)
      ).toMatchObject({ kind, scope: grant.scope, clientId: grant.clientId });
    }
    second.close();
    expect(await open().consumePkce('challenge')).toBeNull();
  });

  it('validates the original secret after restart and never stores plaintext secrets or tokens', async () => {
    const first = open();
    await first.saveClient(client);
    await first.saveTokenBinding(binding());
    first.close();
    const second = open();
    const saved = (await second.getClient(client.clientId))!;
    expect(verifyClientSecret('synthetic-client-secret', saved.clientSecretHash)).toBe(true);
    expect(verifyClientSecret('wrong-secret', saved.clientSecretHash)).toBe(false);
    expect(verifyClientSecret('', saved.clientSecretHash)).toBe(false);
    second.close();
    const contents = readFileSync(path).toString('utf8');
    expect(contents).not.toContain('synthetic-client-secret');
    expect(contents).not.toContain('synthetic-upstream-token');
    expect(contents).toContain(client.clientSecretHash);
  });

  it('rejects duplicate client registrations without replacing their secret', async () => {
    const store = open();
    await store.saveClient(client);
    await expect(
      store.saveClient({ ...client, clientSecretHash: hashClientSecret('attacker') })
    ).rejects.toThrow();
    expect(await store.getClient(client.clientId)).toEqual(client);
  });

  it('round-trips absent optional PKCE fields', async () => {
    const store = open();
    const entry = pkce({ clientState: undefined, resource: undefined, scope: undefined });
    await store.savePkce(entry);
    expect(await store.consumePkce(entry.clientChallenge)).toEqual(entry);
  });

  it.each(['refresh', 'device'] as const)(
    'preserves %s ownership and one-shot consumption across connections',
    async (kind) => {
      const first = open();
      const second = open();
      const grant = binding(kind);
      await first.saveTokenBinding(grant);
      await expect(second.saveTokenBinding({ ...grant, clientId: 'attacker' })).rejects.toThrow();
      for (const method of ['getTokenBinding', 'consumeTokenBinding'] as const) {
        expect(await second[method](kind, grant.tokenHash, 'attacker', grant.resource)).toBeNull();
        expect(
          await second[method](kind, grant.tokenHash, grant.clientId, 'wrong-resource')
        ).toBeNull();
        expect(
          await second[method](
            kind === 'device' ? 'refresh' : 'device',
            grant.tokenHash,
            grant.clientId,
            grant.resource
          )
        ).toBeNull();
      }
      const results = await Promise.all(
        [first, second, first].map((store) =>
          store.consumeTokenBinding(kind, grant.tokenHash, grant.clientId, grant.resource)
        )
      );
      expect(results.filter(Boolean)).toEqual([grant]);
      first.close();
      second.close();
      expect(
        await open().consumeTokenBinding(kind, grant.tokenHash, grant.clientId, grant.resource)
      ).toBeNull();
    }
  );

  it('consumes PKCE exactly once across independent connections', async () => {
    const first = open();
    const second = open();
    const entry = pkce();
    await first.savePkce(entry);
    const results = await Promise.all(
      [first, second, first].map((store) => store.consumePkce(entry.clientChallenge))
    );
    expect(results.filter(Boolean)).toEqual([entry]);
  });

  it('rejects grants at the exact expiration boundary, including after restart', async () => {
    vi.useFakeTimers();
    const store = open();
    const entry = pkce();
    const grant = binding();
    await store.savePkce(entry);
    await store.saveTokenBinding(grant);
    vi.setSystemTime(entry.expiresAt);
    expect(await store.consumePkce(entry.clientChallenge)).toBeNull();
    expect(
      await store.getTokenBinding(grant.kind, grant.tokenHash, grant.clientId, grant.resource)
    ).toBeNull();
    expect(
      await store.consumeTokenBinding(grant.kind, grant.tokenHash, grant.clientId, grant.resource)
    ).toBeNull();
    await store.savePkce(entry);
    await store.saveTokenBinding(grant);
    store.close();
    const reopened = open();
    expect(await reopened.consumePkce(entry.clientChallenge)).toBeNull();
    expect(
      await reopened.getTokenBinding(grant.kind, grant.tokenHash, grant.clientId, grant.resource)
    ).toBeNull();
    const db = new DatabaseSync(path);
    try {
      expect(db.prepare('SELECT count(*) AS count FROM pkce').get()!.count).toBe(0);
      expect(db.prepare('SELECT count(*) AS count FROM token_bindings').get()!.count).toBe(0);
    } finally {
      db.close();
    }
  });

  it('prunes expired entries on writes without expiring registered clients', async () => {
    const store = open();
    await store.saveClient(client);
    await store.savePkce(pkce({ expiresAt: 1 }));
    await store.saveTokenBinding({ ...binding(), expiresAt: 1 });
    await store.savePkce(pkce({ clientChallenge: 'fresh' }));
    expect(await store.getClient(client.clientId)).toEqual(client);
    const db = new DatabaseSync(path);
    try {
      expect(db.prepare('SELECT count(*) AS count FROM pkce').get()!.count).toBe(1);
      expect(db.prepare('SELECT count(*) AS count FROM token_bindings').get()!.count).toBe(0);
    } finally {
      db.close();
    }
  });

  it('treats SQL metacharacters as data', async () => {
    const store = open();
    const unusual = { ...client, clientId: "'; DROP TABLE registered_clients; --" };
    await store.saveClient(unusual);
    expect(await store.getClient(unusual.clientId)).toEqual(unusual);
    expect(await store.getClient("' OR 1=1 --")).toBeNull();
  });

  it('fails closed for invalid paths, corrupt files and unsupported schema versions', () => {
    expect(() => new SQLiteStorage(':memory:')).toThrow('absolute');
    const first = open();
    first.close();
    const db = new DatabaseSync(path);
    db.exec('PRAGMA user_version = 2');
    db.close();
    expect(() => open()).toThrow('Unsupported');
    writeFileSync(path, 'not a database');
    expect(() => open()).toThrow();
  });

  it.skipIf(process.platform === 'win32')(
    'protects directory, database and WAL sidecars with owner-only permissions',
    async () => {
      const first = open();
      await first.saveClient(client);
      for (const file of [path, path + '-wal', path + '-shm']) {
        expect(statSync(file).mode & 0o777).toBe(0o600);
      }
      expect(statSync(join(directory, 'private')).mode & 0o777).toBe(0o700);
      first.close();
      chmodSync(path, 0o666);
      chmodSync(join(directory, 'private'), 0o777);
      open();
      expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(statSync(join(directory, 'private')).mode & 0o777).toBe(0o700);
    }
  );

  it.skipIf(process.platform === 'win32')('refuses symlinked databases and sidecars', () => {
    const first = open();
    first.close();
    const target = join(directory, 'target');
    writeFileSync(target, 'do not change');
    symlinkSync(target, path + '-wal');
    expect(() => open()).toThrow('symlink');
    rmSync(path + '-wal');
    rmSync(path);
    symlinkSync(target, path);
    expect(() => open()).toThrow('symlink');
    expect(readFileSync(target, 'utf8')).toBe('do not change');
  });
});
