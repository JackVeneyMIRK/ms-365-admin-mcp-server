import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createOAuthStorage, MemoryStorage } from '../src/storage/index.js';
import { SQLiteStorage } from '../src/storage/sqlite-storage.js';
import { TableStorage } from '../src/storage/table-storage.js';

beforeEach(() => {
  for (const name of [
    'OAUTH_SQLITE_PATH',
    'AZURE_STORAGE_ACCOUNT_NAME',
    'AZURE_STORAGE_CONNECTION_STRING',
    'AZURE_STORAGE_TABLE_NAME',
  ])
    vi.stubEnv(name, undefined);
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('OAuth storage selection', () => {
  it('retains memory storage when no persistent backend is configured', async () => {
    expect(await createOAuthStorage()).toBeInstanceOf(MemoryStorage);
  });
  it.each(['AZURE_STORAGE_ACCOUNT_NAME', 'AZURE_STORAGE_CONNECTION_STRING'])(
    'preserves %s and table name options',
    async (name) => {
      vi.stubEnv(name, 'test-only');
      vi.stubEnv('AZURE_STORAGE_TABLE_NAME', 'envtable');
      const fake = new MemoryStorage();
      const create = vi
        .spyOn(TableStorage, 'create')
        .mockResolvedValue(fake as unknown as TableStorage);
      expect(await createOAuthStorage()).toBe(fake);
      expect(create).toHaveBeenLastCalledWith({
        accountName: process.env.AZURE_STORAGE_ACCOUNT_NAME,
        connectionString: process.env.AZURE_STORAGE_CONNECTION_STRING,
        tableName: 'envtable',
      });
      await createOAuthStorage({ tableName: 'explicit' });
      expect(create).toHaveBeenLastCalledWith(expect.objectContaining({ tableName: 'explicit' }));
    }
  );
  it('opens SQLite only when explicitly configured and never falls back on failure', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'oauth-factory-'));
    try {
      const path = join(directory, 'oauth.sqlite');
      vi.stubEnv('OAUTH_SQLITE_PATH', path);
      const store = await createOAuthStorage();
      expect(store).toBeInstanceOf(SQLiteStorage);
      (store as SQLiteStorage).close();
      writeFileSync(path, 'corrupt');
      await expect(createOAuthStorage()).rejects.toThrow();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
  it('rejects empty and ambiguous SQLite configuration', async () => {
    vi.stubEnv('OAUTH_SQLITE_PATH', '');
    await expect(createOAuthStorage()).rejects.toThrow('empty');
    vi.stubEnv('OAUTH_SQLITE_PATH', '/data/oauth.sqlite');
    for (const name of ['AZURE_STORAGE_ACCOUNT_NAME', 'AZURE_STORAGE_CONNECTION_STRING']) {
      vi.stubEnv(name, 'test-only');
      await expect(createOAuthStorage()).rejects.toThrow('not both');
      vi.stubEnv(name, undefined);
    }
  });
});
