import logger from '../logger.js';
import { MemoryStorage } from './memory-storage.js';
import type { OAuthStorage } from './oauth-storage.js';

export type { OAuthStorage, PkceEntry, RegisteredClient, TokenBinding } from './oauth-storage.js';
export { hashClientSecret, verifyClientSecret } from './oauth-storage.js';
export { MemoryStorage } from './memory-storage.js';

export interface StorageFactoryOptions {
  tableName?: string;
}

// Resolves an OAuthStorage from environment:
// - OAUTH_SQLITE_PATH → SQLiteStorage (Node >=22.13, local persistent volume)
// - AZURE_STORAGE_ACCOUNT_NAME → TableStorage via DefaultAzureCredential (prod / Container Apps)
// - AZURE_STORAGE_CONNECTION_STRING → TableStorage via connection string (local dev / Azurite)
// - neither → MemoryStorage (stdio, tests, non-OAuth deployments)
export async function createOAuthStorage(
  options: StorageFactoryOptions = {}
): Promise<OAuthStorage> {
  const tableName = options.tableName ?? process.env.AZURE_STORAGE_TABLE_NAME ?? 'oauthstate';
  const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
  const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
  const sqlitePath = process.env.OAUTH_SQLITE_PATH;

  if (sqlitePath !== undefined) {
    if (!sqlitePath.trim()) throw new Error('OAUTH_SQLITE_PATH cannot be empty');
    if (accountName || connectionString) {
      throw new Error('Configure either OAUTH_SQLITE_PATH or Azure Table storage, not both');
    }
    const [major, minor] = process.versions.node.split('.').map(Number);
    if (major < 22 || (major === 22 && minor < 13)) {
      throw new Error('OAUTH_SQLITE_PATH requires Node.js 22.13 or newer');
    }
    const { SQLiteStorage } = await import('./sqlite-storage.js');
    const storage = new SQLiteStorage(sqlitePath);
    logger.info('OAuth state backed by SQLite');
    return storage;
  }

  if (accountName || connectionString) {
    const { TableStorage } = await import('./table-storage.js');
    return TableStorage.create({ accountName, connectionString, tableName });
  }

  logger.info('OAuth state backed by in-process memory (single-replica only)');
  return new MemoryStorage();
}
