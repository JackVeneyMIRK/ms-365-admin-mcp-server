import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
} from 'node:fs';
import { dirname, isAbsolute, parse } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { OAuthStorage, PkceEntry, RegisteredClient, TokenBinding } from './oauth-storage.js';

// The containing directory must be dedicated to OAuth state and owned by the
// service user. Protect it before SQLite can create journals or WAL sidecars.
function secureFile(path: string, create: boolean): void {
  let fd: number;
  try {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error('OAuth SQLite files cannot be symlinks');
    if (!stat.isFile() || stat.nlink !== 1)
      throw new Error('OAuth SQLite files must be regular, unshared files');
  } catch (error) {
    if ((error as { code?: string }).code !== 'ENOENT') throw error;
  }
  try {
    fd = openSync(
      path,
      constants.O_RDWR | constants.O_NOFOLLOW | (create ? constants.O_CREAT : 0),
      0o600
    );
  } catch (error) {
    if (!create && (error as { code?: string }).code === 'ENOENT') return;
    throw error;
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1)
      throw new Error('OAuth SQLite files must be regular, unshared files');
    if (process.getuid && stat.uid !== process.getuid())
      throw new Error('OAuth SQLite files must be owned by the service user');
    fchmodSync(fd, 0o600);
  } finally {
    closeSync(fd);
  }
}

type PkceRow = Omit<PkceEntry, 'clientState' | 'resource' | 'scope'> & {
  clientState: string | null;
  resource: string | null;
  scope: string | null;
};

/** Local disk only: SQLite WAL requires reliable local filesystem locking. */
export class SQLiteStorage implements OAuthStorage {
  private db: DatabaseSync;
  private closed = false;

  constructor(path: string) {
    if (!isAbsolute(path) || dirname(path) === parse(path).root) {
      throw new Error(
        'OAUTH_SQLITE_PATH must be an absolute file path inside a dedicated directory'
      );
    }
    const directory = dirname(path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw new Error('OAuth SQLite directory must not be a symlink');
    if (process.getuid && stat.uid !== process.getuid())
      throw new Error(
        'OAuth SQLite directory must be owned by the service user (container UID 1001)'
      );
    chmodSync(directory, 0o700);
    secureFile(path, true);
    for (const suffix of ['-wal', '-shm', '-journal']) secureFile(path + suffix, false);

    this.db = new DatabaseSync(path);
    try {
      this.db.exec(
        'PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;'
      );
      this.db.exec('BEGIN IMMEDIATE');
      const version = this.db.prepare('PRAGMA user_version').get()!.user_version;
      if (version !== 0 && version !== 1)
        throw new Error('Unsupported OAuth SQLite schema version');
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS registered_clients (
          clientId TEXT PRIMARY KEY NOT NULL,
          clientSecretHash TEXT NOT NULL,
          redirectUris TEXT NOT NULL CHECK(json_valid(redirectUris)),
          createdAt INTEGER NOT NULL
        ) STRICT;
        CREATE TABLE IF NOT EXISTS pkce (
          clientChallenge TEXT PRIMARY KEY NOT NULL,
          serverVerifier TEXT NOT NULL,
          redirectUri TEXT NOT NULL,
          clientId TEXT NOT NULL,
          clientState TEXT,
          resource TEXT,
          scope TEXT,
          expiresAt INTEGER NOT NULL
        ) STRICT;
        CREATE INDEX IF NOT EXISTS pkce_expiration ON pkce(expiresAt);
        CREATE TABLE IF NOT EXISTS token_bindings (
          kind TEXT NOT NULL CHECK(kind IN ('refresh', 'device')),
          tokenHash TEXT NOT NULL,
          clientId TEXT NOT NULL,
          resource TEXT NOT NULL,
          scope TEXT NOT NULL,
          expiresAt INTEGER NOT NULL,
          PRIMARY KEY(kind, tokenHash)
        ) STRICT;
        CREATE INDEX IF NOT EXISTS token_binding_expiration ON token_bindings(expiresAt);
        PRAGMA user_version = 1;
        COMMIT;
      `);
      this.pruneExpired();
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  close(): void {
    if (!this.closed) this.db.close();
    this.closed = true;
  }

  private pruneExpired(): void {
    const now = Date.now();
    this.db.prepare('DELETE FROM pkce WHERE expiresAt <= ?').run(now);
    this.db.prepare('DELETE FROM token_bindings WHERE expiresAt <= ?').run(now);
  }

  async saveClient(client: RegisteredClient): Promise<void> {
    // INSERT, not REPLACE: a duplicate registration must never change its owner/secret.
    this.db
      .prepare('INSERT INTO registered_clients VALUES (?, ?, ?, ?)')
      .run(
        client.clientId,
        client.clientSecretHash,
        JSON.stringify(client.redirectUris),
        client.createdAt
      );
  }

  async getClient(clientId: string): Promise<RegisteredClient | null> {
    const row = this.db
      .prepare('SELECT * FROM registered_clients WHERE clientId = ?')
      .get(clientId);
    if (!row) return null;
    return {
      clientId: row.clientId as string,
      clientSecretHash: row.clientSecretHash as string,
      redirectUris: JSON.parse(row.redirectUris as string),
      createdAt: row.createdAt as number,
    };
  }

  async savePkce(entry: PkceEntry): Promise<void> {
    this.pruneExpired();
    this.db
      .prepare('INSERT OR REPLACE INTO pkce VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(
        entry.clientChallenge,
        entry.serverVerifier,
        entry.redirectUri,
        entry.clientId,
        entry.clientState ?? null,
        entry.resource ?? null,
        entry.scope ?? null,
        entry.expiresAt
      );
  }

  async consumePkce(clientChallenge: string): Promise<PkceEntry | null> {
    // DELETE RETURNING is one atomic statement, even across independent processes.
    const row = this.db
      .prepare('DELETE FROM pkce WHERE clientChallenge = ? RETURNING *')
      .get(clientChallenge) as PkceRow | undefined;
    if (!row || row.expiresAt <= Date.now()) return null;
    return {
      ...row,
      clientState: row.clientState ?? undefined,
      resource: row.resource ?? undefined,
      scope: row.scope ?? undefined,
    };
  }

  async saveTokenBinding(binding: TokenBinding): Promise<void> {
    this.pruneExpired();
    this.db
      .prepare('INSERT INTO token_bindings VALUES (?, ?, ?, ?, ?, ?)')
      .run(
        binding.kind,
        binding.tokenHash,
        binding.clientId,
        binding.resource,
        binding.scope,
        binding.expiresAt
      );
  }

  async getTokenBinding(
    kind: TokenBinding['kind'],
    tokenHash: string,
    clientId: string,
    resource: string
  ): Promise<TokenBinding | null> {
    return (
      (this.db
        .prepare(
          `SELECT * FROM token_bindings
      WHERE kind = ? AND tokenHash = ? AND clientId = ? AND resource = ? AND expiresAt > ?`
        )
        .get(kind, tokenHash, clientId, resource, Date.now()) as TokenBinding | undefined) ?? null
    );
  }

  async consumeTokenBinding(
    kind: TokenBinding['kind'],
    tokenHash: string,
    clientId: string,
    resource: string
  ): Promise<TokenBinding | null> {
    const row = this.db
      .prepare(
        `DELETE FROM token_bindings
      WHERE kind = ? AND tokenHash = ? AND clientId = ? AND resource = ? RETURNING *`
      )
      .get(kind, tokenHash, clientId, resource) as TokenBinding | undefined;
    return row && row.expiresAt > Date.now() ? row : null;
  }
}
