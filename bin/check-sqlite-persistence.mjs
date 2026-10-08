// CI-only synthetic state; invoked in separate, network-isolated containers.
import assert from 'node:assert/strict';
import { statSync } from 'node:fs';
import { createOAuthStorage, hashClientSecret, verifyClientSecret } from '../dist/storage/index.js';

assert.equal(process.getuid(), 1001);
assert.equal(process.getgid(), 1001);
const store = await createOAuthStorage();
const path = process.env.OAUTH_SQLITE_PATH;
const resource = 'https://mcp.example/mcp';
const secret = 'synthetic-ci-client-secret';
const hash = hashClientSecret('synthetic-ci-upstream-token');
const phase = process.argv[2];
if (phase === 'write') {
  await store.saveClient({
    clientId: 'ci-client',
    clientSecretHash: hashClientSecret(secret),
    redirectUris: ['https://client.example/cb'],
    createdAt: Date.now(),
  });
  await store.savePkce({
    clientChallenge: 'ci-challenge',
    serverVerifier: 'ci-verifier',
    redirectUri: 'https://client.example/cb',
    clientId: 'ci-client',
    expiresAt: Date.now() + 300_000,
  });
  for (const kind of ['refresh', 'device'])
    await store.saveTokenBinding({
      kind,
      tokenHash: hash,
      clientId: 'ci-client',
      resource,
      scope: 'access_as_user',
      expiresAt: Date.now() + 300_000,
    });
  for (const file of [path, path + '-wal', path + '-shm'])
    assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(statSync('/data').mode & 0o777, 0o700);
  // Deliberately exit without close/checkpoint to exercise WAL recovery.
  process.exit(0);
}
assert.ok(['read', 'consumed'].includes(phase));
const client = await store.getClient('ci-client');
assert.ok(client);
assert.equal(verifyClientSecret(secret, client.clientSecretHash), true);
assert.equal(verifyClientSecret('wrong', client.clientSecretHash), false);
const pkce = await store.consumePkce('ci-challenge');
assert.equal(pkce?.serverVerifier ?? null, phase === 'read' ? 'ci-verifier' : null);
for (const kind of ['refresh', 'device']) {
  assert.equal(await store.consumeTokenBinding(kind, hash, 'attacker', resource), null);
  const grant = await store.consumeTokenBinding(kind, hash, 'ci-client', resource);
  assert.equal(grant?.scope ?? null, phase === 'read' ? 'access_as_user' : null);
}
store.close();
console.log(`SQLite ${phase} persistence check passed as UID/GID 1001`);
