import { afterEach, expect, it, vi } from 'vitest';
import express from 'express';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Server } from 'node:http';
import { registerOAuthRoutes } from '../src/oauth-proxy.js';
import { SQLiteStorage } from '../src/storage/sqlite-storage.js';

const nativeFetch = globalThis.fetch;
const RESOURCE = 'https://mcp.example/mcp';
const REDIRECT = 'https://client.example/callback';
const SCOPE = 'api://test-api/access_as_user';
let directory: string;
let storage: SQLiteStorage;
let server: Server | undefined;
let url: string;
async function stop() {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server!.close((error) => (error ? reject(error) : resolve()))
    );
    server = undefined;
  }
  storage?.close();
}
async function start() {
  storage = new SQLiteStorage(join(directory, 'oauth.sqlite'));
  const app = express();
  app.use(express.json());
  registerOAuthRoutes(app, {
    publicUrl: 'https://mcp.example',
    tenantId: 'test-tenant',
    clientId: 'test-api',
    oauthClientId: 'test-oauth',
    oauthClientSecret: 'synthetic-upstream-secret',
    scopes: ['openid', 'offline_access', SCOPE],
    enableDynamicRegistration: true,
    allowedRedirectUris: [REDIRECT],
    requireResource: true,
    storage,
  });
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  url = 'http://127.0.0.1:' + (server!.address() as { port: number }).port;
}
async function post(path: string, body: object) {
  return nativeFetch(url + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
afterEach(async () => {
  await stop();
  vi.unstubAllGlobals();
  if (directory) rmSync(directory, { recursive: true, force: true });
});

it('accepts the original DCR secret, PKCE and refresh binding after server restarts; rejects wrong secrets and replay', async () => {
  directory = mkdtempSync(join(tmpdir(), 'oauth-http-restart-'));
  const upstream = vi.fn();
  vi.stubGlobal('fetch', (input: string | URL, init?: Parameters<typeof fetch>[1]) =>
    String(input).startsWith('https://login.microsoftonline.com/')
      ? upstream(input, init)
      : nativeFetch(input, init)
  );
  await start();
  const registered = await post('/register', { redirect_uris: [REDIRECT] });
  expect(registered.status).toBe(201);
  const client = (await registered.json()) as { client_id: string; client_secret: string };
  const verifier = randomBytes(32).toString('base64url');
  const authorize = () =>
    nativeFetch(
      url +
        '/authorize?' +
        new URLSearchParams({
          client_id: client.client_id,
          redirect_uri: REDIRECT,
          resource: RESOURCE,
          code_challenge: createHash('sha256').update(verifier).digest('base64url'),
          code_challenge_method: 'S256',
        }),
      { redirect: 'manual' }
    );
  await stop();
  await start();
  expect((await authorize()).status).toBe(302);
  await stop();
  await start();
  const exchange = {
    ...client,
    resource: RESOURCE,
    grant_type: 'authorization_code',
    code: 'synthetic-code',
    code_verifier: verifier,
    redirect_uri: REDIRECT,
  };
  for (const client_secret of ['wrong-secret', '', undefined]) {
    expect((await post('/token', { ...exchange, client_secret })).status).toBe(401);
  }
  expect(upstream).not.toHaveBeenCalled();
  upstream.mockResolvedValueOnce(
    new Response(
      JSON.stringify({ access_token: 'synthetic-access', refresh_token: 'synthetic-refresh' })
    )
  );
  expect((await post('/token', exchange)).status).toBe(200);
  expect((await post('/token', exchange)).status).toBe(400);
  expect(upstream).toHaveBeenCalledTimes(1);
  await stop();
  await start();
  const refresh = {
    ...client,
    resource: RESOURCE,
    grant_type: 'refresh_token',
    refresh_token: 'synthetic-refresh',
  };
  expect((await post('/token', { ...refresh, client_secret: 'wrong-secret' })).status).toBe(401);
  upstream.mockResolvedValueOnce(
    new Response(
      JSON.stringify({ access_token: 'synthetic-access-2', refresh_token: 'synthetic-refresh-2' })
    )
  );
  expect((await post('/token', refresh)).status).toBe(200);
  await stop();
  await start();
  expect((await post('/token', refresh)).status).toBe(400);
  expect(upstream).toHaveBeenCalledTimes(2);
});
