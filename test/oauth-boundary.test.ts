import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import crypto from 'node:crypto';
import type { Server } from 'node:http';
import { registerOAuthRoutes } from '../src/oauth-proxy.js';
import { MemoryStorage } from '../src/storage/memory-storage.js';
import { hashClientSecret } from '../src/storage/oauth-storage.js';

const RESOURCE = 'https://mcp.example.com/mcp';
const REDIRECT = 'https://chatgpt.com/connector/oauth/test-only';
const SCOPE = 'api://22222222-2222-2222-2222-222222222222/access_as_user';
const nativeFetch = globalThis.fetch;
let store: MemoryStorage;
let server: Server;
let url: string;
let upstream: ReturnType<typeof vi.fn>;
type Client = { client_id: string; client_secret: string };

beforeEach(async () => {
  store = new MemoryStorage();
  upstream = vi.fn();
  vi.stubGlobal('fetch', (input: string | URL, init?: Parameters<typeof fetch>[1]) =>
    String(input).startsWith('https://login.microsoftonline.com/')
      ? upstream(input, init)
      : nativeFetch(input, init)
  );
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  registerOAuthRoutes(app, {
    publicUrl: 'https://mcp.example.com',
    tenantId: 'tenant',
    clientId: '22222222-2222-2222-2222-222222222222',
    oauthClientId: 'oauth-client',
    oauthClientSecret: 'test-secret',
    scopes: ['openid', 'profile', 'offline_access', SCOPE],
    enableDynamicRegistration: true,
    requireResource: true,
    allowedRedirectUris: [REDIRECT],
    storage: store,
  });
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  url = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve()))
  );
});

async function post(path: string, body: object) {
  return nativeFetch(url + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
async function register(): Promise<Client> {
  const response = await post('/register', { redirect_uris: [REDIRECT] });
  expect(response.status).toBe(201);
  return response.json() as Promise<Client>;
}
async function authorize(client: Client, overrides: Record<string, string> = {}) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const query = new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: REDIRECT,
    resource: RESOURCE,
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...overrides,
  });
  const response = await nativeFetch(url + '/authorize?' + query, { redirect: 'manual' });
  return { response, verifier };
}
async function issue(client: Client) {
  const { response, verifier } = await authorize(client);
  expect(response.status).toBe(302);
  const refreshToken = crypto.randomUUID();
  upstream.mockResolvedValueOnce(
    new Response(JSON.stringify({ access_token: 'test-access', refresh_token: refreshToken }))
  );
  const token = await post('/token', {
    ...client,
    resource: RESOURCE,
    grant_type: 'authorization_code',
    code: 'test-code',
    code_verifier: verifier,
    redirect_uri: REDIRECT,
  });
  return { token, refreshToken };
}
function refresh(client: Client, refreshToken: string, overrides: object = {}) {
  return post('/token', {
    ...client,
    resource: RESOURCE,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    ...overrides,
  });
}

describe('OAuth grant boundaries', () => {
  it.each([
    {},
    { redirect_uris: [] },
    { redirect_uris: [4] },
    { redirect_uris: ['https://attacker.example/callback'] },
    { redirect_uris: [REDIRECT + '#fragment'] },
    { redirect_uris: ['http://example.com/callback'] },
  ])('rejects invalid or unapproved registrations %j', async (body) => {
    expect((await post('/register', body)).status).toBe(400);
    expect(upstream).not.toHaveBeenCalled();
  });
  it.each([
    { resource: 'https://attacker.example/mcp' },
    { resource: '' },
    { scope: 'https://graph.microsoft.com/Directory.ReadWrite.All' },
    { code_challenge_method: '' },
    { code_challenge_method: 'plain' },
    { code_challenge: 'too-short' },
  ])('rejects invalid authorization inputs before redirecting %j', async (override) => {
    const client = await register();
    expect((await authorize(client, override)).response.status).toBe(400);
    expect(upstream).not.toHaveBeenCalled();
  });
  it('binds issued refresh tokens to their original client and rotates them once', async () => {
    const owner = await register();
    const attacker = await register();
    const { token, refreshToken } = await issue(owner);
    expect(token.status).toBe(200);
    expect(token.headers.get('cache-control')).toBe('no-store');
    const binding = await store.getTokenBinding(
      'refresh',
      hashClientSecret(refreshToken),
      owner.client_id,
      RESOURCE
    );
    expect(binding?.resource).toBe(RESOURCE);
    expect(JSON.stringify(binding)).not.toContain(refreshToken);
    upstream.mockClear();
    expect((await refresh(attacker, refreshToken)).status).toBe(400);
    expect((await refresh(owner, 'unissued-token')).status).toBe(400);
    expect(
      (await refresh(owner, refreshToken, { resource: 'https://other.example/mcp' })).status
    ).toBe(400);
    expect((await refresh(owner, refreshToken, { scope: 'Directory.ReadWrite.All' })).status).toBe(
      400
    );
    expect(upstream).not.toHaveBeenCalled();
    const rotated = crypto.randomUUID();
    upstream.mockResolvedValueOnce(
      new Response(JSON.stringify({ access_token: 'rotated', refresh_token: rotated }))
    );
    expect((await refresh(owner, refreshToken)).status).toBe(200);
    expect((await refresh(owner, refreshToken)).status).toBe(400);
    expect(upstream).toHaveBeenCalledTimes(1);
    expect(
      await store.getTokenBinding('refresh', hashClientSecret(rotated), owner.client_id, RESOURCE)
    ).not.toBeNull();
  });
  it('allows only one concurrent refresh to reach Entra', async () => {
    const client = await register();
    const { refreshToken } = await issue(client);
    upstream.mockClear();
    upstream.mockImplementation(
      async () =>
        new Response(
          JSON.stringify({ access_token: 'rotated', refresh_token: crypto.randomUUID() })
        )
    );
    const responses = await Promise.all([
      refresh(client, refreshToken),
      refresh(client, refreshToken),
    ]);
    expect(responses.map((r) => r.status).sort()).toEqual([200, 400]);
    expect(upstream).toHaveBeenCalledTimes(1);
  });
  it('does not release tokens when their ownership cannot be stored', async () => {
    const client = await register();
    vi.spyOn(store, 'saveTokenBinding').mockRejectedValueOnce(new Error('storage unavailable'));
    const { token, refreshToken } = await issue(client);
    expect(token.status).toBe(502);
    expect(await token.text()).not.toContain(refreshToken);
  });
  it('requires sign-in again after an uncertain refresh exchange', async () => {
    const client = await register();
    const { refreshToken } = await issue(client);
    upstream.mockClear();
    upstream.mockRejectedValueOnce(new Error('network timeout'));
    expect((await refresh(client, refreshToken)).status).toBe(502);
    expect((await refresh(client, refreshToken)).status).toBe(400);
    expect(upstream).toHaveBeenCalledTimes(1);
  });
  it('binds device codes before polling and keeps pending codes available only to their owner', async () => {
    const owner = await register();
    const attacker = await register();
    upstream.mockResolvedValueOnce(
      new Response(JSON.stringify({ device_code: 'bound-code', expires_in: 900 }))
    );
    expect((await post('/devicecode', { ...owner, resource: RESOURCE })).status).toBe(200);
    upstream.mockClear();
    const poll = (client: Client) =>
      post('/token', {
        ...client,
        resource: RESOURCE,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: 'bound-code',
      });
    expect((await poll(attacker)).status).toBe(400);
    expect(upstream).not.toHaveBeenCalled();
    upstream.mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'authorization_pending' }), { status: 400 })
    );
    expect((await poll(owner)).status).toBe(400);
    upstream.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ access_token: 'device-access', refresh_token: 'device-refresh' })
      )
    );
    expect((await poll(owner)).status).toBe(200);
    expect((await poll(owner)).status).toBe(400);
    expect(upstream).toHaveBeenCalledTimes(2);
    expect(
      await store.getTokenBinding(
        'refresh',
        hashClientSecret('device-refresh'),
        owner.client_id,
        RESOURCE
      )
    ).not.toBeNull();
  });
  it.each(['/devicecode', '/token'])(
    'requires a resource and rejects scope escalation at %s',
    async (path) => {
      const client = await register();
      expect(
        (await post(path, { ...client, grant_type: 'refresh_token', refresh_token: 'unknown' }))
          .status
      ).toBe(400);
      expect(
        (
          await post(path, {
            ...client,
            resource: RESOURCE,
            scope: 'Directory.ReadWrite.All',
            grant_type: 'refresh_token',
            refresh_token: 'unknown',
          })
        ).status
      ).toBe(400);
      expect(upstream).not.toHaveBeenCalled();
    }
  );
});
