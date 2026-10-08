import { describe, it, expect, vi, afterEach } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { startHttpServer } from '../src/http-server.js';
import AdminGraphServer from '../src/server.js';
import type AuthManager from '../src/auth.js';
import { INTUNE_READ_TOOLS } from '../src/deployment-profile.js';

vi.mock('../src/http-server.js', () => ({ startHttpServer: vi.fn() }));
vi.mock('../src/secrets.js', () => ({
  getSecrets: vi.fn(async () => ({
    tenantId: '11111111-1111-1111-1111-111111111111',
    clientId: '22222222-2222-2222-2222-222222222222',
    clientSecret: 'test-resource-secret',
    oauthClientId: '33333333-3333-3333-3333-333333333333',
    oauthClientSecret: 'test-oauth-secret',
  })),
}));
afterEach(() => {
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

describe('HTTP server authorization wiring', () => {
  it('retains caller roles and restricts audiences to the MCP API', async () => {
    const server = new AdminGraphServer({} as AuthManager, {
      transport: 'http',
      oauthMode: true,
      publicUrl: 'https://mcp.example.com',
      authorizedUsers: '44444444-4444-4444-4444-444444444444',
      readOnly: true,
      enabledTools: INTUNE_READ_TOOLS,
      deploymentProfile: 'intune-read-only',
      requiredUserScopes: 'access_as_user',
      oauthRedirectUris: 'https://chatgpt.com/connector/oauth/test',
    });
    await server.initialize('test');
    const create = vi.spyOn(server, 'createServer');
    await server.start();
    const config = vi.mocked(startHttpServer).mock.calls[0][0];
    expect(config.userTokenValidatorOptions).toMatchObject({
      expectedAudiences: [
        '22222222-2222-2222-2222-222222222222',
        'api://22222222-2222-2222-2222-222222222222',
      ],
      authorizedUserOids: ['44444444-4444-4444-4444-444444444444'],
      allowAnyTenantUser: false,
      requiredScopes: ['access_as_user'],
    });
    expect(config.tokenValidatorOptions).toBeUndefined();
    expect(config.oauthProxyOptions).toMatchObject({
      requireResource: true,
      allowedRedirectUris: ['https://chatgpt.com/connector/oauth/test'],
    });
    config.createServer('user-token', []);
    expect(create).toHaveBeenLastCalledWith('user-token', []);
    config.createServer('user-token', ['MCP.Write.Low']);
    expect(create).toHaveBeenLastCalledWith('user-token', ['MCP.Write.Low']);
  });
  it('registers exactly the fifteen audit tools for the locked filter', async () => {
    const register = vi.spyOn(McpServer.prototype, 'tool');
    const server = new AdminGraphServer({} as AuthManager, {
      readOnly: true,
      enabledTools: INTUNE_READ_TOOLS,
    });
    await server.initialize('test');
    expect(register.mock.calls.map((call) => call[0]).sort()).toEqual([
      'get-intune-configuration-policy-noncompliance-report',
      'get-intune-configuration-setting-noncompliance-report',
      'get-intune-settings-catalog-policy',
      'list-intune-compliance-policy-assignments',
      'list-intune-compliance-policy-device-statuses',
      'list-intune-device-compliance-policies',
      'list-intune-device-configurations',
      'list-intune-device-encryption-states',
      'list-intune-legacy-policy-assignments',
      'list-intune-legacy-policy-device-statuses',
      'list-intune-legacy-policy-setting-statuses',
      'list-intune-managed-devices',
      'list-intune-settings-catalog-assignments',
      'list-intune-settings-catalog-policies',
      'list-intune-settings-catalog-settings',
    ]);
  });
});
