import { describe, it, expect, afterEach, vi } from 'vitest';
import { applyDeploymentProfile, INTUNE_READ_TOOLS } from '../src/deployment-profile.js';
import type { CommandOptions } from '../src/cli.js';

const env = {
  MS365_ADMIN_MCP_DEPLOYMENT_PROFILE: 'intune-read-only',
  MS365_ADMIN_MCP_TENANT_ID: '11111111-1111-1111-1111-111111111111',
  MS365_ADMIN_MCP_CLIENT_ID: '22222222-2222-2222-2222-222222222222',
  MS365_ADMIN_MCP_OAUTH_CLIENT_ID: '33333333-3333-3333-3333-333333333333',
  MS365_ADMIN_MCP_AUTHORIZED_USER_OIDS: '44444444-4444-4444-4444-444444444444',
  MS365_ADMIN_MCP_CLIENT_SECRET: 'test-resource-secret',
  MS365_ADMIN_MCP_OAUTH_CLIENT_SECRET: 'test-oauth-secret',
  MS365_ADMIN_MCP_PUBLIC_URL: 'https://mcp.example.com',
  MS365_ADMIN_MCP_OAUTH_REDIRECT_URIS: 'https://chatgpt.com/connector/oauth/test-only',
};

describe('locked Intune deployment profile', () => {
  it('cannot be broadened by general-purpose flags or environment overrides', () => {
    const options: CommandOptions = {
      allowWrites: true,
      readOnly: false,
      enabledTools: '.*',
      maxRiskLevel: 'critical',
      allowedClients: 'other-client',
      allowAnyTenantUser: true,
      requiredUserScopes: '',
      transport: 'stdio',
      dynamicRegistration: false,
    };
    applyDeploymentProfile(options, { ...env, READ_ONLY: 'false', ENABLED_TOOLS: '.*' });
    expect(options).toMatchObject({
      readOnly: true,
      allowWrites: false,
      enabledTools: INTUNE_READ_TOOLS,
      maxRiskLevel: 'low',
      allowedClients: undefined,
      allowAnyTenantUser: false,
      requiredUserScopes: 'access_as_user',
      authorizedUsers: env.MS365_ADMIN_MCP_AUTHORIZED_USER_OIDS,
      transport: 'http',
      oauthMode: true,
      dynamicRegistration: true,
    });
  });
  it.each(Object.keys(env).filter((key) => key !== 'MS365_ADMIN_MCP_DEPLOYMENT_PROFILE'))(
    'refuses to start without %s',
    (key) => {
      expect(() => applyDeploymentProfile({}, { ...env, [key]: '' })).toThrow(/requires|require/);
    }
  );
  it.each([
    { MS365_ADMIN_MCP_AUTHORIZED_USER_OIDS: 'user@example.com' },
    {
      MS365_ADMIN_MCP_AUTHORIZED_USER_OIDS:
        env.MS365_ADMIN_MCP_AUTHORIZED_USER_OIDS + ',another-user',
    },
    { MS365_ADMIN_MCP_PUBLIC_URL: 'http://mcp.example.com' },
    { MS365_ADMIN_MCP_PUBLIC_URL: 'https://mcp.example.com/path' },
    { MS365_ADMIN_MCP_OAUTH_CLIENT_ID: env.MS365_ADMIN_MCP_CLIENT_ID },
    { MS365_ADMIN_MCP_OAUTH_REDIRECT_URIS: 'https://example.com/#fragment' },
  ])('refuses unsafe profile configuration %j', (override) => {
    expect(() => applyDeploymentProfile({}, { ...env, ...override })).toThrow();
  });
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.resetModules();
});
describe('read-only precedence at the actual CLI boundary', () => {
  it.each([
    { args: ['--read-only', '--allow-writes'], value: 'false' },
    { args: ['--read-only', '--max-risk-level', 'critical'], value: '0' },
    { args: ['--allow-writes'], value: 'true' },
    { args: ['--max-risk-level', 'critical'], value: '1' },
  ])('keeps writes disabled for %j', async ({ args, value }) => {
    vi.stubEnv('READ_ONLY', value);
    vi.stubEnv('MS365_ADMIN_MCP_DEPLOYMENT_PROFILE', '');
    vi.spyOn(process, 'argv', 'get').mockReturnValue(['node', 'cli', ...args]);
    const { parseArgs } = await import('../src/cli.js');
    expect(parseArgs()).toMatchObject({ readOnly: true, allowWrites: false });
  });
});
