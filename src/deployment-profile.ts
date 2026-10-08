import type { CommandOptions } from './cli.js';
import { isValidRedirectUri } from './oauth-proxy.js';

export const INTUNE_READ_TOOLS =
  '^(list-intune-(settings-catalog-(policies|settings|assignments)|managed-devices|device-(compliance-policies|configurations|encryption-states)|legacy-policy-(assignments|device-statuses|setting-statuses)|compliance-setting-status-summaries|device-configuration-status-summary|compliance-policy-(assignments|device-statuses))|get-intune-(settings-catalog-policy|configuration-(policy|setting)-noncompliance-report))$';

// This opt-in container profile is deliberately independent of general-purpose
// flags. Environment overrides and future defaults must not broaden its tools.
export function applyDeploymentProfile(
  options: CommandOptions,
  env: Record<string, string | undefined> = process.env
): void {
  const profile = options.deploymentProfile ?? env.MS365_ADMIN_MCP_DEPLOYMENT_PROFILE;
  if (!profile) return;
  if (profile !== 'intune-read-only') throw new Error('Unknown deployment profile');
  const required = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) throw new Error(`Deployment profile requires ${name}`);
    return value;
  };
  const guid = (name: string): string => {
    const value = required(name);
    if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value)) {
      throw new Error(`Deployment profile requires a GUID in ${name}`);
    }
    return value;
  };
  guid('MS365_ADMIN_MCP_TENANT_ID');
  const resourceId = guid('MS365_ADMIN_MCP_CLIENT_ID');
  const oauthId = guid('MS365_ADMIN_MCP_OAUTH_CLIENT_ID');
  if (resourceId.toLowerCase() === oauthId.toLowerCase()) {
    throw new Error('Deployment profile requires two distinct app registrations');
  }
  required('MS365_ADMIN_MCP_CLIENT_SECRET');
  required('MS365_ADMIN_MCP_OAUTH_CLIENT_SECRET');
  const userId = guid('MS365_ADMIN_MCP_AUTHORIZED_USER_OIDS');
  const publicUrl = required('MS365_ADMIN_MCP_PUBLIC_URL');
  const url = new URL(publicUrl);
  if (url.protocol !== 'https:' || url.origin !== publicUrl) {
    throw new Error('Deployment profile requires an HTTPS public origin without a trailing slash');
  }
  const redirects = required('MS365_ADMIN_MCP_OAUTH_REDIRECT_URIS')
    .split(',')
    .map((s) => s.trim());
  if (redirects.length > 16 || !redirects.every(isValidRedirectUri)) {
    throw new Error('Deployment profile requires exact HTTPS or loopback OAuth redirect URIs');
  }
  if (options.verifyLogin) {
    throw new Error(
      'The deployment profile uses delegated access; app-only login checks are disabled'
    );
  }
  Object.assign(options, {
    deploymentProfile: profile,
    transport: 'http',
    port: '8080',
    host: '0.0.0.0',
    oauthMode: true,
    publicUrl,
    authorizedUsers: userId,
    oauthRedirectUris: redirects.join(','),
    readOnly: true,
    allowWrites: false,
    maxRiskLevel: 'low',
    enabledTools: INTUNE_READ_TOOLS,
    allowedClients: undefined,
    allowAnyTenantUser: false,
    requiredUserScopes: 'access_as_user',
    dynamicRegistration: true,
    logRedactUpn: true,
  });
}
