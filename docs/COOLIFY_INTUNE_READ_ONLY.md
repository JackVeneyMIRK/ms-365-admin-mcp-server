# Intune audit deployment on Coolify

Keep the application stopped until the code review, credentials, exact client callback,
user allowlist and delegated permission plan have all been verified. The checks in CI
do not grant consent, connect to a tenant, publish an image, or deploy the application.

## Locked deployment profile

Set `MS365_ADMIN_MCP_DEPLOYMENT_PROFILE=intune-read-only` as a runtime variable.
The Dockerfile's existing command then starts HTTP on port 8080 with OAuth, one
allowlisted user, `access_as_user` enforcement, and exactly these four tools:

- `list-intune-settings-catalog-policies`
- `get-intune-settings-catalog-policy`
- `list-intune-settings-catalog-settings`
- `list-intune-settings-catalog-assignments`

The profile overrides general write flags, tool patterns, permissive tenant settings,
and service-to-service authentication. All four operations use delegated Graph GETs.
Outside this profile, explicit `--read-only` or `READ_ONLY=true` also wins over write flags.

Supply these runtime variables; never bake secrets into build arguments or commit them:

| Variable                               | Value                                                  |
| -------------------------------------- | ------------------------------------------------------ |
| `MS365_ADMIN_MCP_DEPLOYMENT_PROFILE`   | `intune-read-only`                                     |
| `MS365_ADMIN_MCP_PUBLIC_URL`           | HTTPS service origin, with no trailing slash           |
| `MS365_ADMIN_MCP_TENANT_ID`            | Your tenant GUID                                       |
| `MS365_ADMIN_MCP_AUTHORIZED_USER_OIDS` | One user's Entra object GUID, not their email          |
| `MS365_ADMIN_MCP_CLIENT_ID`            | Resource/API app client ID                             |
| `MS365_ADMIN_MCP_CLIENT_SECRET`        | Resource/API app secret value                          |
| `MS365_ADMIN_MCP_OAUTH_CLIENT_ID`      | Separate OAuth client app ID                           |
| `MS365_ADMIN_MCP_OAUTH_CLIENT_SECRET`  | OAuth client app secret value                          |
| `MS365_ADMIN_MCP_OAUTH_REDIRECT_URIS`  | Exact approved client callback URI(s), comma-separated |

The process refuses missing or malformed configuration. No tenant IDs, user IDs,
secrets or callback IDs are supplied by this repository.

## Microsoft app registrations

1. Create a single-tenant **Intune Audit MCP API** registration. Configure v2 access
   tokens and expose the delegated scope `api://<API_CLIENT_ID>/access_as_user`.
   Stage only Microsoft Graph **delegated** `DeviceManagementConfiguration.Read.All`.
   This supports the four audit routes; no Graph application or write permission is needed.
2. Create a separate single-tenant **Intune Audit MCP OAuth Client** registration.
   Stage only the API app's delegated `access_as_user` permission. Configure the
   exact client callback as a **Web** redirect URI. This is a confidential client;
   do not enable implicit grant or public-client flows for the initial browser setup.
3. Create short-lived secrets only when ready to enter their values directly in
   Coolify. The two registrations need different IDs and their own secrets.
4. Review the staged permissions, tenant, user and credentials before granting
   consent. Check the user's applicable Intune rights and tenant licensing. Do not
   add broader permissions to work around a failed test.

Microsoft's [configuration policy permission table](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfigv2-devicemanagementconfigurationpolicy-list?view=graph-rest-beta)
and [on-behalf-of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
describe this delegated model.

## ChatGPT and Codex callbacks

These are separate clients. Start with one and copy its exact displayed callback.
For a new ChatGPT connection, obtain the callback from its server management flow;
do not invent the callback ID or assume the legacy shared redirect works.
Register the same exact URI in Entra and `MS365_ADMIN_MCP_OAUTH_REDIRECT_URIS`.
Codex may use a loopback callback; include its exact address and port only after
confirming them. Do not add arbitrary redirect URLs to make an error disappear.

This proxy redirects directly through Entra and does **not** advertise RFC 9207
issuer identification. It therefore does not claim eligibility for OpenAI's stable
shared redirect URI. See [OpenAI authentication](https://developers.openai.com/plugins/build/auth)
and [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp).

Clients must send the advertised resource URL, `<PUBLIC_URL>/mcp`, on authorization,
token and device requests in the locked profile. Explicitly wrong resources are
rejected in every mode. OAuth scopes are restricted to this API plus OIDC scopes.

## Coolify and acceptance checks

- Use the repository Dockerfile (Node 22), port 8080, one replica, manual deployment,
  and a reviewed commit SHA. Disable preview deployments. Keep secrets runtime-only.
- Route only the intended HTTPS hostname through the trusted reverse proxy. Do not
  publish port 8080 directly or leave alternate public hostnames configured.
- Plan a private test path first. A public ChatGPT connection needs reachability;
  do not expose the service to solve that until the launch conditions are confirmed.
- Confirm health, unauthenticated rejection, tenant/audience/user rejection, scope
  enforcement, exactly four tools, unavailable write tools, one permitted read,
  refresh rotation and cross-client rejection. Exercise actual ChatGPT/Codex sign-in
  and refresh with the configured callback before calling the integration complete.

### Persistent OAuth storage

For a single Coolify replica, configure **both** of the following before the next
approved deployment:

| Setting                           | Value                                           |
| --------------------------------- | ----------------------------------------------- |
| Runtime environment variable      | `OAUTH_SQLITE_PATH=/data/oauth.sqlite`          |
| Persistent Storage → Volume Mount | Name: `oauth-state`; Destination Path: `/data`  |
| Container user                    | Existing `mcpuser`, UID/GID `1001:1001`         |
| Directory / file permissions      | `/data`: `0700`; database and sidecars: `0600`  |
| Replicas                          | One, on the same server with local disk storage |

Use the repository Dockerfile with Node 22.13+ (or Node 24). SQLite uses Node's
built-in `node:sqlite` module, which is experimental in Node 22 and may emit an
experimental warning. The image prepares `/data` with the service user's ownership
and `0700` permissions. A new, empty Docker named volume inherits that directory's
ownership. Reuse the **same named volume** on subsequent deployments. Mount the
whole directory, not just the database: SQLite also writes `oauth.sqlite-wal` and
`oauth.sqlite-shm`. Do not add `OAUTH_SQLITE_PATH` as a build argument.

For an existing volume or a host directory bind mount, an administrator must first
make the dedicated directory owned by `1001:1001` with mode `0700`, and any existing
SQLite database/sidecars owned by `1001:1001` with mode `0600`. The process stays
non-root and fails startup on inaccessible, foreign-owned, symlinked or corrupt
storage. It does not repair ownership by escalating privileges or silently switch
to memory. Windows development requires a user-private directory ACL; POSIX modes
are enforced and tested in the Linux container.

Leave `AZURE_STORAGE_ACCOUNT_NAME` and `AZURE_STORAGE_CONNECTION_STRING` unset when
selecting SQLite. Configuring either alongside `OAUTH_SQLITE_PATH` fails startup
to prevent accidentally using the wrong database. Existing Azure Table storage
remains available when `OAUTH_SQLITE_PATH` is unset, including managed identity,
connection strings, and `AZURE_STORAGE_TABLE_NAME`. With no storage configuration,
the existing memory backend remains the default.

SQLite stores registered clients (secret hashes, approved redirects, creation
time), PKCE bridges (including the upstream verifier and expiration), and token
bindings (only refresh/device token digests, client/resource/scope and expiration).
Treat the database and backups as sensitive OAuth state. Registrations have no
automatic expiry, consistent with the existing backends. Expired PKCE and token
bindings are always rejected; they are pruned at startup and when saving a PKCE
bridge or token binding. Read-only/idle stores may retain expired rows until then.
PKCE and token consumption are atomic across connections; consumed grants remain
consumed after restart. This does not extend the existing session deadlines.

The first switch from memory cannot recover registrations or grants already lost
at restart. Recreate the client connection/register and sign in once after enabling
persistence; later restarts preserve those new registrations. There is no automatic
migration between memory, Azure Table and SQLite. Never restore an old live database
snapshot casually: it can resurrect consumed grants. For backups, stop the service
and copy the entire directory, or use a SQLite-consistent backup procedure. Keep
backups private and off-host, and require fresh sign-in after disaster recovery.

Use local disk; do not share a WAL database through NFS/SMB or between deployment
servers. Use Azure Table for distributed deployments. See
[Coolify storage mounts](https://coolify.io/docs/core/persistent-storage/storage-mounts/overview)
for volume versus directory mount behavior. CI tests an unpublished image as UID
1001 with synthetic state, no network, and three replacement containers sharing
one volume. It does not deploy or access tenant credentials.

Memory storage is single-process: restart loses registrations and grant bindings.
Azure Table expired binding rows require periodic storage maintenance; expired
grants are rejected even before cleanup.

Refresh tokens have a local 24-hour session limit and are consumed atomically before
exchange; rotations retain that original deadline. An upstream timeout or failure
requires a new sign-in. Device codes are bound to the requesting client and expire
within 15 minutes. Previously issued unbound tokens and empty redirect registrations
must be replaced. The old single-app/Graph-audience OAuth workaround is no longer supported.

Rollback means stop the application and restore the last reviewed secure configuration.
Do not restore a public deployment of the previous OAuth implementation.
