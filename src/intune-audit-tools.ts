/**
 * Read-only Intune configuration, compliance, managed-device, and encryption inspection.
 * Graph: deviceManagement read endpoints on v1.0 and beta
 *
 * These tools use fixed Graph paths, with validated IDs for policy-specific reads.
 * They cannot make write requests or retrieve BitLocker recovery-key material.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type GraphClient from './graph-client.js';
import { wrapUntrustedContent } from './untrusted-envelope.js';

const base = '/deviceManagement/configurationPolicies';
const uuid = z.string().uuid().describe('Intune configuration policy ID (GUID)');

type ReadTool = {
  name: string;
  description: string;
  schema: Record<string, z.ZodTypeAny>;
  path: (params: Record<string, unknown>) => string;
  apiVersion?: 'v1.0' | 'beta';
};

const tools: ReadTool[] = [
  {
    name: 'list-intune-settings-catalog-policies',
    description:
      'Read Intune modern configuration policies (Settings Catalog and endpoint security). Returns policy IDs, names, platform, technology, and @odata.nextLink when paginated.',
    schema: {},
    path: () => base,
  },
  {
    name: 'get-intune-settings-catalog-policy',
    description: 'Read metadata for a single Intune modern configuration policy.',
    schema: { policyId: uuid },
    path: ({ policyId }) => `${base}/${encodeURIComponent(String(policyId))}`,
  },
  {
    name: 'list-intune-settings-catalog-settings',
    description:
      'Read individual settings and values for an Intune modern configuration policy, including BitLocker and Windows Hello settings.',
    schema: { policyId: uuid },
    path: ({ policyId }) => `${base}/${encodeURIComponent(String(policyId))}/settings`,
  },
  {
    name: 'list-intune-settings-catalog-assignments',
    description: 'Read group and filter assignments for an Intune modern configuration policy.',
    schema: { policyId: uuid },
    path: ({ policyId }) => `${base}/${encodeURIComponent(String(policyId))}/assignments`,
  },
  {
    name: 'list-intune-managed-devices',
    description:
      'Read Intune managed device inventory and compliance status. Results may be paginated; no remote actions or recovery keys.',
    schema: {},
    path: () => '/deviceManagement/managedDevices',
    apiVersion: 'v1.0',
  },
  {
    name: 'list-intune-device-compliance-policies',
    description: 'Read Intune device compliance policy metadata.',
    schema: {},
    path: () => '/deviceManagement/deviceCompliancePolicies',
    apiVersion: 'v1.0',
  },
  {
    name: 'list-intune-device-configurations',
    description:
      'Read Intune legacy device configuration profiles (distinct from Settings Catalog).',
    schema: {},
    path: () => '/deviceManagement/deviceConfigurations',
    apiVersion: 'v1.0',
  },
  {
    name: 'list-intune-device-encryption-states',
    description:
      'Read device encryption status summaries; does not retrieve BitLocker recovery keys.',
    schema: {},
    path: () => '/deviceManagement/managedDeviceEncryptionStates',
    apiVersion: 'beta',
  },
];

/** Restrict tool exposure independently from Graph permissions and the read-only switch. */
export function registerIntuneAuditTools(
  server: McpServer,
  graphClient: GraphClient,
  enabledToolsPattern?: string
): number {
  const filter = enabledToolsPattern ? new RegExp(enabledToolsPattern, 'i') : undefined;
  let count = 0;
  for (const tool of tools) {
    if (filter && !filter.test(tool.name)) continue;
    server.tool(
      tool.name,
      tool.description,
      tool.schema,
      {
        title: tool.name,
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: true,
      },
      async (params) => {
        const result = await graphClient.graphRequest(tool.path(params), {
          method: 'GET',
          apiVersion: tool.apiVersion ?? 'beta',
        });
        return wrapUntrustedContent(result, tool.name);
      }
    );
    count++;
  }
  return count;
}
