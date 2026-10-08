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
  reportAction?: boolean;
  reportName?: string;
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
  {
    name: 'list-intune-legacy-policy-assignments',
    description: 'Read device and group assignments for one legacy Intune configuration profile.',
    schema: { policyId: uuid },
    path: ({ policyId }) =>
      `/deviceManagement/deviceConfigurations/${encodeURIComponent(String(policyId))}/assignments`,
    apiVersion: 'v1.0',
  },
  {
    name: 'list-intune-legacy-policy-device-statuses',
    description: 'Read per-device deployment results for one legacy configuration profile.',
    schema: { policyId: uuid },
    path: ({ policyId }) =>
      `/deviceManagement/deviceConfigurations/${encodeURIComponent(String(policyId))}/deviceStatuses`,
    apiVersion: 'v1.0',
  },
  {
    name: 'list-intune-legacy-policy-setting-statuses',
    description:
      'Read per-setting success, error, and conflict counts for a legacy configuration profile.',
    schema: { policyId: uuid },
    path: ({ policyId }) =>
      `/deviceManagement/deviceConfigurations/${encodeURIComponent(String(policyId))}/deviceSettingStateSummaries`,
    apiVersion: 'v1.0',
  },
  {
    name: 'list-intune-compliance-policy-assignments',
    description: 'Read Intune device compliance policy assignments.',
    schema: { policyId: uuid },
    path: ({ policyId }) =>
      `/deviceManagement/deviceCompliancePolicies/${encodeURIComponent(String(policyId))}/assignments`,
    apiVersion: 'v1.0',
  },
  {
    name: 'list-intune-compliance-policy-device-statuses',
    description: 'Read per-device compliance results for one Intune compliance policy.',
    schema: { policyId: uuid },
    path: ({ policyId }) =>
      `/deviceManagement/deviceCompliancePolicies/${encodeURIComponent(String(policyId))}/deviceStatuses`,
    apiVersion: 'v1.0',
  },
  {
    name: 'get-intune-configuration-policy-noncompliance-report',
    description:
      'Read configuration policy noncompliance reports; fixed Microsoft Graph report action only.',
    schema: {},
    path: () => '/deviceManagement/reports/getConfigurationPolicyNonComplianceReport',
    reportName: 'ConfigurationPolicyNonComplianceReport',
    apiVersion: 'v1.0',
    reportAction: true,
  },
  {
    name: 'get-intune-configuration-setting-noncompliance-report',
    description:
      'Read configuration setting noncompliance reports including conflict details; no writes.',
    schema: {},
    path: () => '/deviceManagement/reports/getConfigurationSettingNonComplianceReport',
    reportName: 'ConfigurationSettingNonComplianceReport',
    apiVersion: 'v1.0',
    reportAction: true,
  },
  {
    name: 'get-intune-device-configuration-status-summary',
    description: 'Read tenant-wide device configuration deployment totals, including conflict and error counts.',
    schema: {},
    path: () => '/deviceManagement/deviceConfigurationDeviceStateSummaries',
    apiVersion: 'v1.0',
  },
  {
    name: 'list-intune-compliance-setting-status-summaries',
    description: 'Read per-setting compliance results for a specified legacy compliance policy.',
    schema: { policyId: uuid },
    path: ({ policyId }) =>
      `/deviceManagement/deviceCompliancePolicies/${encodeURIComponent(String(policyId))}/deviceSettingStateSummaries`,
    apiVersion: 'v1.0',
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
          method: tool.reportAction ? 'POST' : 'GET',
          ...(tool.reportAction
            ? { body: JSON.stringify({ name: tool.reportName, skip: 0, top: 50 }) }
            : {}),
          apiVersion: tool.apiVersion ?? 'beta',
        });
        return wrapUntrustedContent(result, tool.name);
      }
    );
    count++;
  }
  return count;
}
