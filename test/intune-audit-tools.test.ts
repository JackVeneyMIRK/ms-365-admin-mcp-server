import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const source = readFileSync(path.join(dirname, '../src/intune-audit-tools.ts'), 'utf8');

describe('read-only Intune Settings Catalog tools', () => {
  it('exposes list, metadata, settings and assignments reads', () => {
    expect(source).toContain('list-intune-settings-catalog-policies');
    expect(source).toContain('get-intune-settings-catalog-policy');
    expect(source).toContain('list-intune-settings-catalog-settings');
    expect(source).toContain('list-intune-settings-catalog-assignments');
  });

  it('does not contain write requests or generic user-controlled URL parameters', () => {
    expect(source).toContain("method: 'GET'");
    expect(source).toContain("apiVersion: 'beta'");
    expect(source).toContain('z.string().uuid()');
    expect(source).not.toMatch(/method:\s*['"](?:POST|PATCH|PUT|DELETE)['"]/);
  });
});
