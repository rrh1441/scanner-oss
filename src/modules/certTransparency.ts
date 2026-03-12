/**
 * Certificate Transparency Discovery Module
 *
 * Discovers subdomains and assets by querying certificate transparency logs.
 * Uses crt.sh (free, public CT log aggregator) to find all certificates
 * ever issued for a domain.
 *
 * This reveals:
 * - Subdomains (including internal/staging that may be exposed)
 * - Historical assets
 * - Certificate metadata
 */

import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('certTransparency');

interface CTJob {
  domain: string;
  scanId: string;
}

interface CTEntry {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
  serial_number: string;
}

interface DiscoveredSubdomain {
  subdomain: string;
  firstSeen: string;
  lastSeen: string;
  issuer: string;
  isWildcard: boolean;
  isExpired: boolean;
}

interface CTScanResult {
  success: boolean;
  subdomainsFound: number;
  findings: number;
  subdomains: DiscoveredSubdomain[];
}

// Interesting subdomain patterns that warrant findings
const INTERESTING_PATTERNS = [
  { pattern: /^(dev|development|devel)\./i, category: 'development', severity: 'MEDIUM' as const },
  { pattern: /^(staging|stage|stg|uat)\./i, category: 'staging', severity: 'MEDIUM' as const },
  { pattern: /^(test|testing|qa)\./i, category: 'testing', severity: 'MEDIUM' as const },
  { pattern: /^(internal|intra|corp|private)\./i, category: 'internal', severity: 'HIGH' as const },
  { pattern: /^(admin|administrator|manage|management)\./i, category: 'admin', severity: 'HIGH' as const },
  { pattern: /^(api|api-internal|api-staging)\./i, category: 'api', severity: 'MEDIUM' as const },
  { pattern: /^(vpn|remote|gateway)\./i, category: 'remote_access', severity: 'HIGH' as const },
  { pattern: /^(mail|smtp|imap|pop|exchange)\./i, category: 'email', severity: 'LOW' as const },
  { pattern: /^(ftp|sftp|backup)\./i, category: 'file_transfer', severity: 'MEDIUM' as const },
  { pattern: /^(db|database|mysql|postgres|mongo|redis)\./i, category: 'database', severity: 'HIGH' as const },
  { pattern: /^(jenkins|ci|cd|gitlab|github|bitbucket)\./i, category: 'cicd', severity: 'HIGH' as const },
  { pattern: /^(jira|confluence|wiki|docs)\./i, category: 'productivity', severity: 'MEDIUM' as const },
  { pattern: /^(grafana|kibana|prometheus|monitor)\./i, category: 'monitoring', severity: 'MEDIUM' as const },
  { pattern: /^(k8s|kubernetes|docker|container)\./i, category: 'infrastructure', severity: 'HIGH' as const },
  { pattern: /^(old|legacy|deprecated|archive)\./i, category: 'legacy', severity: 'MEDIUM' as const },
  { pattern: /^(beta|alpha|preview|canary)\./i, category: 'prerelease', severity: 'LOW' as const },
];

/**
 * Query crt.sh for certificate transparency data
 */
async function queryCrtSh(domain: string): Promise<CTEntry[]> {
  const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Accept': 'application/json',
      },
    });

    clearTimeout(timeout);

    if (!response.ok) {
      log.warn({ status: response.status }, 'crt.sh returned non-OK status');
      return [];
    }

    const data = await response.json() as CTEntry[];
    return Array.isArray(data) ? data : [];
  } catch (error) {
    if ((error as Error).name === 'AbortError') {
      log.warn('crt.sh query timed out');
    } else {
      log.error({ err: error }, 'Failed to query crt.sh');
    }
    return [];
  }
}

/**
 * Extract unique subdomains from CT entries
 */
function extractSubdomains(entries: CTEntry[], baseDomain: string): Map<string, DiscoveredSubdomain> {
  const subdomains = new Map<string, DiscoveredSubdomain>();
  const now = new Date();

  for (const entry of entries) {
    // name_value can contain multiple domains separated by newlines
    const names = entry.name_value.split('\n').map(n => n.trim().toLowerCase());

    for (const name of names) {
      // Skip if not a subdomain of our target
      if (!name.endsWith(`.${baseDomain}`) && name !== baseDomain) {
        continue;
      }

      // Skip if already processed with better data
      const existing = subdomains.get(name);
      const notBefore = new Date(entry.not_before);
      const notAfter = new Date(entry.not_after);
      const isExpired = notAfter < now;
      const isWildcard = name.startsWith('*.');

      if (existing) {
        // Update with earliest first seen and latest last seen
        if (notBefore < new Date(existing.firstSeen)) {
          existing.firstSeen = entry.not_before;
        }
        if (notAfter > new Date(existing.lastSeen)) {
          existing.lastSeen = entry.not_after;
          existing.isExpired = isExpired;
          existing.issuer = entry.issuer_name;
        }
      } else {
        subdomains.set(name, {
          subdomain: name,
          firstSeen: entry.not_before,
          lastSeen: entry.not_after,
          issuer: entry.issuer_name,
          isWildcard,
          isExpired,
        });
      }
    }
  }

  return subdomains;
}

/**
 * Categorize a subdomain based on naming patterns
 */
function categorizeSubdomain(subdomain: string): { category: string; severity: 'LOW' | 'MEDIUM' | 'HIGH' } | null {
  for (const { pattern, category, severity } of INTERESTING_PATTERNS) {
    if (pattern.test(subdomain)) {
      return { category, severity };
    }
  }
  return null;
}

/**
 * Main scanner function
 */
export async function runCertTransparency(job: CTJob): Promise<number> {
  const { domain, scanId } = job;

  log.info({ domain, scanId }, 'Starting certificate transparency discovery');

  // Query crt.sh
  const entries = await queryCrtSh(domain);

  if (entries.length === 0) {
    log.info({ domain }, 'No CT entries found');
    return 0;
  }

  log.info({ domain, entries: entries.length }, 'CT entries retrieved');

  // Extract subdomains
  const subdomains = extractSubdomains(entries, domain);
  log.info({ domain, subdomains: subdomains.size }, 'Unique subdomains extracted');

  let findingsCount = 0;

  // Store all discovered subdomains as an artifact
  const allSubdomainsList = Array.from(subdomains.keys()).sort();

  await insertArtifact({
    type: 'ct_subdomains',
    val_text: `Certificate Transparency: ${subdomains.size} subdomains for ${domain}`,
    severity: 'INFO',
    meta: {
      scan_id: scanId,
      scan_module: 'cert_transparency',
      domain,
      subdomain_count: subdomains.size,
      subdomains: allSubdomainsList,
      ct_entries_processed: entries.length,
    },
  });

  // Analyze interesting subdomains
  const interestingFindings: Array<{
    subdomain: string;
    category: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
    data: DiscoveredSubdomain;
  }> = [];

  for (const [name, data] of subdomains) {
    const categorization = categorizeSubdomain(name);
    if (categorization) {
      interestingFindings.push({
        subdomain: name,
        ...categorization,
        data,
      });
    }
  }

  // Group findings by category for cleaner reporting
  const byCategory = new Map<string, typeof interestingFindings>();
  for (const finding of interestingFindings) {
    const existing = byCategory.get(finding.category) || [];
    existing.push(finding);
    byCategory.set(finding.category, existing);
  }

  // Create findings for each category
  for (const [category, findings] of byCategory) {
    const maxSeverity = findings.reduce((max, f) =>
      f.severity === 'HIGH' ? 'HIGH' :
      f.severity === 'MEDIUM' && max !== 'HIGH' ? 'MEDIUM' : max,
      'LOW' as 'LOW' | 'MEDIUM' | 'HIGH'
    );

    const subdomainList = findings.map(f => f.subdomain);

    const artifactId = await insertArtifact({
      type: 'ct_interesting_subdomains',
      val_text: `${category}: ${subdomainList.length} subdomain(s) discovered via CT`,
      severity: maxSeverity,
      meta: {
        scan_id: scanId,
        scan_module: 'cert_transparency',
        category,
        subdomains: subdomainList,
        details: findings.map(f => f.data),
      },
    });

    const categoryDescriptions: Record<string, string> = {
      development: 'Development environment subdomains discovered. These often have weaker security controls.',
      staging: 'Staging environment subdomains discovered. May contain pre-production data.',
      testing: 'Testing environment subdomains discovered. Often have debug features enabled.',
      internal: 'Internal-facing subdomains discovered via public certificates. Review if these should be exposed.',
      admin: 'Administrative interface subdomains discovered. High-value targets for attackers.',
      remote_access: 'Remote access infrastructure discovered. VPN/gateway endpoints are common attack targets.',
      database: 'Database-related subdomains discovered. Verify these services are not publicly accessible.',
      cicd: 'CI/CD infrastructure discovered. These systems often have elevated privileges.',
      infrastructure: 'Container/orchestration infrastructure discovered. Kubernetes dashboards are common targets.',
      legacy: 'Legacy/deprecated subdomains discovered. Old systems often have unpatched vulnerabilities.',
      api: 'API subdomains discovered. Check for proper authentication and rate limiting.',
      email: 'Email infrastructure discovered.',
      file_transfer: 'File transfer infrastructure discovered.',
      productivity: 'Productivity tool subdomains discovered.',
      monitoring: 'Monitoring infrastructure discovered.',
      prerelease: 'Pre-release environment subdomains discovered.',
    };

    await insertFinding({
      artifact_id: artifactId,
      finding_type: 'CT_SUBDOMAIN_DISCOVERY',
      scan_id: scanId,
      severity: maxSeverity,
      type: 'CT_SUBDOMAIN_DISCOVERY',
      description: `${categoryDescriptions[category] || 'Interesting subdomains discovered.'} Found: ${subdomainList.join(', ')}`,
      recommendation: 'Review these subdomains for proper access controls. Ensure non-production environments are not publicly accessible or contain sensitive data.',
      data: {
        category,
        subdomains: subdomainList,
        count: subdomainList.length,
      },
    });

    findingsCount++;

    log.info({
      category,
      count: subdomainList.length,
      severity: maxSeverity,
    }, 'Interesting subdomains found');
  }

  // If we found a lot of subdomains, that's useful intel even without interesting patterns
  if (subdomains.size > 50 && findingsCount === 0) {
    const artifactId = await insertArtifact({
      type: 'ct_large_footprint',
      val_text: `Large subdomain footprint: ${subdomains.size} subdomains`,
      severity: 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'cert_transparency',
        subdomain_count: subdomains.size,
      },
    });

    await insertFinding({
      artifact_id: artifactId,
      finding_type: 'LARGE_SUBDOMAIN_FOOTPRINT',
      scan_id: scanId,
      severity: 'INFO',
      type: 'LARGE_SUBDOMAIN_FOOTPRINT',
      description: `Organization has ${subdomains.size} unique subdomains visible in certificate transparency logs. This provides a comprehensive view of the external attack surface.`,
      recommendation: 'Review the full subdomain list for any unexpected or unauthorized services. Consider the operational security implications of subdomain naming conventions.',
      data: {
        subdomain_count: subdomains.size,
      },
    });

    findingsCount++;
  }

  log.info({
    domain,
    scanId,
    totalSubdomains: subdomains.size,
    interestingSubdomains: interestingFindings.length,
    findings: findingsCount,
  }, 'Certificate transparency discovery complete');

  return findingsCount;
}
