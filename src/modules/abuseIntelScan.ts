/**
 * AbuseIntel-GPT Module
 * 
 * Autonomous scanner module for DealBrief's artifact pipeline that checks IP addresses
 * against AbuseIPDB v2 API for reputation and abuse intelligence.
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';
import { executeModule, apiCall, errorHandler } from '../util/errorHandler.js';
import { resolveDomain, isSharedHostingIP } from '../util/dnsResolver.js';

// Configuration constants
const ABUSEIPDB_ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';
const RATE_LIMIT_DELAY_MS = 2000; // 30 requests/minute = 2 second intervals
const JITTER_MS = 200; // ±200ms jitter
const REQUEST_TIMEOUT_MS = 10000;


// Risk assessment thresholds
const SUSPICIOUS_THRESHOLD = 25;
const MALICIOUS_THRESHOLD = 70;

// Enhanced logging
const log = createModuleLogger('abuseIntelScan');

interface AbuseIPDBResponse {
  ipAddress: string;
  isPublic: boolean;
  ipVersion: number;
  isWhitelisted: boolean;
  abuseConfidenceScore: number;
  countryCode: string;
  usageType: string;
  isp: string;
  domain: string;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string | null;
}

interface RiskAssessment {
  confidence: number;
  findingType: 'IP_REPUTATION_ISSUE' | 'MAIL_DELIVERABILITY_RISK';
  severity: 'MEDIUM' | 'HIGH';
  description: string;
  evidence: AbuseIPDBResponse;
  recommendation: string;
  ipSource: 'web' | 'mail';
}

interface ScanMetrics {
  totalIPs: number;
  suspicious: number;
  malicious: number;
  errors: number;
  scanTimeMs: number;
}

/**
 * Jittered delay to respect rate limits and avoid thundering herd
 */
async function jitteredDelay(): Promise<void> {
  const delay = RATE_LIMIT_DELAY_MS + (Math.random() * JITTER_MS * 2 - JITTER_MS);
  await new Promise(resolve => setTimeout(resolve, delay));
}

/**
 * Get domain from scan record
 */
async function getDomainFromScan(scanId: string): Promise<string | null> {
  try {
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();

    try {
      const result = await store.query(
        'SELECT domain FROM scans WHERE id = $1',
        [scanId]
      );

      if (result.rows.length === 0) {
        log.info(`Scan ${scanId} not found`);
        return null;
      }

      return result.rows[0].domain;
    } finally {
      await store.close();
    }
  } catch (error) {
    log.info(`Error getting domain for scan ${scanId}: ${(error as Error).message}`);
    return null;
  }
}

/**
 * Resolve target IPs from domain (A/AAAA + MX records)
 */
async function resolveTargetIPs(domain: string): Promise<{ ip: string; source: 'web' | 'mail' }[]> {
  log.info(`Resolving IPs for domain: ${domain}`);

  const dnsResult = await resolveDomain(domain);
  const targets: { ip: string; source: 'web' | 'mail' }[] = [];

  // Add web IPs (A/AAAA)
  for (const ip of dnsResult.webIPs) {
    targets.push({ ip, source: 'web' });
  }

  // Add mail IPs (MX)
  for (const ip of dnsResult.mailIPs) {
    targets.push({ ip, source: 'mail' });
  }

  // Deduplicate (prefer 'web' source if IP appears in both)
  const seen = new Map<string, 'web' | 'mail'>();
  for (const target of targets) {
    if (!seen.has(target.ip) || target.source === 'web') {
      seen.set(target.ip, target.source);
    }
  }

  const deduplicated = Array.from(seen.entries()).map(([ip, source]) => ({ ip, source }));
  log.info(`Resolved ${deduplicated.length} unique IPs (${dnsResult.webIPs.length} web, ${dnsResult.mailIPs.length} mail)`);

  return deduplicated;
}

/**
 * Check if finding should be promoted based on thresholds
 */
async function shouldPromoteFinding(
  data: AbuseIPDBResponse,
  isSharedHosting: boolean
): Promise<boolean> {
  const { totalReports, lastReportedAt, abuseConfidenceScore } = data;

  // No last report = no promotion
  if (!lastReportedAt) {
    log.info(`No last report date for IP, skipping`);
    return false;
  }

  const lastReportedDate = new Date(lastReportedAt);
  const daysSinceLastReport = (Date.now() - lastReportedDate.getTime()) / (1000 * 60 * 60 * 24);

  // Critical categories that warrant immediate attention
  // AbuseIPDB doesn't provide category in the check response, so we use confidence as proxy
  const isCriticalConfidence = abuseConfidenceScore >= 75;

  // Shared hosting requires stricter thresholds
  if (isSharedHosting) {
    // Stricter: reports >= 10 AND last_reported <= 30 days
    const meetsStrictThreshold = totalReports >= 10 && daysSinceLastReport <= 30;
    log.info(`Shared hosting IP: reports=${totalReports}, days=${daysSinceLastReport.toFixed(1)}, meetsThreshold=${meetsStrictThreshold}`);
    return meetsStrictThreshold;
  }

  // Default thresholds for dedicated/unknown hosting
  // Option 1: reports >= 5 AND last_reported <= 90 days
  const meetsDefaultThreshold = totalReports >= 5 && daysSinceLastReport <= 90;

  // Option 2: last_reported <= 7 days AND critical confidence >= 75
  const meetsRecentCritical = daysSinceLastReport <= 7 && isCriticalConfidence;

  const shouldPromote = meetsDefaultThreshold || meetsRecentCritical;
  log.info(`Standard IP: reports=${totalReports}, days=${daysSinceLastReport.toFixed(1)}, confidence=${abuseConfidenceScore}%, promote=${shouldPromote}`);

  return shouldPromote;
}

/**
 * Check if IP address is valid (IPv4 or IPv6)
 */
function isValidIP(ip: string): boolean {
  // Basic IPv4 regex
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // Basic IPv6 regex (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Check single IP against AbuseIPDB with retries and error handling
 */
async function checkAbuseIPDB(
  ip: string,
  ipSource: 'web' | 'mail'
): Promise<RiskAssessment | null> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    log.info('ABUSEIPDB_API_KEY not set - skipping AbuseIPDB check');
    return null;
  }

  if (!isValidIP(ip)) {
    log.info(`Skipping invalid IP: ${ip}`);
    return null;
  }

  // Use standardized API call with retry logic
  const result = await apiCall(async () => {
    log.info(`Checking IP ${ip} (${ipSource}) with AbuseIPDB`);

    const response = await httpClient.get(ABUSEIPDB_ENDPOINT, {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: ''
      },
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      },
      timeout: REQUEST_TIMEOUT_MS
    });

    return response.data.data as AbuseIPDBResponse;
  }, {
    moduleName: 'abuseIntelScan',
    operation: 'checkAbuseIPDB',
    target: ip
  });

  if (!result.success) {
    log.info(`Failed to check IP ${ip}: ${(result as any).error}`);
    return null;
  }

  const data = result.data;

  // Check if IP is on shared hosting
  const isSharedIP = await isSharedHostingIP(ip);

  // Apply threshold filtering
  const shouldPromote = await shouldPromoteFinding(data, isSharedIP);
  if (!shouldPromote) {
    log.info(`IP ${ip} did not meet threshold (confidence: ${data.abuseConfidenceScore}%, reports: ${data.totalReports})`);
    return null;
  }

  // Determine finding type based on IP source
  const findingType = ipSource === 'mail' ? 'MAIL_DELIVERABILITY_RISK' : 'IP_REPUTATION_ISSUE';

  // Determine severity based on confidence and recency
  const isCritical = data.abuseConfidenceScore >= MALICIOUS_THRESHOLD;
  const severity = isCritical ? 'HIGH' : 'MEDIUM';

  // Generate actionable description
  const lastReportedDate = data.lastReportedAt ? new Date(data.lastReportedAt).toLocaleDateString() : 'Unknown';
  const description = `${ip} (${ipSource === 'mail' ? 'mail server' : 'web server'}) has ${data.abuseConfidenceScore}% abuse confidence score with ${data.totalReports} reports from ${data.numDistinctUsers} users. Last reported: ${lastReportedDate}`;

  // Generate specific recommendation based on IP source
  let recommendation = '';
  if (ipSource === 'mail') {
    recommendation = `Your mail server IP (${ip}) has abuse reports that may affect email deliverability. Recommended actions:
1. Move outgoing mail to a reputable relay service (SendGrid, Mailgun, Mailchimp Transactional)
2. Implement SPF, DKIM, and DMARC records to improve sender reputation
3. Contact your hosting provider to request a clean IP address
4. Monitor your mail logs for unauthorized sending activity`;
  } else {
    recommendation = `Your web server IP (${ip}) has abuse reports indicating ${isSharedIP ? 'shared hosting' : 'dedicated server'} reputation issues. Recommended actions:
1. ${isSharedIP ? 'Consider migrating to a dedicated IP or different hosting provider' : 'Review server logs for compromise or unauthorized activity'}
2. Contact your hosting provider's abuse team to investigate
3. Ensure all software is patched and up-to-date
4. Implement IP-based firewall rules and rate limiting`;
  }

  log.info(`IP ${ip} flagged as ${findingType} (confidence: ${data.abuseConfidenceScore}%, ${isSharedIP ? 'shared hosting' : 'dedicated'})`);

  return {
    confidence: data.abuseConfidenceScore,
    findingType,
    severity,
    description,
    evidence: data,
    recommendation,
    ipSource
  };
}


/**
 * Main scan function - processes all resolved IPs for the given scan
 */
export async function runAbuseIntelScan(job: { scanId: string }): Promise<number> {
  const { scanId } = job;

  return executeModule('abuseIntelScan', async () => {
    log.info(`Starting AbuseIPDB scan for scanId=${scanId}`);

    // Check for API key first
    if (!process.env.ABUSEIPDB_API_KEY) {
      log.info('ABUSEIPDB_API_KEY not configured, emitting warning and exiting gracefully');

      await insertArtifact({
        type: 'scan_warning',
        val_text: 'AbuseIPDB scan skipped - API key not configured',
        severity: 'LOW',
        meta: {
          scan_id: scanId,
          scan_module: 'abuseIntelScan',
          reason: 'missing_api_key'
        }
      });

      return 0;
    }

    // Get domain from scan record
    const domain = await getDomainFromScan(scanId);
    if (!domain) {
      log.info('Could not retrieve domain for scan, exiting');
      return 0;
    }

    log.info(`Domain: ${domain}`);

    // Resolve IPs from DNS (A/AAAA + MX)
    const targetIPs = await resolveTargetIPs(domain);

    if (targetIPs.length === 0) {
      log.info('No IPs resolved for this domain');

      await insertArtifact({
        type: 'abuse_intel_summary',
        val_text: 'AbuseIPDB scan completed: no IPs resolved',
        severity: 'INFO',
        meta: {
          scan_id: scanId,
          scan_module: 'abuseIntelScan',
          domain,
          reason: 'no_ips_resolved'
        }
      });

      return 0;
    }

    log.info(`Processing ${targetIPs.length} unique IPs (web + mail)`);

    const metrics: ScanMetrics = {
      totalIPs: targetIPs.length,
      suspicious: 0,
      malicious: 0,
      errors: 0,
      scanTimeMs: 0
    };

    let findingsCount = 0;
    let mailRiskCount = 0;
    let webRiskCount = 0;

    // Process each IP sequentially with rate limiting
    for (let i = 0; i < targetIPs.length; i++) {
      const { ip, source } = targetIPs[i];

      try {
        // Check IP against AbuseIPDB
        const risk = await checkAbuseIPDB(ip, source);

        if (risk) {
          // Create finding in findings table (enables EAL calculation)
          await insertFinding({
            scan_id: scanId,
            type: risk.findingType,
            severity: risk.severity,
            title: risk.description,
            description: risk.recommendation,
            data: {
              scan_module: 'abuseIntelScan',
              ip_address: ip,
              ip_source: source,
              confidence_score: risk.confidence,
              total_reports: risk.evidence.totalReports,
              num_distinct_users: risk.evidence.numDistinctUsers,
              last_reported_at: risk.evidence.lastReportedAt,
              country_code: risk.evidence.countryCode,
              usage_type: risk.evidence.usageType,
              isp: risk.evidence.isp
            }
          });

          // Update metrics
          if (risk.severity === 'HIGH') {
            metrics.malicious++;
          } else {
            metrics.suspicious++;
          }

          if (risk.findingType === 'MAIL_DELIVERABILITY_RISK') {
            mailRiskCount++;
          } else {
            webRiskCount++;
          }

          findingsCount++;

          log.info(`Created ${risk.findingType} finding for ${ip} (${source}, confidence: ${risk.confidence}%)`);
        }

      } catch (error) {
        metrics.errors++;
        log.info(`Error processing IP ${ip}: ${(error as Error).message}`);

        // Continue with remaining IPs
        continue;
      }

      // Rate limiting - don't delay after the last IP
      if (i < targetIPs.length - 1) {
        await jitteredDelay();
      }
    }

    // Create summary artifact
    const summaryText = findingsCount > 0
      ? `AbuseIPDB scan completed: ${findingsCount} reputation issues found (${mailRiskCount} mail, ${webRiskCount} web)`
      : 'AbuseIPDB scan completed: no reputation issues found';

    await insertArtifact({
      type: 'abuse_intel_summary',
      val_text: summaryText,
      severity: metrics.malicious > 0 ? 'HIGH' : metrics.suspicious > 0 ? 'MEDIUM' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'abuseIntelScan',
        domain,
        metrics: {
          total_ips_checked: metrics.totalIPs,
          high_severity: metrics.malicious,
          medium_severity: metrics.suspicious,
          mail_risks: mailRiskCount,
          web_risks: webRiskCount,
          errors: metrics.errors
        },
        api_quota_used: metrics.totalIPs - metrics.errors
      }
    });

    log.info(`AbuseIPDB scan completed: ${findingsCount} findings from ${metrics.totalIPs} IPs`);
    log.info(`Breakdown: ${metrics.malicious} HIGH, ${metrics.suspicious} MEDIUM (${mailRiskCount} mail, ${webRiskCount} web), ${metrics.errors} errors`);

    return findingsCount;

  }, { scanId });
}