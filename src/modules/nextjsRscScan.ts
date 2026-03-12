/* =============================================================================
 * MODULE: nextjsRscScan.ts
 * =============================================================================
 * Next.js / React Server Components (RSC) fingerprinting scanner.
 * Detects domains running Next.js App Router / RSC stack that may be vulnerable
 * to critical RCE vulnerabilities (CVE-2025-55182 / CVE-2025-66478).
 * =============================================================================
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('nextjsRscScan');

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

export type RiskLevel =
  | 'NONE'
  | 'POTENTIAL_NEXTJS'
  | 'POTENTIAL_NEXTJS_APP_ROUTER_RSC';

export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';

export interface NextRscEvidence {
  type: 'HEADER' | 'BODY_SNIPPET' | 'PATH_PROBE' | 'ERROR';
  detail: string;
}

export interface NextRscFingerprint {
  domain: string;
  statusCode?: number;
  isHttps: boolean;
  isNextjs: boolean;
  isAppRouterLikely: boolean;
  riskLevel: RiskLevel;
  confidence: Confidence;
  evidence: NextRscEvidence[];
  scannedAt: string;
}

// -----------------------------------------------------------------------------
// Detection Logic
// -----------------------------------------------------------------------------

/**
 * Evaluate HTTP response for Next.js / RSC fingerprints.
 */
function evaluateNextFingerprint(
  statusCode: number | undefined,
  headers: Record<string, string>,
  bodySnippet: string,
  evidence: NextRscEvidence[]
): {
  isNextjs: boolean;
  isAppRouterLikely: boolean;
  riskLevel: RiskLevel;
  confidence: Confidence;
} {
  let isNextjs = false;
  let isAppRouterLikely = false;
  let riskLevel: RiskLevel = 'NONE';
  let confidence: Confidence = 'LOW';

  // Check x-powered-by header
  const xPoweredBy = headers['x-powered-by'] || '';
  if (xPoweredBy.toLowerCase().includes('next.js')) {
    isNextjs = true;
    evidence.push({
      type: 'HEADER',
      detail: `x-powered-by: ${xPoweredBy}`
    });
  }

  // Check for __NEXT_DATA__ (Pages Router or App Router with some pages)
  if (bodySnippet.includes('__NEXT_DATA__')) {
    isNextjs = true;
    evidence.push({
      type: 'BODY_SNIPPET',
      detail: 'Found "__NEXT_DATA__" in HTML body'
    });
  }

  // Check for /_next/static/ reference (generic Next.js indicator)
  if (bodySnippet.includes('/_next/static/')) {
    isNextjs = true;
    evidence.push({
      type: 'BODY_SNIPPET',
      detail: 'Found "/_next/static/" reference in HTML body'
    });
  }

  // Check for /_next/static/chunks/app/ (App Router / RSC indicator)
  if (bodySnippet.includes('/_next/static/chunks/app/')) {
    isNextjs = true;
    isAppRouterLikely = true;
    evidence.push({
      type: 'BODY_SNIPPET',
      detail: 'Found "/_next/static/chunks/app/" reference (App Router / RSC style)'
    });
  }

  // Check for RSC payload markers (streaming, server components)
  // These patterns appear in RSC flight data responses
  if (bodySnippet.includes('$undefined') ||
      bodySnippet.includes('$Sreact.') ||
      bodySnippet.includes('"children":[null,"$L')) {
    isAppRouterLikely = true;
    evidence.push({
      type: 'BODY_SNIPPET',
      detail: 'Found RSC flight data markers in response'
    });
  }

  // Check for Next.js-specific headers that indicate RSC
  const rscHeader = headers['rsc'] || headers['x-nextjs-cache'] || '';
  if (rscHeader) {
    isNextjs = true;
    isAppRouterLikely = true;
    evidence.push({
      type: 'HEADER',
      detail: `RSC-related header present: ${rscHeader ? 'rsc/x-nextjs-cache' : ''}`
    });
  }

  // Calculate confidence based on evidence strength
  const strongMarkers = evidence.filter((ev) =>
    ev.detail.includes('__NEXT_DATA__') ||
    ev.detail.includes('/_next/static/chunks/app/') ||
    ev.detail.includes('x-powered-by') ||
    ev.detail.includes('RSC flight data') ||
    ev.detail.includes('RSC-related header')
  ).length;

  if (isNextjs) {
    if (isAppRouterLikely) {
      riskLevel = 'POTENTIAL_NEXTJS_APP_ROUTER_RSC';
      confidence = strongMarkers >= 2 ? 'HIGH' : 'MEDIUM';
    } else {
      riskLevel = 'POTENTIAL_NEXTJS';
      confidence = strongMarkers >= 2 ? 'MEDIUM' : 'LOW';
    }
  }

  // Reduce confidence for error responses
  if (statusCode && statusCode >= 400) {
    if (confidence === 'HIGH') {
      confidence = 'MEDIUM';
    } else if (confidence === 'MEDIUM') {
      confidence = 'LOW';
    }
  }

  return {
    isNextjs,
    isAppRouterLikely,
    riskLevel,
    confidence
  };
}

/**
 * Probe a single URL and return fingerprint results.
 */
async function probeUrl(
  url: string,
  isHttps: boolean,
  timeoutMs: number,
  maxBodyBytes: number
): Promise<{
  statusCode?: number;
  headers: Record<string, string>;
  bodySnippet: string;
  error?: string;
}> {
  try {
    const response = await httpClient.get(url, {
      timeout: timeoutMs,
      maxContentLength: maxBodyBytes,
      validateStatus: () => true, // Accept all status codes
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner Security Scanner)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      }
    });

    const content = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data || '');

    // Normalize headers to lowercase keys
    const headers: Record<string, string> = {};
    if (response.headers) {
      for (const [key, value] of Object.entries(response.headers)) {
        headers[key.toLowerCase()] = String(value);
      }
    }

    return {
      statusCode: response.status,
      headers,
      bodySnippet: content.substring(0, maxBodyBytes)
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      headers: {},
      bodySnippet: '',
      error: `Fetch failed for ${url}: ${message}`
    };
  }
}

/**
 * Fingerprint a single domain for Next.js / RSC.
 */
async function fingerprintDomain(
  domain: string,
  timeoutMs: number = 8000,
  maxBodyBytes: number = 256 * 1024
): Promise<NextRscFingerprint> {
  const scannedAt = new Date().toISOString();
  const evidence: NextRscEvidence[] = [];

  const baseFinding: NextRscFingerprint = {
    domain,
    statusCode: undefined,
    isHttps: true,
    isNextjs: false,
    isAppRouterLikely: false,
    riskLevel: 'NONE',
    confidence: 'LOW',
    evidence,
    scannedAt
  };

  // Try HTTPS first
  const httpsUrl = `https://${domain}/`;
  const httpsResult = await probeUrl(httpsUrl, true, timeoutMs, maxBodyBytes);

  if (httpsResult.error) {
    evidence.push({
      type: 'ERROR',
      detail: httpsResult.error
    });
  }

  // If HTTPS worked (status < 500), use that result
  if (httpsResult.statusCode && httpsResult.statusCode < 500) {
    const evaluated = evaluateNextFingerprint(
      httpsResult.statusCode,
      httpsResult.headers,
      httpsResult.bodySnippet,
      evidence
    );

    return {
      ...baseFinding,
      statusCode: httpsResult.statusCode,
      isHttps: true,
      isNextjs: evaluated.isNextjs,
      isAppRouterLikely: evaluated.isAppRouterLikely,
      riskLevel: evaluated.riskLevel,
      confidence: evaluated.confidence,
      evidence
    };
  }

  // Fallback to HTTP
  const httpUrl = `http://${domain}/`;
  const httpResult = await probeUrl(httpUrl, false, timeoutMs, maxBodyBytes);

  if (httpResult.error) {
    evidence.push({
      type: 'ERROR',
      detail: httpResult.error
    });
  }

  if (httpResult.statusCode) {
    const evaluated = evaluateNextFingerprint(
      httpResult.statusCode,
      httpResult.headers,
      httpResult.bodySnippet,
      evidence
    );

    return {
      ...baseFinding,
      statusCode: httpResult.statusCode,
      isHttps: false,
      isNextjs: evaluated.isNextjs,
      isAppRouterLikely: evaluated.isAppRouterLikely,
      riskLevel: evaluated.riskLevel,
      confidence: evaluated.confidence,
      evidence
    };
  }

  // Both failed
  return baseFinding;
}

// -----------------------------------------------------------------------------
// Main Module Export
// -----------------------------------------------------------------------------

export async function runNextjsRscScan(job: {
  domain: string;
  scanId: string;
}): Promise<number> {
  const MODULE_NAME = 'nextjsRscScan';
  const start = Date.now();
  const { domain, scanId } = job;

  log.info({ domain, scanId }, 'Starting scan');

  let findingsCount = 0;

  try {
    // Fingerprint the domain
    const fingerprint = await fingerprintDomain(domain);

    log.info({ isNextjs: fingerprint.isNextjs, isAppRouter: fingerprint.isAppRouterLikely, confidence: fingerprint.confidence }, 'Fingerprint result');

    // Always store the fingerprint artifact for audit/analysis
    const artifactId = await insertArtifact({
      type: 'nextjs_rsc_fingerprint',
      val_text: `Next.js RSC fingerprint for ${domain}: ${fingerprint.riskLevel} (${fingerprint.confidence} confidence)`,
      severity: fingerprint.riskLevel === 'POTENTIAL_NEXTJS_APP_ROUTER_RSC' ? 'HIGH' :
                fingerprint.riskLevel === 'POTENTIAL_NEXTJS' ? 'MEDIUM' : 'INFO',
      src_url: `https://${domain}/`,
      meta: {
        scan_id: scanId,
        scan_module: MODULE_NAME,
        domain,
        is_nextjs: fingerprint.isNextjs,
        is_app_router_likely: fingerprint.isAppRouterLikely,
        risk_level: fingerprint.riskLevel,
        confidence: fingerprint.confidence,
        status_code: fingerprint.statusCode,
        is_https: fingerprint.isHttps,
        evidence: fingerprint.evidence,
        scanned_at: fingerprint.scannedAt
      }
    });

    // Emit CRITICAL finding if RSC/App Router detected with MEDIUM or HIGH confidence
    if (
      fingerprint.riskLevel === 'POTENTIAL_NEXTJS_APP_ROUTER_RSC' &&
      (fingerprint.confidence === 'MEDIUM' || fingerprint.confidence === 'HIGH')
    ) {
      await insertFinding({
        scan_id: scanId,
        artifact_id: artifactId,
        type: 'NEXTJS_RSC_RCE_EXPOSURE',
        severity: 'CRITICAL',
        title: `Critical RCE Exposure in React Server Components / Next.js`,
        description: `External fingerprinting indicates that ${domain} is running a Next.js / React Server Components stack that may be vulnerable to critical RCE vulnerabilities (CVE-2025-55182 / CVE-2025-66478). Detection confidence: ${fingerprint.confidence}.`,
        data: {
          domain,
          risk_level: fingerprint.riskLevel,
          confidence: fingerprint.confidence,
          is_nextjs: fingerprint.isNextjs,
          is_app_router_likely: fingerprint.isAppRouterLikely,
          evidence: fingerprint.evidence,
          status_code: fingerprint.statusCode,
          is_https: fingerprint.isHttps
        }
      });
      findingsCount++;
      log.warn({ domain, confidence: fingerprint.confidence }, 'CRITICAL: Emitted NEXTJS_RSC_RCE_EXPOSURE finding');
    } else if (fingerprint.isNextjs) {
      // Log but don't create finding for plain Next.js without App Router
      log.info({ domain }, 'Next.js detected but no RSC/App Router indicators (or LOW confidence)');
    }

  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error({ err: error, domain }, 'Scan failed');

    // Store error artifact
    await insertArtifact({
      type: 'scan_error',
      val_text: `Next.js RSC scan failed for ${domain}: ${errorMsg}`,
      severity: 'LOW',
      meta: {
        scan_id: scanId,
        scan_module: MODULE_NAME,
        domain,
        error: errorMsg
      }
    });
  }

  const duration = Date.now() - start;
  log.info({ findingsCount, domain, durationMs: duration }, 'Scan completed');

  return findingsCount;
}
