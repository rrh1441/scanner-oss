/**
 * Scan Execution Orchestrator
 *
 * Central coordinator for running security scan modules.
 * Handles module selection, parallel execution, timeout management,
 * and result aggregation.
 */

import { insertArtifact } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';
import { ScanProfile, SCAN_PROFILES, MODULE_REGISTRY, getProfileModules, isModuleAvailable } from '../config/scanProfiles.js';

const log = createModuleLogger('executeScan');

// === Module Imports ===
import { runShodanScan } from '../modules/shodan.js';
import { runDocumentExposure } from '../modules/documentExposure.js';
import { runClientSecretScanner } from '../modules/clientSecretScanner.js';
import { runTlsScan } from '../modules/tlsScan.js';
import { runNuclei } from '../modules/nuclei.js';
import { executeModule as runLightweightCveCheck } from '../modules/lightweightCveCheck.js';
import { runSpfDmarc } from '../modules/spfDmarc.js';
import { runEndpointDiscovery } from '../modules/endpointDiscovery.js';
import { runTechStackScan } from '../modules/techStackScan.js';
import { runAbuseIntelScan } from '../modules/abuseIntelScan.js';
import { runAccessibilityScan } from '../modules/accessibilityScan.js';
import { runInfostealerProbe } from '../modules/infostealerProbe.js';
import { runAssetCorrelator } from '../modules/assetCorrelator.js';
import { runConfigExposureScanner } from '../modules/configExposureScanner.js';
import { runBackendExposureScanner } from '../modules/backendExposureScanner.js';
import { runDenialWalletScan } from '../modules/denialWalletScan.js';
import { runAiPathFinder } from '../modules/aiPathFinder.js';
import { runWhoisWrapper } from '../modules/whoisWrapper.js';
import { runWpPluginQuickScan } from '../modules/wpPluginQuickScan.js';
import { runWpVulnResolver } from '../modules/wpVulnResolver.js';
import { runNextjsRscScan } from '../modules/nextjsRscScan.js';
import { runSubdomainTakeover } from '../modules/subdomainTakeover.js';
import { runDnsTwist } from '../modules/dnsTwist.js';
import { runDbPortScan } from '../modules/dbPortScan.js';
import { runPortScan } from '../modules/portScan.js';
import { runWebArchiveScanner } from '../modules/webArchiveScanner.js';
import { runGithubSecretSearch } from '../modules/githubSecretSearch.js';
import { runAdminPanelDetector } from '../modules/adminPanelDetector.js';
import { runDnsZoneTransfer } from '../modules/dnsZoneTransfer.js';
import { runRateLimitScan } from '../modules/rateLimitScan.js';
import { runCloudBucketEnum } from '../modules/cloudBucketEnum.js';
import { runCertTransparency } from '../modules/certTransparency.js';

// === Configuration ===
const DEFAULT_MODULE_TIMEOUT_MS = parseInt(process.env.MODULE_TIMEOUT_MS || '180000', 10); // 3 minutes
const SCAN_MAX_MS = parseInt(process.env.SCAN_MAX_MS || '900000', 10); // 15 minutes
const ENABLE_ENDPOINT_DISCOVERY = process.env.ENABLE_ENDPOINT_DISCOVERY !== 'false';
const ENDPOINT_DISCOVERY_TIMEOUT_MS = parseInt(process.env.ENDPOINT_DISCOVERY_TIMEOUT_MS || '60000', 10);

// === Types ===
export interface ScanJob {
  scan_id: string;
  domain: string;
  companyName?: string;
  profile?: ScanProfile;
  config?: {
    timeout_ms?: number;
    tier?: 'tier1' | 'tier2';
    modules?: string[];
    skip_modules?: string[];
    callback_url?: string;
  };
}

export interface ScanResult {
  scan_id: string;
  domain: string;
  status: 'completed' | 'partial' | 'failed';
  totalFindings: number;
  modulesRun: number;
  modulesFailed: number;
  modulesSkipped: number;
  duration_ms: number;
  failedModules: string[];
  skippedModules: string[];
  metadata?: {
    modules_completed?: number;
    modules_failed?: number;
    [key: string]: unknown;
  };
}

interface ModuleResult {
  module: string;
  status: 'success' | 'failed' | 'timeout' | 'skipped';
  findings: number;
  duration_ms: number;
  error?: string;
}

// === Module Runner Map ===
type ModuleRunner = (job: { domain: string; scanId: string; companyName?: string }) => Promise<number>;

const MODULE_RUNNERS: Record<string, ModuleRunner> = {
  shodan: (job) => runShodanScan({ domain: job.domain, scanId: job.scanId, companyName: job.companyName }),
  config_exposure: (job) => runConfigExposureScanner({ domain: job.domain, scanId: job.scanId }),
  document_exposure: (job) => runDocumentExposure({ domain: job.domain, scanId: job.scanId, companyName: job.companyName }),
  breach_directory_probe: (job) => runInfostealerProbe({ domain: job.domain, scanId: job.scanId }),
  whois_wrapper: (job) => runWhoisWrapper({ domain: job.domain, scanId: job.scanId }),
  ai_path_finder: (job) => runAiPathFinder({ domain: job.domain, scanId: job.scanId }),
  endpoint_discovery: (job) => runEndpointDiscovery({ domain: job.domain, scanId: job.scanId }),
  tech_stack_scan: (job) => runTechStackScan({ domain: job.domain, scanId: job.scanId }),
  tls_scan: (job) => runTlsScan({ domain: job.domain, scanId: job.scanId }),
  spf_dmarc: (job) => runSpfDmarc({ domain: job.domain, scanId: job.scanId }),
  client_secret_scanner: (job) => runClientSecretScanner({ scanId: job.scanId }),
  backend_exposure_scanner: (job) => runBackendExposureScanner({ scanId: job.scanId }),
  abuse_intel_scan: (job) => runAbuseIntelScan({ scanId: job.scanId }),
  accessibility_scan: (job) => runAccessibilityScan({ domain: job.domain, scanId: job.scanId }),
  lightweight_cve_check: async (job) => {
    const result = await runLightweightCveCheck({ scanId: job.scanId, domain: job.domain, artifacts: [] });
    return result.findings ? result.findings.length : 0;
  },
  wp_plugin_quickscan: (job) => runWpPluginQuickScan({ domain: job.domain, scanId: job.scanId }),
  wp_vuln_resolver: (job) => runWpVulnResolver({ domain: job.domain, scanId: job.scanId }),
  denial_wallet_scan: (job) => runDenialWalletScan({ domain: job.domain, scanId: job.scanId }),
  nextjs_rsc_scan: (job) => runNextjsRscScan({ domain: job.domain, scanId: job.scanId }),
  subdomain_takeover: (job) => runSubdomainTakeover({ domain: job.domain, scanId: job.scanId }),
  // Tier 2 modules
  nuclei: async (job) => {
    const result = await runNuclei({ domain: job.domain, scanId: job.scanId });
    return result.totalFindings;
  },
  dns_twist: (job) => runDnsTwist({ domain: job.domain, scanId: job.scanId }),
  db_port_scan: (job) => runDbPortScan({ domain: job.domain, scanId: job.scanId }),
  port_scan: async (job) => {
    const result = await runPortScan({ domain: job.domain, scanId: job.scanId });
    return result.findings;
  },
  web_archive_scanner: (job) => runWebArchiveScanner({ domain: job.domain, scanId: job.scanId }),
  github_secret_search: (job) => runGithubSecretSearch({ domain: job.domain, scanId: job.scanId }),
  admin_panel_detector: (job) => runAdminPanelDetector({ domain: job.domain, scanId: job.scanId }),
  dns_zone_transfer: (job) => runDnsZoneTransfer({ domain: job.domain, scanId: job.scanId }),
  rate_limit_scan: (job) => runRateLimitScan({ domain: job.domain, scanId: job.scanId }),
  cloud_bucket_enum: (job) => runCloudBucketEnum({ domain: job.domain, scanId: job.scanId, companyName: job.companyName }),
  cert_transparency: (job) => runCertTransparency({ domain: job.domain, scanId: job.scanId }),
};

// === Timeout Wrapper ===
async function runModuleWithTimeout(
  moduleName: string,
  runner: () => Promise<number>,
  timeoutMs: number,
  scanId: string
): Promise<ModuleResult> {
  const startTime = Date.now();
  let timeoutHandle: NodeJS.Timeout | undefined;

  try {
    const result = await Promise.race([
      runner().then(findings => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        return { status: 'success' as const, findings };
      }),
      new Promise<{ status: 'timeout'; findings: number }>((resolve) => {
        timeoutHandle = setTimeout(() => {
          log.warn({ moduleName, timeoutMs, scanId }, 'Module timeout');
          resolve({ status: 'timeout', findings: 0 });
        }, timeoutMs);
      }),
    ]);

    const duration = Date.now() - startTime;
    log.info({ moduleName, status: result.status, findings: result.findings, durationMs: duration, scanId }, 'Module completed');

    return {
      module: moduleName,
      status: result.status,
      findings: result.findings,
      duration_ms: duration,
    };
  } catch (error) {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    const duration = Date.now() - startTime;
    const errorMessage = error instanceof Error ? error.message : String(error);

    log.error({ moduleName, err: error, durationMs: duration, scanId }, 'Module failed');

    return {
      module: moduleName,
      status: 'failed',
      findings: 0,
      duration_ms: duration,
      error: errorMessage,
    };
  }
}

// === Module Availability Check ===
function checkModuleAvailability(moduleName: string): { available: boolean; reason?: string } {
  const runner = MODULE_RUNNERS[moduleName];
  if (!runner) {
    return { available: false, reason: 'Module runner not implemented' };
  }

  const apiCheck = isModuleAvailable(moduleName);
  if (!apiCheck.available && apiCheck.missingKeys) {
    return { available: false, reason: `Missing API keys: ${apiCheck.missingKeys.join(', ')}` };
  }

  return { available: true };
}

// === Main Scan Executor ===
export async function executeScan(job: ScanJob): Promise<ScanResult> {
  const { scan_id, domain, companyName, profile = 'full', config = {} } = job;
  const startTime = Date.now();

  log.info({ scanId: scan_id, domain, profile, config }, 'Starting scan execution');

  const results: ModuleResult[] = [];
  const failedModules: string[] = [];
  const skippedModules: string[] = [];

  try {
    // Determine which modules to run
    let modulesToRun = config.modules || getProfileModules(profile, config.tier);

    // Apply skip_modules filter
    if (config.skip_modules && config.skip_modules.length > 0) {
      modulesToRun = modulesToRun.filter(m => !config.skip_modules!.includes(m));
    }

    // Disable endpoint_discovery if configured
    if (!ENABLE_ENDPOINT_DISCOVERY) {
      modulesToRun = modulesToRun.filter(m => m !== 'endpoint_discovery');
    }

    log.info({ scanId: scan_id, moduleCount: modulesToRun.length, modules: modulesToRun }, 'Modules selected');

    // Check module availability and partition
    const availableModules: string[] = [];
    for (const moduleName of modulesToRun) {
      const check = checkModuleAvailability(moduleName);
      if (check.available) {
        availableModules.push(moduleName);
      } else {
        skippedModules.push(moduleName);
        log.info({ moduleName, reason: check.reason, scanId: scan_id }, 'Module skipped');

        results.push({
          module: moduleName,
          status: 'skipped',
          findings: 0,
          duration_ms: 0,
          error: check.reason,
        });
      }
    }

    // Phase 1: Run endpoint discovery first (other modules depend on it)
    if (availableModules.includes('endpoint_discovery')) {
      log.info({ scanId: scan_id }, 'Phase 1: Running endpoint discovery');

      const edResult = await runModuleWithTimeout(
        'endpoint_discovery',
        () => MODULE_RUNNERS.endpoint_discovery({ domain, scanId: scan_id, companyName }),
        ENDPOINT_DISCOVERY_TIMEOUT_MS,
        scan_id
      );
      results.push(edResult);

      if (edResult.status === 'failed') {
        failedModules.push('endpoint_discovery');
      }
    }

    // Phase 2: Run independent modules in parallel
    const independentModules = availableModules.filter(m =>
      m !== 'endpoint_discovery' &&
      !MODULE_REGISTRY[m]?.dependencies?.length
    );

    log.info({ scanId: scan_id, count: independentModules.length }, 'Phase 2: Running independent modules');

    const independentPromises = independentModules.map(moduleName => {
      const runner = MODULE_RUNNERS[moduleName];
      const timeoutMs = getModuleTimeout(moduleName);

      return runModuleWithTimeout(
        moduleName,
        () => runner({ domain, scanId: scan_id, companyName }),
        timeoutMs,
        scan_id
      );
    });

    const independentResults = await Promise.all(independentPromises);
    results.push(...independentResults);

    for (const r of independentResults) {
      if (r.status === 'failed' || r.status === 'timeout') {
        failedModules.push(r.module);
      }
    }

    // Phase 3: Run dependent modules
    const dependentModules = availableModules.filter(m =>
      m !== 'endpoint_discovery' &&
      MODULE_REGISTRY[m]?.dependencies?.length
    );

    if (dependentModules.length > 0) {
      log.info({ scanId: scan_id, count: dependentModules.length }, 'Phase 3: Running dependent modules');

      const dependentPromises = dependentModules.map(moduleName => {
        const runner = MODULE_RUNNERS[moduleName];
        const timeoutMs = getModuleTimeout(moduleName);

        return runModuleWithTimeout(
          moduleName,
          () => runner({ domain, scanId: scan_id, companyName }),
          timeoutMs,
          scan_id
        );
      });

      const dependentResults = await Promise.all(dependentPromises);
      results.push(...dependentResults);

      for (const r of dependentResults) {
        if (r.status === 'failed' || r.status === 'timeout') {
          failedModules.push(r.module);
        }
      }
    }

    // Phase 4: Run asset correlator
    try {
      log.info({ scanId: scan_id }, 'Phase 4: Running asset correlator');
      await runAssetCorrelator({ scanId: scan_id, domain, tier: config.tier || 'tier1' });
    } catch (error) {
      log.warn({ err: error, scanId: scan_id }, 'Asset correlation failed');
    }

    // Calculate totals
    const totalFindings = results.reduce((sum, r) => sum + r.findings, 0);
    const duration = Date.now() - startTime;
    const successfulModules = results.filter(r => r.status === 'success').length;

    // Determine overall status
    let status: 'completed' | 'partial' | 'failed' = 'completed';
    if (failedModules.length > 0 && successfulModules === 0) {
      status = 'failed';
    } else if (failedModules.length > 0) {
      status = 'partial';
    }

    log.info({
      scanId: scan_id,
      status,
      totalFindings,
      modulesRun: results.length - skippedModules.length,
      modulesFailed: failedModules.length,
      modulesSkipped: skippedModules.length,
      durationMs: duration,
    }, 'Scan execution completed');

    // Store scan summary artifact
    await insertArtifact({
      type: 'scan_summary',
      val_text: `Scan completed: ${totalFindings} findings from ${successfulModules} modules`,
      severity: totalFindings > 0 ? 'HIGH' : 'INFO',
      meta: {
        scan_id,
        domain,
        profile,
        status,
        totalFindings,
        modulesRun: results.length - skippedModules.length,
        modulesFailed: failedModules.length,
        modulesSkipped: skippedModules.length,
        failedModules,
        skippedModules,
        duration_ms: duration,
        moduleResults: results,
      },
    });

    return {
      scan_id,
      domain,
      status,
      totalFindings,
      modulesRun: results.length - skippedModules.length,
      modulesFailed: failedModules.length,
      modulesSkipped: skippedModules.length,
      duration_ms: duration,
      failedModules,
      skippedModules,
    };

  } catch (error) {
    const duration = Date.now() - startTime;
    const errorMessage = error instanceof Error ? error.message : String(error);

    log.error({ err: error, scanId: scan_id, durationMs: duration }, 'Scan execution failed');

    await insertArtifact({
      type: 'scan_error',
      val_text: `Scan failed: ${errorMessage}`,
      severity: 'CRITICAL',
      meta: { scan_id, domain, error: errorMessage },
    });

    return {
      scan_id,
      domain,
      status: 'failed',
      totalFindings: 0,
      modulesRun: 0,
      modulesFailed: 1,
      modulesSkipped: 0,
      duration_ms: duration,
      failedModules: ['orchestrator'],
      skippedModules: [],
    };
  }
}

// === Helper Functions ===
function getModuleTimeout(moduleName: string): number {
  const reg = MODULE_REGISTRY[moduleName];
  if (reg?.estimatedDurationMs) {
    // Allow 2x estimated duration as timeout
    return Math.max(reg.estimatedDurationMs * 2, DEFAULT_MODULE_TIMEOUT_MS);
  }
  return DEFAULT_MODULE_TIMEOUT_MS;
}
