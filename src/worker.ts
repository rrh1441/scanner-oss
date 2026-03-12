import { config } from 'dotenv';
import { insertArtifact } from './core/artifactStore.js';
import { runShodanScan } from './modules/shodan.js';
import { runDocumentExposure } from './modules/documentExposure.js';
import { runClientSecretScanner } from './modules/clientSecretScanner.js';
import { runTlsScan } from './modules/tlsScan.js';
// import { runNucleiLegacy as runNuclei } from './modules/nuclei.js'; // Moved to Tier 2
import { executeModule as runLightweightCveCheck } from './modules/lightweightCveCheck.js';
import { runSpfDmarc } from './modules/spfDmarc.js';
import { runEndpointDiscovery } from './modules/endpointDiscovery.js';
import { runTechStackScan } from './modules/techStackScan.js';
import { runAbuseIntelScan } from './modules/abuseIntelScan.js';
import { runAccessibilityScan } from './modules/accessibilityScan.js';
import { runInfostealerProbe } from './modules/infostealerProbe.js';
import { runAssetCorrelator } from './modules/assetCorrelator.js';
import { runConfigExposureScanner } from './modules/configExposureScanner.js';
import { runBackendExposureScanner } from './modules/backendExposureScanner.js';
import { runDenialWalletScan } from './modules/denialWalletScan.js';
import { runAiPathFinder } from './modules/aiPathFinder.js';
import { runWhoisWrapper } from './modules/whoisWrapper.js';
import { runWpPluginQuickScan } from './modules/wpPluginQuickScan.js';
import { runWpVulnResolver } from './modules/wpVulnResolver.js';
import { runNextjsRscScan } from './modules/nextjsRscScan.js';
import { createModuleLogger } from './core/logger.js';

const log = createModuleLogger('worker');

// Module timeout wrapper
async function runModuleWithTimeout<T>(
  moduleName: string,
  moduleFunction: () => Promise<T>,
  timeoutMs: number,
  scanId: string,
  options: { onTimeoutReturn?: T } = {}
): Promise<T> {
  const startTime = Date.now();
  
  let timeoutHandle: NodeJS.Timeout | undefined;
  
  try {
    return await Promise.race([
      moduleFunction().then(result => {
        const duration = Date.now() - startTime;
        log.info({ moduleName, durationMs: duration, scanId }, 'Module completed');
        if (timeoutHandle) clearTimeout(timeoutHandle);
        return result;
      }).catch(error => {
        const duration = Date.now() - startTime;
        log.error({ moduleName, err: error, durationMs: duration, scanId }, 'Module failed');
        if (timeoutHandle) clearTimeout(timeoutHandle);
        throw error;
      }),
      new Promise<T>((_, reject) => {
        timeoutHandle = setTimeout(() => {
          log.warn({ moduleName, timeoutMs, scanId }, 'Module timeout');
          reject(new Error(`Module ${moduleName} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  } catch (error) {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    if (error instanceof Error && error.message.includes('timed out') && options.onTimeoutReturn !== undefined) {
      log.info({ moduleName, scanId }, 'Timeout handled - returning fallback result');
      return options.onTimeoutReturn;
    }
    throw error;
  }
}

config();

const ENABLE_ENDPOINT_DISCOVERY = process.env.ENABLE_ENDPOINT_DISCOVERY !== 'false';
const ENDPOINT_DISCOVERY_TIMEOUT_MS = parseInt(process.env.ENDPOINT_DISCOVERY_TIMEOUT_MS || '60000', 10);

// Update scan status - uses local database
async function updateScanStatus(scanId: string, updates: any) {
  try {
    // For OSS, scan status is managed by queueService/database
    // This is a no-op stub for compatibility
    log.debug({ scanId, updates }, 'Scan status update (local mode)');
  } catch (error) {
    log.error({ err: error, scanId }, 'Failed to update scan');
  }
}

interface ScanJob {
  scanId: string;
  companyName: string;
  domain: string;
  createdAt: string;
}

// Tier configuration
const BASE_TIER_1_MODULES = [
  'config_exposure',
  'document_exposure',
  'shodan',
  'breach_directory_probe',
  'whois_wrapper',  // Added: domain registration data
  'ai_path_finder',  // Added: AI-powered discovery (run early to inform others)
  'endpoint_discovery',
  'tech_stack_scan',
  'wp_plugin_quickscan', // NEW: fast WP plugin inventory (runs only if WP markers found)
  'wp_vuln_resolver',    // NEW: resolve plugin vulns via NVD/heuristics
  'abuse_intel_scan',
  'accessibility_scan',
  'lightweight_cve_check',  // Replaced nuclei with fast CVE checker
  'tls_scan',
  'spf_dmarc',
  'client_secret_scanner',
  'backend_exposure_scanner',
  'denial_wallet_scan',  // Added: cloud cost exploitation
  'nextjs_rsc_scan'  // Added: Next.js RSC/App Router RCE fingerprinting
];

const TIER_1_MODULES = ENABLE_ENDPOINT_DISCOVERY
  ? BASE_TIER_1_MODULES
  : BASE_TIER_1_MODULES.filter(module => module !== 'endpoint_discovery');

export async function processScan(job: ScanJob) {
  const { scanId, companyName, domain } = job;

  log.info({ scanId, companyName, domain }, 'Processing scan');
  
  try {
    // Update scan status
    await updateScanStatus(scanId, {
      status: 'processing',
      started_at: new Date().toISOString()
    });
    
    const activeModules = TIER_1_MODULES;
    let totalFindings = 0;
    
    // Run modules in parallel where possible
    const parallelModules: { [key: string]: Promise<number> } = {};
    
    // Independent modules
    if (activeModules.includes('breach_directory_probe')) {
      log.info({ module: 'breach_directory_probe', scanId }, 'Starting module');
      parallelModules.breach_directory_probe = runModuleWithTimeout('breach_directory_probe', 
        () => runInfostealerProbe({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('shodan')) {
      log.info({ module: 'shodan', scanId }, 'Starting module');
      parallelModules.shodan = runModuleWithTimeout('shodan', 
        () => runShodanScan({ domain, scanId, companyName }), 
        3 * 60 * 1000, scanId);
    }
    // dns_twist moved to Tier 2 - no longer runs in Tier 1
    if (activeModules.includes('document_exposure')) {
      log.info({ module: 'document_exposure', scanId }, 'Starting module');
      parallelModules.document_exposure = runModuleWithTimeout('document_exposure', 
        () => runDocumentExposure({ companyName, domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('whois_wrapper')) {
      log.info({ module: 'whois_wrapper', scanId }, 'Starting module');
      parallelModules.whois_wrapper = runModuleWithTimeout('whois_wrapper', 
        () => runWhoisWrapper({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('ai_path_finder')) {
      log.info({ module: 'ai_path_finder', scanId }, 'Starting module');
      parallelModules.ai_path_finder = runModuleWithTimeout('ai_path_finder', 
        () => runAiPathFinder({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (ENABLE_ENDPOINT_DISCOVERY && activeModules.includes('endpoint_discovery')) {
      log.info({ module: 'endpoint_discovery', scanId }, 'Starting module');
      parallelModules.endpoint_discovery = runModuleWithTimeout('endpoint_discovery', 
        () => runEndpointDiscovery({ domain, scanId }), 
        ENDPOINT_DISCOVERY_TIMEOUT_MS, scanId, { onTimeoutReturn: 0 });
    }
    if (activeModules.includes('tls_scan')) {
      log.info({ module: 'tls_scan', scanId }, 'Starting module');
      parallelModules.tls_scan = runModuleWithTimeout('tls_scan', 
        () => runTlsScan({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('spf_dmarc')) {
      log.info({ module: 'spf_dmarc', scanId }, 'Starting module');
      parallelModules.spf_dmarc = runModuleWithTimeout('spf_dmarc', 
        () => runSpfDmarc({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('config_exposure')) {
      log.info({ module: 'config_exposure', scanId }, 'Starting module');
      parallelModules.config_exposure = runModuleWithTimeout('config_exposure', 
        () => runConfigExposureScanner({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    
    // Wait for endpoint discovery first
    let endpointResults = 0;
    if (ENABLE_ENDPOINT_DISCOVERY && parallelModules.endpoint_discovery) {
      endpointResults = await parallelModules.endpoint_discovery;
      log.info({ findingsCount: endpointResults }, 'Endpoint discovery completed');
      delete parallelModules.endpoint_discovery;
      totalFindings += endpointResults;
    }
    
    // Then run dependent modules
    if (activeModules.includes('lightweight_cve_check')) {
      log.info({ module: 'lightweight_cve_check', scanId }, 'Starting module');
      parallelModules.lightweight_cve_check = runModuleWithTimeout('lightweight_cve_check', 
        async () => {
          const result = await runLightweightCveCheck({ scanId, domain, artifacts: [] });
          // Return the count of findings for compatibility
          return result.findings ? result.findings.length : 0;
        }, 
        30 * 1000, scanId);  // 30 second timeout for fast CVE check
    }
    if (activeModules.includes('tech_stack_scan')) {
      log.info({ module: 'tech_stack_scan', scanId }, 'Starting module');
      parallelModules.tech_stack_scan = runModuleWithTimeout('tech_stack_scan', 
        () => runTechStackScan({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('wp_plugin_quickscan')) {
      log.info({ module: 'wp_plugin_quickscan', scanId }, 'Starting module');
      // Fast, passive; module self-gates by checking WP markers
      parallelModules.wp_plugin_quickscan = runModuleWithTimeout('wp_plugin_quickscan',
        () => runWpPluginQuickScan({ domain, scanId }),
        30 * 1000, scanId, { onTimeoutReturn: 0 });
    }
    if (activeModules.includes('wp_vuln_resolver')) {
      log.info({ module: 'wp_vuln_resolver', scanId }, 'Starting module');
      // Depends on plugin inventory artifact; will no-op if none
      parallelModules.wp_vuln_resolver = runModuleWithTimeout('wp_vuln_resolver',
        () => runWpVulnResolver({ domain, scanId }),
        45 * 1000, scanId, { onTimeoutReturn: 0 });
    }
    if (activeModules.includes('abuse_intel_scan')) {
      log.info({ module: 'abuse_intel_scan', scanId }, 'Starting module');
      parallelModules.abuse_intel_scan = runModuleWithTimeout('abuse_intel_scan', 
        () => runAbuseIntelScan({ scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('client_secret_scanner')) {
      log.info({ module: 'client_secret_scanner', scanId }, 'Starting module');
      parallelModules.client_secret_scanner = runModuleWithTimeout('client_secret_scanner', 
        () => runClientSecretScanner({ scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('backend_exposure_scanner')) {
      log.info({ module: 'backend_exposure_scanner', scanId }, 'Starting module');
      parallelModules.backend_exposure_scanner = runModuleWithTimeout('backend_exposure_scanner', 
        () => runBackendExposureScanner({ scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('accessibility_scan')) {
      log.info({ module: 'accessibility_scan', scanId }, 'Starting module');
      parallelModules.accessibility_scan = runModuleWithTimeout('accessibility_scan', 
        () => runAccessibilityScan({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('denial_wallet_scan')) {
      log.info({ module: 'denial_wallet_scan', scanId }, 'Starting module');
      parallelModules.denial_wallet_scan = runModuleWithTimeout('denial_wallet_scan',
        () => runDenialWalletScan({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('nextjs_rsc_scan')) {
      log.info({ module: 'nextjs_rsc_scan', scanId }, 'Starting module');
      // Fast HTTP fingerprinting - 30 second timeout
      parallelModules.nextjs_rsc_scan = runModuleWithTimeout('nextjs_rsc_scan',
        () => runNextjsRscScan({ domain, scanId }),
        30 * 1000, scanId, { onTimeoutReturn: 0 });
    }

    // Wait for all modules with graceful degradation
    let completedModules = 0;
    const totalModules = Object.keys(parallelModules).length;
    
    for (const [moduleName, promise] of Object.entries(parallelModules)) {
      try {
        const results = await promise;
        completedModules++;
        totalFindings += results;
        log.info({ completedModules, totalModules, moduleName, findingsCount: results, scanId }, 'Module progress');
      } catch (error) {
        completedModules++;
        log.warn({ moduleName, err: error, scanId }, 'Module failed but scan continues');
        log.info({ completedModules, totalModules, moduleName, status: 'FAILED', scanId }, 'Module progress');
        
        await insertArtifact({
          type: 'scan_error',
          val_text: `Module ${moduleName} failed: ${(error as Error).message}`,
          severity: 'MEDIUM',
          meta: { scan_id: scanId, module: moduleName }
        });
      }
    }
    
    // Run asset correlator
    try {
      await runAssetCorrelator({ scanId, domain, tier: 'tier1' });
      log.info({ scanId }, 'Asset correlation completed');
    } catch (error) {
      log.warn({ err: error, scanId }, 'Asset correlation failed');
    }
    
    // Update scan completion
    await updateScanStatus(scanId, {
      status: 'completed',
      completed_at: new Date().toISOString(),
      total_findings: totalFindings
    });
    
    log.info({ totalFindings, scanId }, 'Scan completed');

  } catch (error) {
    log.error({ err: error, scanId }, 'Scan failed');
    
    await updateScanStatus(scanId, {
      status: 'failed',
      error: (error as Error).message,
      failed_at: new Date().toISOString()
    });
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `Scan failed: ${(error as Error).message}`,
      severity: 'CRITICAL',
      meta: { scan_id: scanId }
    });
    
    throw error;
  }
}

// Export for use by worker-pubsub.ts
// The main entry point is now handled by worker-pubsub.ts which listens to Pub/Sub messages
