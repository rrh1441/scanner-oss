/**
 * External Tool Validation
 *
 * Validates the availability and configuration of external security tools
 * required by scan modules. Provides graceful degradation warnings at startup.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import { createModuleLogger } from './logger.js';

const execFileAsync = promisify(execFile);
const log = createModuleLogger('toolValidation');

export interface ToolStatus {
  name: string;
  available: boolean;
  version?: string;
  path?: string;
  error?: string;
  required: boolean;
  affectedModules: string[];
}

export interface ValidationReport {
  timestamp: Date;
  tools: ToolStatus[];
  allRequired: boolean;
  warnings: string[];
  errors: string[];
}

interface ToolDefinition {
  name: string;
  command: string;
  versionArgs: string[];
  required: boolean;
  affectedModules: string[];
  versionPattern?: RegExp;
  paths?: string[];
}

const EXTERNAL_TOOLS: ToolDefinition[] = [
  {
    name: 'Nuclei',
    command: 'nuclei',
    versionArgs: ['-version'],
    required: false,
    affectedModules: ['nuclei', 'cve_verifier', 'db_port_scan', 'rdp_vpn_templates'],
    versionPattern: /nuclei\s+v?([\d.]+)/i,
  },
  {
    name: 'sslscan',
    command: 'sslscan',
    versionArgs: ['--version'],
    required: false,
    affectedModules: ['tls_scan'],
    versionPattern: /sslscan\s+version\s+([\d.]+)/i,
  },
  {
    name: 'nmap',
    command: 'nmap',
    versionArgs: ['--version'],
    required: false,
    affectedModules: ['db_port_scan', 'port_scan'],
    versionPattern: /Nmap\s+version\s+([\d.]+)/i,
  },
  {
    name: 'dnstwist',
    command: 'dnstwist',
    versionArgs: ['--version'],
    required: false,
    affectedModules: ['dns_twist'],
    versionPattern: /dnstwist\s+([\d.]+)/i,
  },
  {
    name: 'TruffleHog',
    command: 'trufflehog',
    versionArgs: ['--version'],
    required: false,
    affectedModules: ['trufflehog', 'github_secret_search'],
    versionPattern: /trufflehog\s+([\d.]+)/i,
  },
  {
    name: 'testssl.sh',
    command: 'testssl.sh',
    versionArgs: ['--version'],
    required: false,
    affectedModules: ['tls_scan'],
    paths: ['/usr/local/bin/testssl.sh', '/opt/testssl/testssl.sh'],
  },
  {
    name: 'OWASP ZAP',
    command: 'zap-baseline.py',
    versionArgs: ['--version'],
    required: false,
    affectedModules: ['zap_scan'],
  },
  {
    name: 'SpiderFoot',
    command: 'spiderfoot',
    versionArgs: ['--version'],
    required: false,
    affectedModules: ['spider_foot'],
  },
];

/**
 * Check if a single tool is available
 */
async function checkTool(tool: ToolDefinition): Promise<ToolStatus> {
  const status: ToolStatus = {
    name: tool.name,
    available: false,
    required: tool.required,
    affectedModules: tool.affectedModules,
  };

  try {
    // First try to find the command
    const { stdout: whichOutput } = await execFileAsync('which', [tool.command], {
      timeout: 5000,
    }).catch(() => ({ stdout: '' }));

    if (whichOutput.trim()) {
      status.path = whichOutput.trim();
    } else if (tool.paths) {
      // Check alternative paths
      for (const path of tool.paths) {
        if (existsSync(path)) {
          status.path = path;
          break;
        }
      }
    }

    if (!status.path) {
      status.error = `${tool.command} not found in PATH`;
      return status;
    }

    // Get version
    const { stdout, stderr } = await execFileAsync(
      status.path,
      tool.versionArgs,
      { timeout: 10000 }
    ).catch((err) => ({
      stdout: err.stdout || '',
      stderr: err.stderr || err.message,
    }));

    const output = stdout || stderr;

    if (tool.versionPattern) {
      const match = output.match(tool.versionPattern);
      if (match) {
        status.version = match[1];
      }
    }

    status.available = true;

  } catch (error) {
    status.error = error instanceof Error ? error.message : String(error);
  }

  return status;
}

/**
 * Validate all external tools and generate a report
 */
export async function validateExternalTools(): Promise<ValidationReport> {
  const report: ValidationReport = {
    timestamp: new Date(),
    tools: [],
    allRequired: true,
    warnings: [],
    errors: [],
  };

  log.info('Validating external tools...');

  // Check all tools in parallel
  const results = await Promise.all(EXTERNAL_TOOLS.map(checkTool));
  report.tools = results;

  // Generate warnings and errors
  for (const tool of results) {
    if (!tool.available) {
      if (tool.required) {
        report.allRequired = false;
        report.errors.push(
          `Required tool '${tool.name}' is not available: ${tool.error}. ` +
          `Affected modules: ${tool.affectedModules.join(', ')}`
        );
      } else {
        report.warnings.push(
          `Optional tool '${tool.name}' is not available. ` +
          `Modules that will be disabled: ${tool.affectedModules.join(', ')}`
        );
      }
    } else {
      log.info({
        tool: tool.name,
        version: tool.version,
        path: tool.path,
      }, 'Tool available');
    }
  }

  // Log summary
  const availableCount = results.filter(t => t.available).length;
  const totalCount = results.length;

  log.info({
    available: availableCount,
    total: totalCount,
    warnings: report.warnings.length,
    errors: report.errors.length,
  }, 'Tool validation complete');

  // Log warnings
  for (const warning of report.warnings) {
    log.warn(warning);
  }

  // Log errors
  for (const error of report.errors) {
    log.error(error);
  }

  return report;
}

/**
 * Check if a specific tool is available
 */
export function isToolAvailable(toolName: string, report: ValidationReport): boolean {
  const tool = report.tools.find(t => t.name.toLowerCase() === toolName.toLowerCase());
  return tool?.available ?? false;
}

/**
 * Get list of modules that should be disabled due to missing tools
 */
export function getDisabledModules(report: ValidationReport): string[] {
  const disabled = new Set<string>();

  for (const tool of report.tools) {
    if (!tool.available) {
      for (const module of tool.affectedModules) {
        disabled.add(module);
      }
    }
  }

  return Array.from(disabled);
}

/**
 * Validate API keys and environment configuration
 */
export function validateApiKeys(): {
  configured: string[];
  missing: string[];
  warnings: string[];
} {
  const result = {
    configured: [] as string[],
    missing: [] as string[],
    warnings: [] as string[],
  };

  const API_KEYS = [
    { key: 'SHODAN_API_KEY', service: 'Shodan', modules: ['shodan'] },
    { key: 'LEAKCHECK_API_KEY', service: 'LeakCheck', modules: ['breach_directory_probe'] },
    { key: 'GITHUB_TOKEN', service: 'GitHub', modules: ['github_secret_search'] },
    { key: 'NVD_API_KEY', service: 'NVD', modules: ['lightweight_cve_check', 'wp_vuln_resolver'], optional: true },
    { key: 'CENSYS_API_ID', service: 'Censys', modules: ['censys_platform_scan'] },
    { key: 'CENSYS_API_SECRET', service: 'Censys', modules: ['censys_platform_scan'] },
    { key: 'ABUSEIPDB_API_KEY', service: 'AbuseIPDB', modules: ['abuse_intel_scan'] },
    { key: 'WHOISXML_API_KEY', service: 'WHOISXML', modules: ['whois_wrapper'], optional: true },
    { key: 'OPENAI_API_KEY', service: 'OpenAI', modules: ['ai_path_finder'], optional: true },
    { key: 'OPENVAS_HOST', service: 'OpenVAS', modules: ['openvas_scan'] },
    { key: 'OPENVAS_USER', service: 'OpenVAS', modules: ['openvas_scan'] },
    { key: 'OPENVAS_PASSWORD', service: 'OpenVAS', modules: ['openvas_scan'] },
  ];

  for (const { key, service, modules, optional } of API_KEYS) {
    if (process.env[key]) {
      result.configured.push(service);
    } else {
      result.missing.push(service);
      if (!optional) {
        result.warnings.push(
          `${service} API key (${key}) not configured. Modules affected: ${modules.join(', ')}`
        );
      }
    }
  }

  // Log results
  log.info({
    configured: result.configured.length,
    missing: result.missing.length,
  }, 'API key validation complete');

  for (const warning of result.warnings) {
    log.warn(warning);
  }

  return result;
}

/**
 * Run full startup validation
 */
export async function runStartupValidation(): Promise<{
  tools: ValidationReport;
  apiKeys: ReturnType<typeof validateApiKeys>;
  ready: boolean;
}> {
  log.info('Running startup validation...');

  const [tools, apiKeys] = await Promise.all([
    validateExternalTools(),
    Promise.resolve(validateApiKeys()),
  ]);

  // Determine if system is ready
  // For now, we don't require any tools - just warn about missing ones
  const ready = true; // Could be: tools.allRequired && apiKeys.missing.length === 0

  if (ready) {
    log.info('Startup validation passed - system is ready');
  } else {
    log.warn('Startup validation found issues - some features may be unavailable');
  }

  return { tools, apiKeys, ready };
}
