/**
 * Active Port Scanning Module
 *
 * Performs comprehensive port scanning on target domains to identify:
 * - Open services and their versions
 * - Potentially dangerous exposed services
 * - Misconfigurations and security issues
 *
 * Uses nmap for service detection and version fingerprinting.
 * This module is rate-limited and should only run in Tier 2 (deep scan).
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { XMLParser } from 'fast-xml-parser';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('portScan');
const execFileAsync = promisify(execFile);

interface PortScanJob {
  domain: string;
  scanId: string;
  hosts?: string[];
  ports?: string;
  quickScan?: boolean;
}

interface DiscoveredService {
  host: string;
  port: number;
  protocol: string;
  state: string;
  service: string;
  version?: string;
  product?: string;
  extraInfo?: string;
  cpe?: string[];
}

interface PortScanResult {
  success: boolean;
  services: DiscoveredService[];
  findings: number;
  errors: string[];
}

// Common ports to scan in quick mode
const QUICK_SCAN_PORTS = [
  21,    // FTP
  22,    // SSH
  23,    // Telnet
  25,    // SMTP
  53,    // DNS
  80,    // HTTP
  110,   // POP3
  143,   // IMAP
  443,   // HTTPS
  445,   // SMB
  587,   // SMTP Submission
  993,   // IMAPS
  995,   // POP3S
  3389,  // RDP
  8080,  // HTTP Alt
  8443,  // HTTPS Alt
].join(',');

// Extended ports for full scan
const FULL_SCAN_PORTS = [
  ...QUICK_SCAN_PORTS.split(',').map(Number),
  135,   // MSRPC
  139,   // NetBIOS
  389,   // LDAP
  636,   // LDAPS
  1433,  // MSSQL
  1521,  // Oracle
  2049,  // NFS
  3306,  // MySQL
  5432,  // PostgreSQL
  5900,  // VNC
  5901,  // VNC
  6379,  // Redis
  8000,  // HTTP Alt
  8888,  // HTTP Alt
  9000,  // Various
  9200,  // Elasticsearch
  27017, // MongoDB
].join(',');

// High-risk services that always generate findings
const HIGH_RISK_SERVICES = new Set([
  'telnet',
  'ftp',
  'vnc',
  'rdp',
  'ms-wbt-server',
  'microsoft-ds',
  'netbios-ssn',
  'msrpc',
  'nfs',
  'ldap',
]);

// Services that are concerning if exposed to internet
const CONCERNING_SERVICES = new Set([
  'ssh',
  'smtp',
  'mysql',
  'postgresql',
  'mongodb',
  'redis',
  'elasticsearch',
  'memcached',
  'mssql',
  'oracle',
]);

/**
 * Check if nmap is available
 */
async function checkNmapAvailable(): Promise<boolean> {
  try {
    await execFileAsync('nmap', ['--version'], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Parse nmap XML output
 */
function parseNmapOutput(xmlOutput: string): DiscoveredService[] {
  const services: DiscoveredService[] = [];
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
  });

  try {
    const result = parser.parse(xmlOutput);
    const nmapRun = result.nmaprun;

    if (!nmapRun?.host) return services;

    // Handle single or multiple hosts
    const hosts = Array.isArray(nmapRun.host) ? nmapRun.host : [nmapRun.host];

    for (const host of hosts) {
      // Get host address
      const addresses = Array.isArray(host.address) ? host.address : [host.address];
      const ipAddress = addresses.find((a: any) => a?.['@_addrtype'] === 'ipv4')?.['@_addr'] ||
                       addresses[0]?.['@_addr'] ||
                       'unknown';

      // Get ports
      const ports = host.ports?.port;
      if (!ports) continue;

      const portList = Array.isArray(ports) ? ports : [ports];

      for (const port of portList) {
        const state = port.state?.['@_state'];
        if (state !== 'open') continue;

        const service = port.service || {};
        const cpeList: string[] = [];

        // Extract CPE strings if present
        if (service.cpe) {
          const cpes = Array.isArray(service.cpe) ? service.cpe : [service.cpe];
          cpeList.push(...cpes.filter((c: unknown) => typeof c === 'string'));
        }

        services.push({
          host: ipAddress,
          port: parseInt(port['@_portid'], 10),
          protocol: port['@_protocol'] || 'tcp',
          state,
          service: service['@_name'] || 'unknown',
          version: service['@_version'],
          product: service['@_product'],
          extraInfo: service['@_extrainfo'],
          cpe: cpeList.length > 0 ? cpeList : undefined,
        });
      }
    }
  } catch (error) {
    log.warn({ err: error }, 'Failed to parse nmap output');
  }

  return services;
}

/**
 * Determine severity based on service type
 */
function getSeverity(service: DiscoveredService): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  const serviceName = service.service.toLowerCase();

  // Critical: Services that should never be exposed
  if (serviceName === 'telnet' || serviceName === 'vnc') {
    return 'CRITICAL';
  }

  // High: Services with known security risks
  if (HIGH_RISK_SERVICES.has(serviceName)) {
    return 'HIGH';
  }

  // Medium: Database and infrastructure services
  if (CONCERNING_SERVICES.has(serviceName)) {
    return 'MEDIUM';
  }

  // Low: Standard web services
  if (serviceName === 'http' || serviceName === 'https' || serviceName === 'ssh') {
    return 'LOW';
  }

  return 'INFO';
}

/**
 * Get recommendation based on service
 */
function getRecommendation(service: DiscoveredService): string {
  const serviceName = service.service.toLowerCase();

  if (serviceName === 'telnet') {
    return 'Disable Telnet and use SSH for remote access. Telnet transmits data in plaintext.';
  }
  if (serviceName === 'ftp') {
    return 'Replace FTP with SFTP or FTPS. If FTP is required, ensure anonymous access is disabled.';
  }
  if (serviceName === 'vnc' || serviceName === 'rdp' || serviceName === 'ms-wbt-server') {
    return 'Restrict remote desktop access to VPN users only. Never expose RDP/VNC directly to the internet.';
  }
  if (serviceName === 'ssh') {
    return 'Ensure SSH is using key-based authentication. Consider changing the default port and using fail2ban.';
  }
  if (CONCERNING_SERVICES.has(serviceName)) {
    return `Restrict ${service.service} access to internal networks only. Database services should not be internet-accessible.`;
  }

  return 'Review if this service needs to be publicly accessible. Apply appropriate firewall rules.';
}

/**
 * Run port scan using nmap
 */
export async function runPortScan(job: PortScanJob): Promise<PortScanResult> {
  const result: PortScanResult = {
    success: false,
    services: [],
    findings: 0,
    errors: [],
  };

  log.info({ domain: job.domain, scanId: job.scanId }, 'Starting port scan');

  // Check nmap availability
  if (!await checkNmapAvailable()) {
    log.warn('nmap not available - skipping port scan');
    result.errors.push('nmap not installed');
    return result;
  }

  const hosts = job.hosts || [job.domain];
  const ports = job.ports || (job.quickScan ? QUICK_SCAN_PORTS : FULL_SCAN_PORTS);

  for (const host of hosts) {
    try {
      log.info({ host, ports: ports.substring(0, 50) + '...' }, 'Scanning host');

      // Run nmap with service detection
      const args = [
        '-Pn',              // Treat all hosts as online
        '-sV',              // Version detection
        '--version-light', // Faster version detection
        '-p', ports,        // Port list
        '-oX', '-',         // XML output to stdout
        '--host-timeout', '300s',  // 5 minute timeout per host
        '--max-retries', '2',
        host,
      ];

      const { stdout } = await execFileAsync('nmap', args, {
        timeout: 600000, // 10 minute overall timeout
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      });

      const services = parseNmapOutput(stdout);
      result.services.push(...services);

      log.info({
        host,
        servicesFound: services.length,
      }, 'Host scan complete');

    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      log.error({ err: error, host }, 'Error scanning host');
      result.errors.push(`Error scanning ${host}: ${errMsg}`);
    }
  }

  // Generate findings for discovered services
  for (const service of result.services) {
    const severity = getSeverity(service);

    // Only create findings for concerning services
    if (severity === 'INFO' && !HIGH_RISK_SERVICES.has(service.service.toLowerCase()) &&
        !CONCERNING_SERVICES.has(service.service.toLowerCase())) {
      continue;
    }

    const artifactId = await insertArtifact({
      type: 'open_port',
      val_text: `${service.host}:${service.port}/${service.protocol} - ${service.service}`,
      severity,
      meta: {
        scan_id: job.scanId,
        scan_module: 'port_scan',
        host: service.host,
        port: service.port,
        protocol: service.protocol,
        service: service.service,
        version: service.version,
        product: service.product,
        cpe: service.cpe,
      },
    });

    await insertFinding({
      artifact_id: artifactId,
      finding_type: 'EXPOSED_SERVICE',
      scan_id: job.scanId,
      severity,
      type: 'EXPOSED_SERVICE',
      description: `Open ${service.service} service on port ${service.port}` +
        (service.version ? ` (${service.product || service.service} ${service.version})` : ''),
      recommendation: getRecommendation(service),
      data: {
        host: service.host,
        port: service.port,
        protocol: service.protocol,
        service: service.service,
        version: service.version,
        product: service.product,
        extra_info: service.extraInfo,
        cpe: service.cpe,
      },
    });

    result.findings++;
  }

  result.success = true;

  log.info({
    domain: job.domain,
    scanId: job.scanId,
    totalServices: result.services.length,
    findings: result.findings,
    errors: result.errors.length,
  }, 'Port scan complete');

  return result;
}
