/**
 * Scan Profile Configuration
 *
 * Defines available scan profiles and their module configurations.
 * Profiles allow for lightweight, targeted scans vs comprehensive assessments.
 */

export type ScanProfile = 'full' | 'quick' | 'wordpress' | 'infostealer' | 'email' | 'github';

export interface ProfileConfig {
  name: string;
  description: string;
  tier: 'tier1' | 'tier2';
  modules: string[];
  estimatedDurationMs: number;
  /** Modules to skip even if normally included */
  skipModules?: string[];
}

/**
 * Module definitions with metadata
 */
export const MODULE_REGISTRY: Record<string, {
  name: string;
  category: string;
  tier: 'tier1' | 'tier2' | 'both';
  requiresApiKey?: string[];
  estimatedDurationMs: number;
  dependencies?: string[];
}> = {
  // === TIER 1: Fast, passive reconnaissance ===
  shodan: {
    name: 'Shodan Intelligence',
    category: 'reconnaissance',
    tier: 'tier1',
    requiresApiKey: ['SHODAN_API_KEY'],
    estimatedDurationMs: 30000,
  },
  config_exposure: {
    name: 'Configuration Exposure',
    category: 'exposure',
    tier: 'tier1',
    estimatedDurationMs: 45000,
  },
  document_exposure: {
    name: 'Document Exposure',
    category: 'exposure',
    tier: 'tier1',
    estimatedDurationMs: 60000,
  },
  breach_directory_probe: {
    name: 'Breach/Infostealer Detection',
    category: 'credentials',
    tier: 'tier1',
    requiresApiKey: ['LEAKCHECK_API_KEY'],
    estimatedDurationMs: 45000,
  },
  whois_wrapper: {
    name: 'WHOIS Intelligence',
    category: 'reconnaissance',
    tier: 'tier1',
    estimatedDurationMs: 15000,
  },
  ai_path_finder: {
    name: 'AI Path Discovery',
    category: 'discovery',
    tier: 'tier1',
    estimatedDurationMs: 30000,
  },
  endpoint_discovery: {
    name: 'Endpoint Discovery',
    category: 'discovery',
    tier: 'tier1',
    estimatedDurationMs: 60000,
  },
  tech_stack_scan: {
    name: 'Technology Stack Detection',
    category: 'reconnaissance',
    tier: 'tier1',
    estimatedDurationMs: 30000,
  },
  tls_scan: {
    name: 'TLS/SSL Analysis',
    category: 'vulnerability',
    tier: 'tier1',
    estimatedDurationMs: 45000,
  },
  spf_dmarc: {
    name: 'Email Security (SPF/DMARC/DKIM)',
    category: 'email',
    tier: 'tier1',
    estimatedDurationMs: 20000,
  },
  client_secret_scanner: {
    name: 'Client Secret Scanner',
    category: 'credentials',
    tier: 'tier1',
    estimatedDurationMs: 30000,
    dependencies: ['endpoint_discovery'],
  },
  backend_exposure_scanner: {
    name: 'Backend Exposure Scanner',
    category: 'exposure',
    tier: 'tier1',
    estimatedDurationMs: 30000,
    dependencies: ['endpoint_discovery'],
  },
  abuse_intel_scan: {
    name: 'Abuse Intelligence',
    category: 'reputation',
    tier: 'tier1',
    estimatedDurationMs: 20000,
  },
  accessibility_scan: {
    name: 'Accessibility Compliance',
    category: 'compliance',
    tier: 'tier1',
    estimatedDurationMs: 45000,
  },
  lightweight_cve_check: {
    name: 'Lightweight CVE Check',
    category: 'vulnerability',
    tier: 'tier1',
    estimatedDurationMs: 30000,
  },
  wp_plugin_quickscan: {
    name: 'WordPress Plugin Scanner',
    category: 'wordpress',
    tier: 'tier1',
    estimatedDurationMs: 30000,
  },
  wp_vuln_resolver: {
    name: 'WordPress Vulnerability Resolver',
    category: 'wordpress',
    tier: 'tier1',
    estimatedDurationMs: 45000,
    dependencies: ['wp_plugin_quickscan'],
  },
  denial_wallet_scan: {
    name: 'Denial of Wallet Detection',
    category: 'vulnerability',
    tier: 'tier1',
    estimatedDurationMs: 30000,
  },
  nextjs_rsc_scan: {
    name: 'Next.js RSC Scanner',
    category: 'vulnerability',
    tier: 'tier1',
    estimatedDurationMs: 20000,
  },
  subdomain_takeover: {
    name: 'Subdomain Takeover Detection',
    category: 'vulnerability',
    tier: 'tier1',
    estimatedDurationMs: 120000,
  },

  // === TIER 2: Active scanning, deeper analysis ===
  nuclei: {
    name: 'Nuclei Vulnerability Scanner',
    category: 'vulnerability',
    tier: 'tier2',
    estimatedDurationMs: 300000,
  },
  dns_twist: {
    name: 'DNS Typosquatting Detection',
    category: 'brand',
    tier: 'tier2',
    estimatedDurationMs: 180000,
  },
  db_port_scan: {
    name: 'Database Port Scanner',
    category: 'vulnerability',
    tier: 'tier2',
    estimatedDurationMs: 120000,
  },
  port_scan: {
    name: 'Active Port Scanner',
    category: 'vulnerability',
    tier: 'tier2',
    estimatedDurationMs: 300000,
  },
  web_archive_scanner: {
    name: 'Web Archive Analysis',
    category: 'reconnaissance',
    tier: 'tier2',
    estimatedDurationMs: 90000,
  },
  github_secret_search: {
    name: 'GitHub Secret Search',
    category: 'credentials',
    tier: 'tier2',
    requiresApiKey: ['GITHUB_TOKEN'],
    estimatedDurationMs: 60000,
  },
  trufflehog: {
    name: 'TruffleHog Secret Scanner',
    category: 'credentials',
    tier: 'tier2',
    estimatedDurationMs: 180000,
  },
  censys_platform_scan: {
    name: 'Censys Platform Scan',
    category: 'reconnaissance',
    tier: 'tier2',
    requiresApiKey: ['CENSYS_API_ID', 'CENSYS_API_SECRET'],
    estimatedDurationMs: 60000,
  },
  openvas_scan: {
    name: 'OpenVAS Vulnerability Scan',
    category: 'vulnerability',
    tier: 'tier2',
    requiresApiKey: ['OPENVAS_HOST', 'OPENVAS_USER', 'OPENVAS_PASSWORD'],
    estimatedDurationMs: 600000,
  },
  zap_scan: {
    name: 'OWASP ZAP Scan',
    category: 'vulnerability',
    tier: 'tier2',
    estimatedDurationMs: 300000,
  },
  admin_panel_detector: {
    name: 'Admin Panel Detector',
    category: 'exposure',
    tier: 'tier2',
    estimatedDurationMs: 120000,
  },
  dns_zone_transfer: {
    name: 'DNS Zone Transfer Test',
    category: 'vulnerability',
    tier: 'tier2',
    estimatedDurationMs: 30000,
  },
  email_bruteforce_surface: {
    name: 'Email Bruteforce Surface',
    category: 'email',
    tier: 'tier2',
    estimatedDurationMs: 60000,
  },
  rate_limit_scan: {
    name: 'Rate Limit Analysis',
    category: 'vulnerability',
    tier: 'tier2',
    estimatedDurationMs: 90000,
  },
  rdp_vpn_templates: {
    name: 'RDP/VPN Vulnerability Detection',
    category: 'vulnerability',
    tier: 'tier2',
    estimatedDurationMs: 60000,
  },
  cloud_bucket_enum: {
    name: 'Cloud Bucket Enumeration',
    category: 'exposure',
    tier: 'tier1',
    estimatedDurationMs: 120000,
  },
  cert_transparency: {
    name: 'Certificate Transparency Discovery',
    category: 'reconnaissance',
    tier: 'tier1',
    estimatedDurationMs: 30000,
  },
};

/**
 * Scan profile configurations
 */
export const SCAN_PROFILES: Record<ScanProfile, ProfileConfig> = {
  full: {
    name: 'Full Security Scan',
    description: 'Comprehensive security assessment with all Tier 1 and Tier 2 modules',
    tier: 'tier2',
    modules: [
      // Tier 1 - Passive reconnaissance
      'shodan', 'config_exposure', 'document_exposure', 'breach_directory_probe',
      'whois_wrapper', 'ai_path_finder', 'endpoint_discovery', 'tech_stack_scan',
      'tls_scan', 'spf_dmarc', 'client_secret_scanner', 'backend_exposure_scanner',
      'abuse_intel_scan', 'accessibility_scan', 'lightweight_cve_check',
      'wp_plugin_quickscan', 'wp_vuln_resolver', 'denial_wallet_scan',
      'nextjs_rsc_scan', 'subdomain_takeover',
      'cloud_bucket_enum', 'cert_transparency',
      // Tier 2 - Active scanning
      'nuclei', 'dns_twist', 'db_port_scan', 'port_scan', 'web_archive_scanner',
      'github_secret_search', 'admin_panel_detector', 'dns_zone_transfer',
      'rate_limit_scan',
    ],
    estimatedDurationMs: 900000, // 15 minutes
  },

  quick: {
    name: 'Quick Reconnaissance',
    description: 'Fast OSINT-only scan for rapid assessment',
    tier: 'tier1',
    modules: [
      'shodan', 'whois_wrapper', 'tech_stack_scan', 'tls_scan',
      'spf_dmarc', 'lightweight_cve_check', 'subdomain_takeover',
      'cert_transparency',
    ],
    estimatedDurationMs: 180000, // 3 minutes
  },

  wordpress: {
    name: 'WordPress Security Scan',
    description: 'Targeted scan for WordPress installations',
    tier: 'tier1',
    modules: [
      'tech_stack_scan', 'wp_plugin_quickscan', 'wp_vuln_resolver',
      'config_exposure', 'tls_scan', 'lightweight_cve_check',
      'client_secret_scanner', 'admin_panel_detector',
    ],
    estimatedDurationMs: 300000, // 5 minutes
  },

  infostealer: {
    name: 'Credential Breach Scan',
    description: 'Focused scan for credential breaches and infostealer exposure',
    tier: 'tier1',
    modules: [
      'breach_directory_probe', 'github_secret_search', 'client_secret_scanner',
      'document_exposure', 'config_exposure',
    ],
    estimatedDurationMs: 180000, // 3 minutes
  },

  email: {
    name: 'Email Security Scan',
    description: 'Email infrastructure security assessment',
    tier: 'tier1',
    modules: [
      'spf_dmarc', 'breach_directory_probe', 'whois_wrapper',
    ],
    estimatedDurationMs: 120000, // 2 minutes
  },

  github: {
    name: 'GitHub/Repository Scan',
    description: 'Code repository and secret scanning',
    tier: 'tier2',
    modules: [
      'github_secret_search', 'trufflehog', 'client_secret_scanner',
      'breach_directory_probe',
    ],
    estimatedDurationMs: 300000, // 5 minutes
  },
};

/**
 * Get modules for a specific profile
 */
export function getProfileModules(profile: ScanProfile, tier?: 'tier1' | 'tier2'): string[] {
  const config = SCAN_PROFILES[profile];
  if (!config) {
    return SCAN_PROFILES.full.modules;
  }

  // If tier is specified, filter modules
  if (tier) {
    return config.modules.filter(mod => {
      const reg = MODULE_REGISTRY[mod];
      return reg && (reg.tier === tier || reg.tier === 'both');
    });
  }

  return config.modules;
}

/**
 * Check if a module has required API keys configured
 */
export function isModuleAvailable(moduleName: string): { available: boolean; missingKeys?: string[] } {
  const reg = MODULE_REGISTRY[moduleName];
  if (!reg) {
    return { available: false, missingKeys: ['MODULE_NOT_FOUND'] };
  }

  if (!reg.requiresApiKey || reg.requiresApiKey.length === 0) {
    return { available: true };
  }

  const missingKeys = reg.requiresApiKey.filter(key => !process.env[key]);
  return {
    available: missingKeys.length === 0,
    missingKeys: missingKeys.length > 0 ? missingKeys : undefined,
  };
}

/**
 * Get estimated duration for a profile in milliseconds
 */
export function getProfileDuration(profile: ScanProfile): number {
  return SCAN_PROFILES[profile]?.estimatedDurationMs ?? SCAN_PROFILES.full.estimatedDurationMs;
}
