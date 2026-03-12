# Module Requirements

This document outlines the requirements for each scan module, particularly those that need client infrastructure, special tools, or API keys.

## Fully External Modules (No Setup Required)

These modules work out-of-the-box with just a target domain:

| Module | Description |
|--------|-------------|
| `cert_transparency` | Discovers subdomains via certificate transparency logs (crt.sh) |
| `cloud_bucket_enum` | Enumerates public S3/Azure/GCP buckets by name guessing |
| `config_exposure` | Checks for exposed configuration files |
| `document_exposure` | Finds exposed documents via search engines |
| `dns_zone_transfer` | Tests for DNS zone transfer vulnerabilities |
| `endpoint_discovery` | Discovers web endpoints via crawling |
| `spf_dmarc` | Checks email security configuration |
| `subdomain_takeover` | Detects dangling DNS records |
| `tech_stack_scan` | Identifies technologies in use |
| `tls_scan` | Analyzes TLS/SSL configuration |
| `whois_wrapper` | WHOIS intelligence gathering |
| `web_archive_scanner` | Finds historical content via Wayback Machine |
| `admin_panel_detector` | Discovers admin interfaces |
| `denial_wallet_scan` | Detects denial-of-wallet vulnerabilities |
| `nextjs_rsc_scan` | Next.js specific security checks |
| `wp_plugin_quickscan` | WordPress plugin enumeration |
| `wp_vuln_resolver` | WordPress vulnerability checking |
| `dns_twist` | Typosquatting/lookalike domain detection |
| `rate_limit_scan` | Rate limiting analysis |

## Modules Requiring API Keys

These modules require API keys to function. Set them in your `.env` file:

| Module | Required Keys | Notes |
|--------|--------------|-------|
| `shodan` | `SHODAN_API_KEY` | Shodan.io API key |
| `breach_directory_probe` | `LEAKCHECK_API_KEY` | LeakCheck.io API key |
| `github_secret_search` | `GITHUB_TOKEN` | GitHub personal access token |
| `abuse_intel_scan` | `ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `censys_platform_scan` | `CENSYS_PAT`, `CENSYS_ORG_ID` | Censys Platform API credentials |
| `lightweight_cve_check` | `NVD_API_KEY` (optional) | NVD API key for faster lookups |
| `ai_path_finder` | `OPENAI_API_KEY` (optional) | OpenAI API key for AI-assisted discovery |

## Modules Requiring External Tools

These modules require external security tools to be installed on the scanner host:

| Module | Required Tool | Installation |
|--------|--------------|--------------|
| `nuclei` | Nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `db_port_scan` | nmap | `apt install nmap` or `brew install nmap` |
| `port_scan` | nmap | `apt install nmap` or `brew install nmap` |
| `trufflehog` | TruffleHog | `brew install trufflehog` or `go install github.com/trufflesecurity/trufflehog/v3@latest` |

## Modules Requiring Client Infrastructure

**These modules require access to client-owned infrastructure and should NOT be enabled for external-only scanning:**

| Module | Requirement | Use Case |
|--------|------------|----------|
| `openvas_scan` | OpenVAS/GVM server | Internal vulnerability scanning with client's OpenVAS instance |
| `zap_scan` | OWASP ZAP proxy | Web application security testing with ZAP |
| `spider_foot` | SpiderFoot server | Comprehensive OSINT platform |

### OpenVAS Configuration

If using OpenVAS (internal scans only):
```env
OPENVAS_HOST=https://openvas.internal:9392
OPENVAS_USER=admin
OPENVAS_PASSWORD=your_password
```

### OWASP ZAP Configuration

If using ZAP (internal scans only):
```env
ZAP_API_URL=http://localhost:8080
ZAP_API_KEY=your_api_key
```

## Module Categories

### Tier 1 (Passive Reconnaissance)
Fast, non-intrusive modules that don't actively probe the target infrastructure. Safe to run against any target.

### Tier 2 (Active Scanning)
More intrusive modules that actively probe the target. May trigger IDS/IPS alerts. Should be used with authorization.

## Disabling Modules

Modules can be disabled via environment variables:
```env
# Disable specific modules
ENABLE_OPENVAS=0
ENABLE_ZAP=0
ENABLE_SPIDERFOOT=0
```

Or by specifying which modules to run in scan requests:
```json
{
  "domain": "example.com",
  "config": {
    "skip_modules": ["openvas_scan", "zap_scan", "spider_foot"]
  }
}
```
