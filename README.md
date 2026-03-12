# Security Scanner

External attack surface scanner with 50+ modules for vulnerability detection, asset discovery, credential exposure analysis, and security reconnaissance.

## Overview

This scanner performs **external-only** security analysis - discovering what an outsider can see about your organization without any internal access. It combines OSINT reconnaissance, vulnerability scanning, credential breach detection, and web security analysis into a unified platform with REST API access.

**Key Capabilities:**
- Asset discovery (Certificate Transparency, cloud bucket enumeration, DNS)
- Vulnerability scanning (Nuclei, CVE verification, TLS analysis)
- Credential and breach detection (GitHub secrets, infostealers)
- Network reconnaissance (Shodan, Censys, DNS analysis)
- Web security analysis (admin panels, config exposure, API endpoints)
- Email security validation (SPF, DKIM, DMARC)

## Quick Start

```bash
# Install dependencies
npm install

# Configure environment
cp config/env.example .env
# Edit .env with your API keys

# Start the server
npm run dev
```

The server starts on `http://localhost:3000`. Trigger a scan:

```bash
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "profile": "quick"}'
```

## Prerequisites

- Node.js 20+
- PostgreSQL 12+ (optional - can run without for testing)
- Redis 5+ (optional - falls back to in-memory queue)

## API Keys

### Required for Full Functionality

| Service | Environment Variable | Purpose |
|---------|---------------------|---------|
| PostgreSQL | `DATABASE_URL` | Findings database |
| Redis | `REDIS_URL` | Job queue |

### Recommended

| Service | Environment Variable | Purpose |
|---------|---------------------|---------|
| Shodan | `SHODAN_API_KEY` | Internet-wide service enumeration |
| LeakCheck | `LEAKCHECK_API_KEY` | Credential breach detection |
| GitHub | `GITHUB_TOKEN` | Repository scanning, secret detection |
| NVD | `NVD_API_KEY` | CVE database lookups (faster with key) |

### Optional

| Service | Environment Variable | Purpose |
|---------|---------------------|---------|
| Censys | `CENSYS_PAT`, `CENSYS_ORG_ID` | Asset discovery |
| WHOISXML | `WHOISXML_API_KEY` | Domain intelligence |
| Whoxy | `WHOXY_API_KEY` | WHOIS lookups (cheaper alternative) |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP reputation |
| HaveIBeenPwned | `HIBP_API_KEY` | Email breach checks |
| Serper | `SERPER_API_KEY` | Search-based reconnaissance |
| OpenAI | `OPENAI_API_KEY` | AI-powered path discovery |
| OpenVAS | `OPENVAS_HOST`, `OPENVAS_USER`, `OPENVAS_PASSWORD` | Vulnerability scanning (requires client infrastructure) |

## Scan Profiles

| Profile | Duration | Description |
|---------|----------|-------------|
| `full` | 10-15 min | All modules - comprehensive analysis |
| `quick` | 3-5 min | Fast OSINT (CT logs, Shodan, tech stack) |
| `wordpress` | 5-7 min | WordPress vulnerabilities, themes, plugins |
| `infostealer` | 3-5 min | Credential breach and infostealer detection |
| `email` | 3 min | Email security only (SPF/DKIM/DMARC) |
| `github` | 5 min | GitHub repositories and exposed secrets |

## Module Categories

### Discovery & Reconnaissance (No Setup Required)
- **certTransparency** - Subdomain discovery via Certificate Transparency logs
- **cloudBucketEnum** - S3/Azure/GCP bucket enumeration by name guessing
- **dnsZoneTransfer** - DNS zone transfer testing
- **subdomainTakeover** - Dangling DNS record detection
- **dnsTwist** - Domain typosquatting detection
- **whoisWrapper** - WHOIS intelligence
- **techStackScan** - Technology stack detection
- **webArchiveScanner** - Historical exposure via Wayback Machine

### Credential & Breach Detection
- **githubSecretSearch** - Find exposed secrets in GitHub repositories
- **clientSecretScanner** - Detect client-side secret exposure
- **trufflehog** - Git repository secret scanning

### Vulnerability Scanning
- **nuclei** - Template-based vulnerability scanning
- **cveVerifier** - CVE validation and verification
- **wpVulnResolver** - WordPress vulnerability resolution
- **wpPluginQuickScan** - WordPress plugin vulnerability scanning
- **tlsScan** - TLS/SSL configuration analysis
- **lightweightCveCheck** - Quick CVE lookups

### Network & Infrastructure
- **shodan** - Internet-wide service enumeration
- **censysPlatformScan** - Censys asset discovery
- **abuseIntelScan** - IP abuse intelligence
- **dbPortScan** - Database port scanning and exposure detection
- **portScan** - General port scanning

### Web Security
- **endpointDiscovery** - API endpoint enumeration
- **adminPanelDetector** - Admin panel discovery
- **nextjsRscScan** - Next.js RSC vulnerability scanning
- **backendExposureScanner** - Backend service exposure
- **configExposureScanner** - Configuration file exposure
- **documentExposure** - Sensitive document detection
- **denialWalletScan** - Denial of wallet attack vectors
- **rateLimitScan** - Rate limiting analysis
- **aiPathFinder** - AI-powered endpoint discovery

### Email Security
- **spfDmarc** - SPF, DKIM, DMARC validation

See [docs/MODULE_REQUIREMENTS.md](docs/MODULE_REQUIREMENTS.md) for detailed module requirements and which need API keys or external tools.

## REST API

### Start a Scan
```bash
POST /scan
Content-Type: application/json

{
  "domain": "example.com",
  "profile": "full",
  "priority": "high"
}
```

### Check Scan Status
```bash
GET /scan/:scanId/status
```

### Get Scan Results
```bash
GET /scans/:scanId
```

### Get Findings
```bash
GET /scans/:scanId/findings
```

### Health Check
```bash
GET /health
```

## Build & Run

### Development
```bash
npm run dev          # Start with auto-reload
npm run build        # Compile TypeScript
npm run lint         # Run linter
```

### Production
```bash
npm run build        # Compile TypeScript to dist/
npm start            # Run compiled server
```

### Testing Modules Standalone

You can test discovery modules without a database:

```bash
npx tsx test-discovery.ts
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     REST API (Express)                       │
│                    localhost:3000                            │
├─────────────────────────────────────────────────────────────┤
│                     Job Queue (Bull/Redis)                   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ CT Logs │ │ Shodan  │ │ Nuclei  │ │ GitHub  │  ...50+   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
├─────────────────────────────────────────────────────────────┤
│                   PostgreSQL (Findings DB)                   │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

Create a `.env` file from the example:

```bash
cp config/env.example .env
```

Key configuration options:

```env
# Database (optional for testing)
DATABASE_URL=postgresql://user:pass@localhost:5432/scanner

# Redis (optional - falls back to in-memory)
REDIS_URL=redis://localhost:6379

# API Keys
SHODAN_API_KEY=your_key_here
GITHUB_TOKEN=your_token_here

# Server
PORT=3000
NODE_ENV=production
```

## License

BUSL-1.1 (Business Source License 1.1)
