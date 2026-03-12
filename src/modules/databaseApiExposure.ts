/**
 * Database & API Exposure Scanner
 *
 * Unified module that detects Tea App-style client-side database exposure
 * AND infrastructure-level database exposure with denial-of-wallet risk analysis.
 *
 * Detection Coverage:
 * 1. Client-Side Database Exposure (Firebase, Supabase, Realm)
 *    - Extracts backend IDs from JavaScript bundles
 *    - Tests for unauthenticated access to databases/storage
 *    - Checks Row-Level Security (RLS) enforcement
 *
 * 2. Infrastructure Database Exposure (via Shodan)
 *    - Consumes Shodan service artifacts
 *    - Flags exposed database ports (MySQL, Postgres, Mongo, Redis, etc.)
 *
 * 3. Cost Amplification Risk (Denial-of-Wallet)
 *    - Estimates daily cost exposure from abuse
 *    - Calculates attack complexity
 *    - Provides concrete financial impact
 */

import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';
import { executeModule, apiCall } from '../util/errorHandler.js';

const log = createModuleLogger('databaseApiExposure');
import { httpClient } from '../net/httpClient.js';

// Configuration
const PROBE_TIMEOUT_MS = parseInt(process.env.DATABASE_EXPOSURE_TIMEOUT || '8000', 10);
const MAX_PROBES_PER_BACKEND = 3; // Limit probes per backend to avoid overwhelming targets

// Database port mapping
const DATABASE_PORTS: Record<number, { name: string; severity: 'CRITICAL' | 'HIGH' }> = {
  3306: { name: 'MySQL', severity: 'CRITICAL' },
  5432: { name: 'PostgreSQL', severity: 'CRITICAL' },
  27017: { name: 'MongoDB', severity: 'CRITICAL' },
  6379: { name: 'Redis', severity: 'CRITICAL' },
  9200: { name: 'Elasticsearch', severity: 'HIGH' },
  5984: { name: 'CouchDB', severity: 'HIGH' },
  7000: { name: 'Cassandra', severity: 'HIGH' },
  8086: { name: 'InfluxDB', severity: 'HIGH' },
  9042: { name: 'Cassandra', severity: 'HIGH' },
  11211: { name: 'Memcached', severity: 'HIGH' },
  50000: { name: 'DB2', severity: 'HIGH' },
};

// Cost estimation per operation (realistic malicious attack scenarios)
// Based on: Distributed botnets sustain 10K-50K RPS, attacks run for hours/days
const COST_PER_OPERATION = {
  firebase_realtime: 0.000001,    // $1/1M ops | 10K RPS = $864/day, 50K RPS = $4,320/day
  firebase_firestore: 0.000360,   // $0.36/1M reads | 10K RPS = $311K/day, 50K RPS = $1.55M/day
  supabase_db: 0.000002,          // ~$2/1M ops | 10K RPS = $1,728/day, 50K RPS = $8,640/day
  supabase_storage: 0.000005,     // ~$5/1M ops | 10K RPS = $4,320/day, 50K RPS = $21,600/day
  realm: 0.000010,                // $10/1M sync | 10K RPS = $8,640/day, 50K RPS = $43,200/day
  s3: 0.000005,                   // $0.005/1K req | 10K RPS = $4,320/day, 50K RPS = $21,600/day
  gcs: 0.000005,                  // Similar to S3
  azure_blob: 0.000004,           // $0.004/1K ops | 10K RPS = $3,456/day, 50K RPS = $17,280/day
  // Modern serverless databases (2024+)
  planetscale: 0.000001,          // ~$1/1M rows read | 10K RPS = $864/day (free tier: 1B rows/mo)
  neon: 0.000002,                 // ~$2/1M ops estimate | 10K RPS = $1,728/day (generous free tier)
  turso: 0.000001,                // ~$1/1M rows | 10K RPS = $864/day (500 DB free)
  xata: 0.000003,                 // ~$3/1M ops estimate | 10K RPS = $2,592/day (Postgres + search)
  convex: 0.000005,               // ~$5/1M ops estimate | 10K RPS = $4,320/day (real-time features)
  railway: 0.000002,              // ~$2/1M ops estimate | 10K RPS = $1,728/day (usage-based)
  vercel_postgres: 0.000002,      // Powered by Neon, similar costs | 10K RPS = $1,728/day
  vercel_kv: 0.000005,            // Powered by Upstash, Redis pricing | 10K RPS = $4,320/day
  upstash: 0.000005,              // Redis serverless with REST API | 10K RPS = $4,320/day
  mysql_infra: 0.0000001,         // Infrastructure cost negligible, data breach is real risk
  postgres_infra: 0.0000001,
  mongodb_infra: 0.0000001,
  redis_infra: 0.0000001,
};

interface BackendIdentifier {
  provider: 'firebase' | 's3' | 'gcs' | 'azure' | 'supabase' | 'r2' | 'spaces' | 'b2' | 'realm'
    | 'planetscale' | 'neon' | 'turso' | 'xata' | 'convex' | 'railway'
    | 'vercel-postgres' | 'vercel-kv' | 'upstash';
  id: string;
  raw: string;
  src: { file: string; line: number };
}

interface ShodanService {
  ip: string;
  port: number;
  product?: string;
  version?: string;
  scan_id: string;
}

interface ExposureResult {
  exposed: boolean;
  access_level: 'full' | 'partial' | 'none';
  test_url: string;
  response_code?: number;
  evidence?: string;
  rls_enabled?: boolean;
}

interface CostEstimate {
  conservative_daily_cost: number;      // 100 RPS scenario
  moderate_daily_cost: number;          // 1,000 RPS scenario
  serious_daily_cost: number;           // 10,000 RPS scenario
  attack_complexity: 'trivial' | 'low' | 'medium' | 'high';
  cost_basis: string;
}

// Enhanced logging
const logger = (...args: unknown[]) => log.info(args.map(String).join(' '));

/**
 * Build Firebase test URLs
 */
function buildFirebaseUrls(projectId: string): string[] {
  return [
    `https://${projectId}.firebaseio.com/.json?print=silent`,
    `https://${projectId}.firebasedatabase.app/.json?print=silent`,
    `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`,
  ];
}

/**
 * Build Supabase test URLs
 */
function buildSupabaseUrls(projectId: string): string[] {
  return [
    `https://${projectId}.supabase.co/rest/v1/`,
    `https://${projectId}.supabase.co/storage/v1/bucket/`,
  ];
}

/**
 * Build storage/database URLs for S3, GCS, Azure, and modern serverless DBs
 */
function buildStorageUrls(backend: BackendIdentifier): string[] {
  switch (backend.provider) {
    case 's3':
      return [`https://${backend.id}.s3.amazonaws.com/?list-type=2`];
    case 'gcs':
      return [
        `https://${backend.id}.storage.googleapis.com/?delimiter=/`,
        `https://storage.googleapis.com/${backend.id}/?delimiter=/`,
      ];
    case 'azure':
      return [
        `https://${backend.id}.blob.core.windows.net/?comp=list`,
        `https://${backend.id}.file.core.windows.net/?comp=list`,
      ];
    case 'realm':
      return [`https://${backend.id}.realm.mongodb.com`];
    case 'xata':
      // Xata REST API endpoints
      return [`https://${backend.id}.xata.sh/db`];
    case 'convex':
      // Convex deployment endpoints
      return [`https://${backend.id}.convex.cloud`];
    case 'turso':
      // Turso LibSQL endpoints
      return [`https://${backend.id}.turso.io`];
    case 'upstash':
      // Upstash Redis REST API
      return [`https://${backend.id}.upstash.io`];
    // Note: PlanetScale, Neon, Railway, Vercel Postgres use authenticated MySQL/Postgres protocols
    // Vercel KV proxies Upstash but requires auth tokens
    // They don't have HTTP REST APIs we can probe without credentials
    // Detection alone is valuable (shows DB credentials in client code)
    default:
      return [];
  }
}

/**
 * Test if a backend is exposed (unauthenticated access)
 */
async function testBackendExposure(backend: BackendIdentifier): Promise<ExposureResult> {
  const operation = async (): Promise<ExposureResult> => {
    let urls: string[] = [];

    // Build appropriate test URLs based on provider
    switch (backend.provider) {
      case 'firebase':
        urls = buildFirebaseUrls(backend.id);
        break;
      case 'supabase':
        urls = buildSupabaseUrls(backend.id);
        break;
      default:
        urls = buildStorageUrls(backend);
    }

    // Test each URL (up to MAX_PROBES_PER_BACKEND)
    for (const url of urls.slice(0, MAX_PROBES_PER_BACKEND)) {
      try {
        const response = await httpClient.get(url, {
          timeout: PROBE_TIMEOUT_MS,
          validateStatus: () => true, // Accept all status codes
          maxRedirects: 2,
        });

        const status = response.status;
        const data = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

        // Check for successful unauthenticated access
        if (status === 200) {
          // Firebase: Check if we got actual data (not just null)
          if (backend.provider === 'firebase') {
            const isNull = data.trim() === 'null' || data.trim() === '{}';
            if (!isNull) {
              return {
                exposed: true,
                access_level: 'full',
                test_url: url,
                response_code: status,
                evidence: data.substring(0, 200),
                rls_enabled: false,
              };
            }
          }

          // Supabase: Check for table listings or data
          if (backend.provider === 'supabase') {
            const hasData = data.includes('table') || data.includes('bucket') || data.length > 100;
            if (hasData) {
              return {
                exposed: true,
                access_level: 'full',
                test_url: url,
                response_code: status,
                evidence: data.substring(0, 200),
                rls_enabled: false,
              };
            }
          }

          // Storage: Check for bucket listings
          if (['s3', 'gcs', 'azure'].includes(backend.provider)) {
            const hasBucketListing = data.includes('<Contents>') || data.includes('"items"') || data.includes('<Blob>');
            if (hasBucketListing) {
              return {
                exposed: true,
                access_level: 'full',
                test_url: url,
                response_code: status,
                evidence: data.substring(0, 200),
              };
            }
          }
        }

        // Check for partial access (403 with informative errors)
        if (status === 403) {
          const hasInfoLeak = data.includes('bucket') || data.includes('project') || data.includes('database');
          if (hasInfoLeak) {
            return {
              exposed: true,
              access_level: 'partial',
              test_url: url,
              response_code: status,
              evidence: data.substring(0, 200),
              rls_enabled: true, // 403 suggests some auth is in place
            };
          }
        }

      } catch (error) {
        // Network errors, timeouts are expected for protected backends
        continue;
      }
    }

    // No exposure detected
    return {
      exposed: false,
      access_level: 'none',
      test_url: urls[0] || 'unknown',
    };
  };

  const result = await apiCall(operation, {
    moduleName: 'databaseApiExposure',
    operation: 'testBackendExposure',
    target: `${backend.provider}:${backend.id}`,
  });

  if (!result.success) {
    return {
      exposed: false,
      access_level: 'none',
      test_url: 'error',
    };
  }

  return result.data;
}

/**
 * Calculate cost estimate for exposed backend with realistic attack scenarios
 */
function calculateCostEstimate(backend: BackendIdentifier, accessLevel: 'full' | 'partial'): CostEstimate {
  let costPerOp = 0.000001; // Default fallback
  let costBasis = 'requests';
  let attackComplexity: 'trivial' | 'low' | 'medium' | 'high' = 'trivial';

  // Determine cost basis and select appropriate rate
  switch (backend.provider) {
    case 'firebase':
      // Use Firestore rate (worst case - 360x more expensive than Realtime DB)
      costPerOp = COST_PER_OPERATION.firebase_firestore;
      costBasis = 'database operations';
      attackComplexity = accessLevel === 'full' ? 'trivial' : 'low';
      break;
    case 'supabase':
      costPerOp = COST_PER_OPERATION.supabase_db;
      costBasis = 'database queries';
      attackComplexity = accessLevel === 'full' ? 'trivial' : 'low';
      break;
    case 's3':
    case 'gcs':
    case 'azure':
      costPerOp = COST_PER_OPERATION.s3;
      costBasis = 'storage operations';
      attackComplexity = accessLevel === 'full' ? 'low' : 'medium';
      break;
    case 'realm':
      costPerOp = COST_PER_OPERATION.realm;
      costBasis = 'sync operations';
      attackComplexity = 'low';
      break;
    case 'planetscale':
      costPerOp = COST_PER_OPERATION.planetscale;
      costBasis = 'database rows read';
      attackComplexity = 'low'; // Requires MySQL connection, not HTTP
      break;
    case 'neon':
      costPerOp = COST_PER_OPERATION.neon;
      costBasis = 'database operations';
      attackComplexity = 'low'; // Requires Postgres connection
      break;
    case 'turso':
      costPerOp = COST_PER_OPERATION.turso;
      costBasis = 'database rows read';
      attackComplexity = accessLevel === 'full' ? 'low' : 'medium';
      break;
    case 'xata':
      costPerOp = COST_PER_OPERATION.xata;
      costBasis = 'database + search operations';
      attackComplexity = accessLevel === 'full' ? 'trivial' : 'low';
      break;
    case 'convex':
      costPerOp = COST_PER_OPERATION.convex;
      costBasis = 'real-time operations';
      attackComplexity = accessLevel === 'full' ? 'trivial' : 'low';
      break;
    case 'railway':
      costPerOp = COST_PER_OPERATION.railway;
      costBasis = 'database operations';
      attackComplexity = 'low'; // Requires authenticated connection
      break;
    case 'vercel-postgres':
      costPerOp = COST_PER_OPERATION.vercel_postgres;
      costBasis = 'database operations';
      attackComplexity = 'low'; // Neon-based, requires Postgres connection
      break;
    case 'vercel-kv':
      costPerOp = COST_PER_OPERATION.vercel_kv;
      costBasis = 'Redis operations';
      attackComplexity = 'low'; // Upstash-based, requires auth tokens
      break;
    case 'upstash':
      costPerOp = COST_PER_OPERATION.upstash;
      costBasis = 'Redis operations';
      attackComplexity = accessLevel === 'full' ? 'trivial' : 'low'; // Has REST API
      break;
  }

  // Calculate realistic daily loss ranges based on verified 2022-2025 incidents
  // Grounded in real-world Firebase/DynamoDB/serverless attack data:
  // - Firebase: $70K/day, $121K in 2 days (documented cases)
  // - Lambda: $25K/day from sustained invocation abuse
  // - Attacker capability: 5K-30K RPS using cheap VPS/IoT botnets

  let conservativeDailyCost = 0;
  let seriousDailyCost = 0;
  let catastrophicDailyCost = 0;

  // Tier-based realistic loss ranges (24 hours of malicious traffic)
  if (backend.provider === 'firebase' || backend.provider === 'realm') {
    // Tier 1: Request-priced platforms (highest risk)
    // Real incidents: $10K-$75K/day from auto-scaling abuse
    conservativeDailyCost = 10000;   // Lower bound: modest botnet
    seriousDailyCost = 40000;        // Mid-range: sustained attack
    catastrophicDailyCost = 75000;   // Upper bound: heavy abuse (verified $70K+ cases)
  } else if (backend.provider === 'supabase' || backend.provider === 'neon' ||
             backend.provider === 'planetscale' || backend.provider === 'xata') {
    // Tier 2: Compute/egress-based serverless DBs (bounded by compute limits)
    // Realistic: $500-$10K/day from query thrashing + egress
    conservativeDailyCost = 500;     // Query abuse only
    seriousDailyCost = 3000;         // Heavy compute usage
    catastrophicDailyCost = 10000;   // Large table egress + compute
  } else if (backend.provider === 's3' || backend.provider === 'gcs' ||
             backend.provider === 'azure') {
    // Storage platforms: egress + operation costs
    conservativeDailyCost = 1000;    // Moderate API abuse
    seriousDailyCost = 5000;         // Heavy egress
    catastrophicDailyCost = 15000;   // Massive egress + ops
  } else {
    // Tier 3: Other platforms (API chains, lower auto-scale)
    conservativeDailyCost = 1000;
    seriousDailyCost = 5000;
    catastrophicDailyCost = 30000;
  }

  return {
    conservative_daily_cost: conservativeDailyCost,
    moderate_daily_cost: seriousDailyCost,
    serious_daily_cost: catastrophicDailyCost,
    attack_complexity: attackComplexity,
    cost_basis: costBasis,
  };
}

/**
 * Get backend identifiers from artifacts
 */
async function getBackendIdentifiers(scanId: string): Promise<BackendIdentifier[]> {
  try {
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();

    try {
      const result = await store.query(
        'SELECT metadata FROM artifacts WHERE scan_id = $1 AND type = $2',
        [scanId, 'backend_identifiers']
      );

      const backends: BackendIdentifier[] = [];

      for (const row of result.rows) {
        if (row.metadata?.backend_ids) {
          backends.push(...row.metadata.backend_ids);
        } else if (row.metadata?.backendArr) {
          // Handle legacy format
          backends.push(...row.metadata.backendArr);
        }
      }

      logger(`Found ${backends.length} backend identifiers from endpoint discovery`);
      return backends;

    } finally {
      await store.close();
    }
  } catch (error) {
    logger(`Error querying backend identifiers: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Get Shodan service artifacts (database ports)
 */
async function getShodanDatabaseServices(scanId: string): Promise<ShodanService[]> {
  try {
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();

    try {
      const result = await store.query(
        'SELECT metadata FROM artifacts WHERE scan_id = $1 AND type = $2',
        [scanId, 'shodan_service']
      );

      const services: ShodanService[] = [];

      for (const row of result.rows) {
        const meta = row.metadata;
        if (meta?.port && DATABASE_PORTS[meta.port]) {
          services.push({
            ip: meta.ip || 'unknown',
            port: meta.port,
            product: meta.product,
            version: meta.version,
            scan_id: scanId,
          });
        }
      }

      logger(`Found ${services.length} exposed database services from Shodan`);
      return services;

    } finally {
      await store.close();
    }
  } catch (error) {
    logger(`Error querying Shodan services: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Main scan function
 */
export async function runDatabaseApiExposureScan(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;

  return executeModule('databaseApiExposure', async () => {
    const startTime = Date.now();
    logger(`Starting database & API exposure scan for domain="${domain}"`);

    let findingsCount = 0;

    // ========== Part 1: Client-Side Backend Exposure (Tea-Style) ==========
    const backends = await getBackendIdentifiers(scanId);

    for (const backend of backends) {
      logger(`Testing ${backend.provider} backend: ${backend.id}`);

      const exposureResult = await testBackendExposure(backend);

      if (exposureResult.exposed && exposureResult.access_level !== 'none') {
        const costEstimate = calculateCostEstimate(backend, exposureResult.access_level);

        // Determine severity
        const severity = exposureResult.access_level === 'full' ? 'CRITICAL' : 'HIGH';

        // Create artifact with full context
        const artifactId = await insertArtifact({
          type: 'exposed_client_database',
          val_text: `${backend.provider.toUpperCase()} ${exposureResult.access_level} exposure: ${backend.id}`,
          severity,
          meta: {
            scan_id: scanId,
            scan_module: 'databaseApiExposure',
            provider: backend.provider,
            backend_id: backend.id,
            access_level: exposureResult.access_level,
            test_url: exposureResult.test_url,
            response_code: exposureResult.response_code,
            rls_enabled: exposureResult.rls_enabled,
            evidence: exposureResult.evidence,
            cost_estimate: costEstimate,
            discovered_in: backend.src,
          },
        });

        // Create finding with Tea App-style context and realistic attack costs
        const rlsStatus = exposureResult.rls_enabled ? 'partial Row-Level Security' : 'NO security rules';
        const attackComplexity = costEstimate.attack_complexity === 'trivial'
          ? 'Trivial (3 clicks in browser DevTools)'
          : `${costEstimate.attack_complexity.charAt(0).toUpperCase() + costEstimate.attack_complexity.slice(1)} complexity`;

        // Format cost estimates for different attack scenarios
        const conservativeCost = costEstimate.conservative_daily_cost >= 1000
          ? `$${(costEstimate.conservative_daily_cost / 1000).toFixed(1)}K`
          : `$${costEstimate.conservative_daily_cost.toFixed(2)}`;
        const moderateCost = costEstimate.moderate_daily_cost >= 1000
          ? `$${(costEstimate.moderate_daily_cost / 1000).toFixed(1)}K`
          : `$${costEstimate.moderate_daily_cost.toFixed(2)}`;
        const seriousCost = costEstimate.serious_daily_cost >= 1000
          ? `$${(costEstimate.serious_daily_cost / 1000).toFixed(1)}K`
          : `$${costEstimate.serious_daily_cost.toFixed(2)}`;

        await insertFinding(
          artifactId,
          'EXPOSED_CLIENT_DATABASE',
          `${backend.provider.toUpperCase()} database '${backend.id}' is ${exposureResult.access_level === 'full' ? 'fully' : 'partially'} accessible from client-side code. ` +
          `Any user can ${exposureResult.access_level === 'full' ? 'read/write all records' : 'enumerate database structure'} by extracting credentials from your JavaScript bundle. ` +
          `Detected ${rlsStatus}.`,
          `IMMEDIATE: Review ${backend.provider.toUpperCase()} security rules and enable Row-Level Security (RLS). ` +
          `Set database rules to deny all unauthenticated access. For Firebase: Update Realtime Database rules or Firestore security rules. ` +
          `For Supabase: Enable RLS on all tables and create policies. ` +
          `\n\nDENIAL-OF-WALLET RISK (24-hour malicious abuse):` +
          `\n• Conservative scenario: ${conservativeCost}/day` +
          `\n• Serious attack: ${moderateCost}/day` +
          `\n• Catastrophic (heavy botnet): ${seriousCost}/day` +
          `\n\nAttack Complexity: ${attackComplexity}. ` +
          `Real incidents (2022-2025): Firebase attacks reached $70K in 1 day, $121K in 2 days. ` +
          `Attackers use 5K-30K RPS botnets. No credentials needed—just send requests, you pay the bill. ` +
          `Detection lag: Budget alerts arrive after damage is done (no real-time warning). ` +
          `\n\nFound in: ${backend.src.file}:${backend.src.line}`
        );

        findingsCount++;
      } else {
        logger(`${backend.provider} backend ${backend.id}: not exposed (protected)`);
      }
    }

    // ========== Part 2: Infrastructure Database Exposure (Shodan) ==========
    const shodanServices = await getShodanDatabaseServices(scanId);

    for (const service of shodanServices) {
      const dbInfo = DATABASE_PORTS[service.port];
      const productName = service.product || dbInfo.name;

      // Create artifact
      const artifactId = await insertArtifact({
        type: 'exposed_infrastructure_database',
        val_text: `${productName} exposed on ${service.ip}:${service.port}`,
        severity: dbInfo.severity,
        meta: {
          scan_id: scanId,
          scan_module: 'databaseApiExposure',
          ip: service.ip,
          port: service.port,
          product: productName,
          version: service.version,
          database_type: dbInfo.name,
        },
      });

      // Create finding
      await insertFinding(
        artifactId,
        'EXPOSED_DATABASE_PORT',
        `${productName}${service.version ? ' ' + service.version : ''} is exposed to the internet on ${service.ip}:${service.port}. ` +
        `This allows anyone to attempt connections and could lead to unauthorized data access, data theft, or denial-of-wallet attacks through query abuse.`,
        `IMMEDIATE: Close port ${service.port} to public internet access. Use firewall rules to restrict database access to trusted IP ranges only. ` +
        `Verify authentication is required and strong passwords are enforced. Consider using VPN or private networking for database access. ` +
        `Risk: Complete data breach + potential query cost amplification if cloud-hosted database.`
      );

      findingsCount++;
    }

    const duration = Date.now() - startTime;
    logger(`Database & API exposure scan completed: ${findingsCount} findings in ${duration}ms`);

    return findingsCount;

  }, { scanId, target: domain });
}

const sustainedRps = 100; // Used in finding message - define at module level for consistency
