/**
 * Cloud Bucket Enumeration Module
 *
 * External reconnaissance for misconfigured cloud storage buckets.
 * Guesses bucket names based on company/domain patterns and checks
 * for public accessibility on S3, Azure Blob Storage, and GCP.
 *
 * This is pure external scanning - no credentials required.
 */

import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('cloudBucketEnum');

interface CloudBucketJob {
  domain: string;
  scanId: string;
  companyName?: string;
}

interface BucketResult {
  provider: 'aws' | 'azure' | 'gcp';
  bucketName: string;
  url: string;
  accessible: boolean;
  listable: boolean;
  error?: string;
}

interface CloudBucketScanResult {
  success: boolean;
  bucketsChecked: number;
  bucketsFound: number;
  findings: number;
  results: BucketResult[];
}

// Common bucket name suffixes to try
const BUCKET_SUFFIXES = [
  '', '-backup', '-backups', '-bak',
  '-dev', '-development', '-staging', '-stage', '-stg',
  '-prod', '-production', '-prd',
  '-test', '-testing', '-qa',
  '-assets', '-static', '-media', '-images', '-img',
  '-uploads', '-upload', '-files', '-data',
  '-public', '-pub', '-cdn',
  '-logs', '-log', '-logging',
  '-db', '-database', '-sql',
  '-archive', '-archives', '-old',
  '-www', '-web', '-website',
  '-api', '-app', '-application',
  '-docs', '-documents', '-doc',
  '-config', '-configs', '-configuration',
  '-internal', '-private', '-secret', '-secrets',
  '-temp', '-tmp',
  '-storage', '-store',
  '-content', '-cms',
  '-reports', '-report',
  '-export', '-exports', '-import', '-imports',
];

// Additional prefixes to combine with company name
const BUCKET_PREFIXES = [
  '', 'backup-', 'dev-', 'prod-', 'staging-',
  'assets-', 'static-', 'media-', 'cdn-',
];

/**
 * Generate bucket name candidates from domain and company name
 */
function generateBucketNames(domain: string, companyName?: string): string[] {
  const names = new Set<string>();

  // Extract base name from domain (e.g., "acme" from "acme.com")
  const domainBase = domain.replace(/\.(com|org|net|io|co|ai|app|dev)$/i, '').replace(/\./g, '-');
  const domainFull = domain.replace(/\./g, '-');

  // Normalize company name
  const company = companyName
    ? companyName.toLowerCase().replace(/[^a-z0-9]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '')
    : null;

  const bases = [domainBase, domainFull];
  if (company && company !== domainBase) {
    bases.push(company);
  }

  // Generate combinations
  for (const base of bases) {
    if (!base || base.length < 2) continue;

    for (const suffix of BUCKET_SUFFIXES) {
      names.add(`${base}${suffix}`);
    }

    for (const prefix of BUCKET_PREFIXES) {
      if (prefix) {
        names.add(`${prefix}${base}`);
      }
    }
  }

  // Filter valid bucket names (3-63 chars, lowercase, no consecutive hyphens)
  return Array.from(names).filter(name =>
    name.length >= 3 &&
    name.length <= 63 &&
    /^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(name) &&
    !name.includes('--')
  );
}

/**
 * Check if an S3 bucket exists and is accessible
 */
async function checkS3Bucket(bucketName: string): Promise<BucketResult> {
  const url = `https://${bucketName}.s3.amazonaws.com/`;
  const result: BucketResult = {
    provider: 'aws',
    bucketName,
    url,
    accessible: false,
    listable: false,
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
    });

    clearTimeout(timeout);

    // 200 = bucket exists and is listable (bad!)
    // 403 = bucket exists but not listable (still interesting)
    // 404 = bucket doesn't exist
    if (response.status === 200) {
      result.accessible = true;
      result.listable = true;
    } else if (response.status === 403) {
      result.accessible = true;
      result.listable = false;
    }
  } catch (error) {
    if ((error as Error).name !== 'AbortError') {
      result.error = (error as Error).message;
    }
  }

  return result;
}

/**
 * Check if an Azure Blob container exists and is accessible
 */
async function checkAzureBlob(bucketName: string): Promise<BucketResult> {
  // Azure blob format: https://<account>.blob.core.windows.net/<container>
  // We'll check if the storage account exists with $root or common container names
  const url = `https://${bucketName}.blob.core.windows.net/?comp=list`;
  const result: BucketResult = {
    provider: 'azure',
    bucketName,
    url: `https://${bucketName}.blob.core.windows.net/`,
    accessible: false,
    listable: false,
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
    });

    clearTimeout(timeout);

    // 200 = storage account exists and containers are listable
    // 403/409 = storage account exists but not listable
    // DNS error or 400 = doesn't exist
    if (response.status === 200) {
      result.accessible = true;
      result.listable = true;
    } else if (response.status === 403 || response.status === 409) {
      result.accessible = true;
      result.listable = false;
    }
  } catch (error) {
    if ((error as Error).name !== 'AbortError') {
      result.error = (error as Error).message;
    }
  }

  return result;
}

/**
 * Check if a GCP bucket exists and is accessible
 */
async function checkGCPBucket(bucketName: string): Promise<BucketResult> {
  const url = `https://storage.googleapis.com/${bucketName}/`;
  const result: BucketResult = {
    provider: 'gcp',
    bucketName,
    url,
    accessible: false,
    listable: false,
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
    });

    clearTimeout(timeout);

    // Similar logic to S3
    if (response.status === 200) {
      result.accessible = true;
      result.listable = true;
    } else if (response.status === 403) {
      result.accessible = true;
      result.listable = false;
    }
  } catch (error) {
    if ((error as Error).name !== 'AbortError') {
      result.error = (error as Error).message;
    }
  }

  return result;
}

/**
 * Rate-limited batch checking
 */
async function checkBucketsWithRateLimit(
  names: string[],
  checker: (name: string) => Promise<BucketResult>,
  concurrency: number = 5,
  delayMs: number = 100
): Promise<BucketResult[]> {
  const results: BucketResult[] = [];

  for (let i = 0; i < names.length; i += concurrency) {
    const batch = names.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(checker));
    results.push(...batchResults);

    // Rate limiting delay between batches
    if (i + concurrency < names.length) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }

  return results;
}

/**
 * Main scanner function
 */
export async function runCloudBucketEnum(job: CloudBucketJob): Promise<number> {
  const { domain, scanId, companyName } = job;

  log.info({ domain, scanId, companyName }, 'Starting cloud bucket enumeration');

  const bucketNames = generateBucketNames(domain, companyName);
  log.info({ count: bucketNames.length }, 'Generated bucket name candidates');

  const allResults: BucketResult[] = [];
  let findingsCount = 0;

  // Check S3 buckets
  log.info('Checking AWS S3 buckets...');
  const s3Results = await checkBucketsWithRateLimit(bucketNames, checkS3Bucket);
  allResults.push(...s3Results);

  // Check Azure Blob Storage
  log.info('Checking Azure Blob Storage...');
  const azureResults = await checkBucketsWithRateLimit(bucketNames, checkAzureBlob);
  allResults.push(...azureResults);

  // Check GCP buckets
  log.info('Checking GCP Cloud Storage...');
  const gcpResults = await checkBucketsWithRateLimit(bucketNames, checkGCPBucket);
  allResults.push(...gcpResults);

  // Process findings
  const accessibleBuckets = allResults.filter(r => r.accessible);

  for (const bucket of accessibleBuckets) {
    const severity = bucket.listable ? 'CRITICAL' : 'MEDIUM';
    const providerName = {
      aws: 'AWS S3',
      azure: 'Azure Blob Storage',
      gcp: 'Google Cloud Storage',
    }[bucket.provider];

    const artifactId = await insertArtifact({
      type: 'cloud_bucket',
      val_text: `${providerName}: ${bucket.bucketName}`,
      severity,
      meta: {
        scan_id: scanId,
        scan_module: 'cloud_bucket_enum',
        provider: bucket.provider,
        bucket_name: bucket.bucketName,
        url: bucket.url,
        listable: bucket.listable,
      },
    });

    const description = bucket.listable
      ? `Publicly listable ${providerName} bucket discovered: ${bucket.bucketName}. Contents can be enumerated without authentication.`
      : `${providerName} bucket exists and may be accessible: ${bucket.bucketName}. While not publicly listable, the bucket name is discoverable.`;

    const recommendation = bucket.listable
      ? `Immediately restrict public access to this bucket. Review bucket policy and ACLs. Audit contents for sensitive data exposure.`
      : `Review bucket permissions. Consider if this bucket name reveals sensitive information about your infrastructure.`;

    await insertFinding({
      artifact_id: artifactId,
      finding_type: bucket.listable ? 'PUBLIC_CLOUD_BUCKET' : 'DISCOVERABLE_CLOUD_BUCKET',
      scan_id: scanId,
      severity,
      type: bucket.listable ? 'PUBLIC_CLOUD_BUCKET' : 'DISCOVERABLE_CLOUD_BUCKET',
      description,
      recommendation,
      data: {
        provider: bucket.provider,
        provider_name: providerName,
        bucket_name: bucket.bucketName,
        url: bucket.url,
        listable: bucket.listable,
      },
    });

    findingsCount++;

    log.warn({
      provider: bucket.provider,
      bucket: bucket.bucketName,
      listable: bucket.listable,
    }, 'Accessible cloud bucket found');
  }

  log.info({
    domain,
    scanId,
    bucketsChecked: allResults.length,
    bucketsFound: accessibleBuckets.length,
    findings: findingsCount,
  }, 'Cloud bucket enumeration complete');

  return findingsCount;
}
