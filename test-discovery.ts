/**
 * Standalone test of discovery logic (no database required)
 */

const TEST_DOMAIN = 'github.com';

// ========== Certificate Transparency Test ==========

interface CTEntry {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
}

async function testCertTransparency() {
  console.log('\n=== Certificate Transparency Discovery ===\n');
  console.log(`Querying crt.sh for: ${TEST_DOMAIN}`);

  const url = `https://crt.sh/?q=%.${encodeURIComponent(TEST_DOMAIN)}&output=json`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Accept': 'application/json',
      },
    });

    clearTimeout(timeout);

    if (!response.ok) {
      console.error(`crt.sh returned status: ${response.status}`);
      return;
    }

    const data = await response.json() as CTEntry[];
    console.log(`Found ${data.length} certificate entries`);

    // Extract unique subdomains
    const subdomains = new Set<string>();
    for (const entry of data) {
      const names = entry.name_value.split('\n').map(n => n.trim().toLowerCase());
      for (const name of names) {
        if (name.endsWith(`.${TEST_DOMAIN}`) || name === TEST_DOMAIN) {
          subdomains.add(name);
        }
      }
    }

    console.log(`Unique subdomains: ${subdomains.size}`);
    console.log('\nSample subdomains (first 20):');
    Array.from(subdomains).slice(0, 20).forEach(s => console.log(`  - ${s}`));

  } catch (error) {
    console.error('CT Discovery failed:', error);
  }
}

// ========== Cloud Bucket Enumeration Test ==========

const BUCKET_SUFFIXES = [
  '', '-backup', '-dev', '-prod', '-staging',
  '-assets', '-static', '-uploads', '-data',
];

function generateBucketNames(domain: string): string[] {
  const names = new Set<string>();
  const domainBase = domain.replace(/\.(com|org|net|io|co)$/i, '').replace(/\./g, '-');

  for (const suffix of BUCKET_SUFFIXES) {
    names.add(`${domainBase}${suffix}`);
  }

  return Array.from(names).filter(name =>
    name.length >= 3 && name.length <= 63 &&
    /^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(name)
  );
}

async function checkS3Bucket(bucketName: string): Promise<{ exists: boolean; listable: boolean }> {
  const url = `https://${bucketName}.s3.amazonaws.com/`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)' },
    });

    clearTimeout(timeout);

    if (response.status === 200) {
      return { exists: true, listable: true };
    } else if (response.status === 403) {
      return { exists: true, listable: false };
    }
    return { exists: false, listable: false };
  } catch {
    return { exists: false, listable: false };
  }
}

async function testCloudBucketEnum() {
  console.log('\n=== Cloud Bucket Enumeration ===\n');

  const bucketNames = generateBucketNames(TEST_DOMAIN);
  console.log(`Generated ${bucketNames.length} bucket name candidates:`);
  bucketNames.forEach(b => console.log(`  - ${b}`));

  console.log('\nChecking S3 buckets...');

  for (const name of bucketNames) {
    const result = await checkS3Bucket(name);
    if (result.exists) {
      const status = result.listable ? 'LISTABLE (CRITICAL!)' : 'EXISTS (not listable)';
      console.log(`  [FOUND] ${name}: ${status}`);
    } else {
      console.log(`  [  -  ] ${name}: not found`);
    }
  }
}

// ========== Main ==========

async function main() {
  console.log('============================================');
  console.log('  Scanner Module Discovery Test');
  console.log(`  Target: ${TEST_DOMAIN}`);
  console.log('============================================');

  await testCertTransparency();
  await testCloudBucketEnum();

  console.log('\n=== Tests Complete ===\n');
}

main().catch(console.error);
