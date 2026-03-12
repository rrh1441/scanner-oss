/**
 * Quick test of new modules
 */

import { runCertTransparency } from './src/modules/certTransparency.js';
import { runCloudBucketEnum } from './src/modules/cloudBucketEnum.js';

const TEST_DOMAIN = 'example.com';
const TEST_SCAN_ID = 'test-scan-001';

async function testCertTransparency() {
  console.log('\n=== Testing Certificate Transparency Discovery ===\n');
  try {
    const findings = await runCertTransparency({
      domain: TEST_DOMAIN,
      scanId: TEST_SCAN_ID,
    });
    console.log(`CT Discovery complete. Findings: ${findings}`);
  } catch (error) {
    console.error('CT Discovery failed:', error);
  }
}

async function testCloudBucketEnum() {
  console.log('\n=== Testing Cloud Bucket Enumeration ===\n');
  try {
    const findings = await runCloudBucketEnum({
      domain: TEST_DOMAIN,
      scanId: TEST_SCAN_ID,
      companyName: 'Example Corp',
    });
    console.log(`Cloud Bucket Enum complete. Findings: ${findings}`);
  } catch (error) {
    console.error('Cloud Bucket Enum failed:', error);
  }
}

async function main() {
  console.log(`Testing against: ${TEST_DOMAIN}\n`);

  await testCertTransparency();
  await testCloudBucketEnum();

  console.log('\n=== Tests Complete ===');
}

main().catch(console.error);
