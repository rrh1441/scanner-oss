/**
 * Custom Infostealer Data Adapter
 *
 * Allows integration of proprietary infostealer/breach data sources.
 * Provides a standardized interface for importing and processing
 * custom credential breach intelligence.
 *
 * This adapter is designed to accept data from your own infostealer
 * intelligence sources and normalize it for the scanner's finding system.
 */

import { z } from 'zod';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('infostealerAdapter');

// === JSON Schema Definitions ===

/**
 * Schema for a single credential record from infostealer data
 */
export const CredentialRecordSchema = z.object({
  /** Unique identifier for this record (optional, will be generated if not provided) */
  id: z.string().optional(),

  /** Email address (primary identifier) */
  email: z.string().email().optional(),

  /** Username (if different from email) */
  username: z.string().optional(),

  /** Domain the credential is associated with */
  domain: z.string().optional(),

  /** URL where the credential was captured (login page, etc.) */
  url: z.string().url().optional(),

  /** Source of the breach/infostealer data */
  source: z.object({
    /** Name of the source (e.g., "Stealer Logs", "Redline", "Raccoon") */
    name: z.string(),
    /** Type of source */
    type: z.enum(['infostealer', 'database_breach', 'paste', 'combo_list', 'other']).default('infostealer'),
    /** Date the breach occurred (ISO 8601) */
    breach_date: z.string().optional(),
    /** Date the data was collected/added to your system (ISO 8601) */
    collection_date: z.string().optional(),
    /** Confidence level in the data (0-1) */
    confidence: z.number().min(0).max(1).optional(),
  }),

  /** What data fields are present (used for severity calculation) */
  fields: z.object({
    /** Password is present */
    has_password: z.boolean().default(false),
    /** Session cookies are present */
    has_cookies: z.boolean().default(false),
    /** Browser autofill data is present */
    has_autofill: z.boolean().default(false),
    /** Browser history/bookmarks present */
    has_browser_data: z.boolean().default(false),
    /** Credit card data present */
    has_credit_card: z.boolean().default(false),
    /** Cryptocurrency wallet data present */
    has_crypto_wallet: z.boolean().default(false),
    /** 2FA/MFA tokens or seeds present */
    has_2fa_tokens: z.boolean().default(false),
    /** SSH/API keys present */
    has_keys: z.boolean().default(false),
  }).default({}),

  /** Additional metadata */
  metadata: z.record(z.unknown()).optional(),
});

/**
 * Schema for batch import of infostealer data
 */
export const InfostealerBatchImportSchema = z.object({
  /** Batch identifier */
  batch_id: z.string().optional(),

  /** Source system identifier */
  source_system: z.string().optional(),

  /** Import timestamp (ISO 8601) */
  import_timestamp: z.string().optional(),

  /** Target domain filter (only import records matching this domain) */
  target_domain: z.string().optional(),

  /** Credential records */
  records: z.array(CredentialRecordSchema),

  /** Batch-level metadata */
  metadata: z.record(z.unknown()).optional(),
});

// === Types ===

export type CredentialRecord = z.infer<typeof CredentialRecordSchema>;
export type InfostealerBatchImport = z.infer<typeof InfostealerBatchImportSchema>;

export interface ProcessedCredential {
  record: CredentialRecord;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  exposureTypes: string[];
  isInfostealer: boolean;
  riskScore: number;
}

export interface ImportResult {
  success: boolean;
  batch_id: string;
  records_received: number;
  records_processed: number;
  records_skipped: number;
  findings_created: number;
  errors: string[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

// === Severity Calculation ===

/**
 * Known infostealer malware families
 */
const INFOSTEALER_FAMILIES = new Set([
  'stealer logs', 'stealer', 'redline', 'raccoon', 'vidar', 'azorult',
  'formbook', 'lokibot', 'mars', 'lumma', 'titan', 'aurora', 'stealc',
  'mystic stealer', 'rhadamanthys', 'risepro', 'whitesnake', 'atomic',
]);

/**
 * Check if source is from infostealer malware
 */
function isInfostealerSource(source: CredentialRecord['source']): boolean {
  const name = source.name.toLowerCase();
  for (const family of INFOSTEALER_FAMILIES) {
    if (name.includes(family)) return true;
  }
  return source.type === 'infostealer';
}

/**
 * Calculate severity based on credential data
 */
function calculateSeverity(record: CredentialRecord): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  const fields = record.fields;
  const isInfostealer = isInfostealerSource(record.source);

  // CRITICAL: Infostealer with session data or sensitive tokens
  if (isInfostealer) {
    if (fields.has_cookies || fields.has_2fa_tokens || fields.has_keys) {
      return 'CRITICAL';
    }
    if (fields.has_password) {
      return 'CRITICAL';
    }
  }

  // CRITICAL: Credit card or crypto wallet data
  if (fields.has_credit_card || fields.has_crypto_wallet) {
    return 'CRITICAL';
  }

  // HIGH: Password + session data from any source
  if (fields.has_password && (fields.has_cookies || fields.has_autofill)) {
    return 'HIGH';
  }

  // MEDIUM: Password only
  if (fields.has_password) {
    return 'MEDIUM';
  }

  // LOW: Just browser data without credentials
  if (fields.has_browser_data || fields.has_autofill) {
    return 'LOW';
  }

  // INFO: Email/username exposure only
  return 'INFO';
}

/**
 * Calculate exposure types for reporting
 */
function calculateExposureTypes(record: CredentialRecord): string[] {
  const types: string[] = [];
  const fields = record.fields;

  if (isInfostealerSource(record.source)) {
    types.push('Infostealer malware');
  }

  if (fields.has_password && fields.has_cookies) {
    types.push('Password + session data');
  } else if (fields.has_password) {
    types.push('Password');
  }

  if (fields.has_cookies) types.push('Session cookies');
  if (fields.has_autofill) types.push('Autofill data');
  if (fields.has_browser_data) types.push('Browser data');
  if (fields.has_credit_card) types.push('Payment card');
  if (fields.has_crypto_wallet) types.push('Crypto wallet');
  if (fields.has_2fa_tokens) types.push('2FA tokens');
  if (fields.has_keys) types.push('SSH/API keys');

  return types;
}

/**
 * Calculate risk score (0-100) for prioritization
 */
function calculateRiskScore(record: CredentialRecord): number {
  let score = 0;
  const fields = record.fields;

  // Base score from severity
  if (isInfostealerSource(record.source)) score += 40;
  if (fields.has_password) score += 20;
  if (fields.has_cookies) score += 15;
  if (fields.has_2fa_tokens) score += 20;
  if (fields.has_credit_card) score += 25;
  if (fields.has_crypto_wallet) score += 25;
  if (fields.has_keys) score += 20;
  if (fields.has_autofill) score += 5;
  if (fields.has_browser_data) score += 5;

  // Recency bonus
  if (record.source.collection_date) {
    const daysSinceCollection = (Date.now() - new Date(record.source.collection_date).getTime()) / (1000 * 60 * 60 * 24);
    if (daysSinceCollection < 7) score += 15;
    else if (daysSinceCollection < 30) score += 10;
    else if (daysSinceCollection < 90) score += 5;
  }

  // Confidence adjustment
  if (record.source.confidence !== undefined) {
    score = score * record.source.confidence;
  }

  return Math.min(100, Math.round(score));
}

// === Processing Functions ===

/**
 * Process a single credential record
 */
function processCredential(record: CredentialRecord): ProcessedCredential {
  return {
    record,
    severity: calculateSeverity(record),
    exposureTypes: calculateExposureTypes(record),
    isInfostealer: isInfostealerSource(record.source),
    riskScore: calculateRiskScore(record),
  };
}

/**
 * Group processed credentials by user (email/username)
 */
function groupByUser(credentials: ProcessedCredential[]): Map<string, ProcessedCredential[]> {
  const groups = new Map<string, ProcessedCredential[]>();

  for (const cred of credentials) {
    const userId = (cred.record.email || cred.record.username || 'unknown').toLowerCase();

    if (!groups.has(userId)) {
      groups.set(userId, []);
    }
    groups.get(userId)!.push(cred);
  }

  return groups;
}

/**
 * Get the highest severity from a group of credentials
 */
function getHighestSeverity(credentials: ProcessedCredential[]): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

  for (const severity of severityOrder) {
    if (credentials.some(c => c.severity === severity)) {
      return severity;
    }
  }
  return 'INFO';
}

// === Main Import Function ===

/**
 * Import and process infostealer data batch
 */
export async function importInfostealerData(
  data: InfostealerBatchImport,
  scanId: string
): Promise<ImportResult> {
  const batchId = data.batch_id || `batch-${Date.now()}`;

  log.info({
    batchId,
    recordCount: data.records.length,
    targetDomain: data.target_domain,
    scanId,
  }, 'Starting infostealer data import');

  const result: ImportResult = {
    success: false,
    batch_id: batchId,
    records_received: data.records.length,
    records_processed: 0,
    records_skipped: 0,
    findings_created: 0,
    errors: [],
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
  };

  try {
    // Validate and process records
    const processed: ProcessedCredential[] = [];

    for (const record of data.records) {
      try {
        const validated = CredentialRecordSchema.parse(record);

        // Apply domain filter if specified
        if (data.target_domain) {
          const recordDomain = validated.domain ||
            (validated.email ? validated.email.split('@')[1] : null) ||
            (validated.url ? new URL(validated.url).hostname : null);

          if (!recordDomain || !recordDomain.includes(data.target_domain)) {
            result.records_skipped++;
            continue;
          }
        }

        processed.push(processCredential(validated));
        result.records_processed++;

      } catch (validationError) {
        result.errors.push(`Record validation error: ${(validationError as Error).message}`);
        result.records_skipped++;
      }
    }

    // Group by user and create findings
    const userGroups = groupByUser(processed);

    for (const [userId, credentials] of userGroups) {
      const highestSeverity = getHighestSeverity(credentials);
      const allExposureTypes = [...new Set(credentials.flatMap(c => c.exposureTypes))];
      const allSources = [...new Set(credentials.map(c => c.record.source.name))];
      const maxRiskScore = Math.max(...credentials.map(c => c.riskScore));
      const hasInfostealer = credentials.some(c => c.isInfostealer);

      // Update summary
      result.summary[highestSeverity.toLowerCase() as keyof typeof result.summary]++;

      // Create artifact
      const artifactId = await insertArtifact({
        type: 'custom_infostealer_data',
        val_text: `Custom breach data: ${userId} (${credentials.length} records)`,
        severity: highestSeverity,
        meta: {
          scan_id: scanId,
          scan_module: 'custom_infostealer_adapter',
          batch_id: batchId,
          user_id: userId,
          record_count: credentials.length,
          exposure_types: allExposureTypes,
          sources: allSources,
          risk_score: maxRiskScore,
          is_infostealer: hasInfostealer,
          source_system: data.source_system,
        },
      });

      // Create finding
      const findingType = hasInfostealer ? 'CRITICAL_BREACH_EXPOSURE' :
        highestSeverity === 'HIGH' || highestSeverity === 'CRITICAL' ? 'PASSWORD_BREACH_EXPOSURE' :
          'EMAIL_BREACH_EXPOSURE';

      const recommendation = hasInfostealer ?
        'Isolate compromised devices, then reset passwords and revoke sessions' :
        highestSeverity === 'MEDIUM' || highestSeverity === 'HIGH' ?
          'Reset passwords, enable MFA, and review sign-in logs' :
          'Monitor for phishing attempts and consider security awareness training';

      await insertFinding({
        artifact_id: artifactId,
        finding_type: findingType,
        recommendation,
        description: `${credentials.length} breach record(s) found for ${userId} | ` +
          `Exposure types: ${allExposureTypes.join(', ')} | ` +
          `Sources: ${allSources.join(', ')}`,
        scan_id: scanId,
        severity: highestSeverity,
        type: findingType,
        data: {
          user_id: userId,
          breach_count: credentials.length,
          exposure_types: allExposureTypes,
          sources: allSources,
          risk_score: maxRiskScore,
          is_infostealer: hasInfostealer,
          // Include breach context for EAL calculation
          credential_completeness: credentials.some(c => c.record.fields.has_cookies) ? 'cookies' :
            credentials.some(c => c.record.fields.has_password) ? 'password' : 'email',
          infostealer_source: hasInfostealer,
        },
      });

      result.findings_created++;
    }

    result.success = true;

    log.info({
      batchId,
      processed: result.records_processed,
      skipped: result.records_skipped,
      findings: result.findings_created,
      summary: result.summary,
    }, 'Infostealer data import completed');

  } catch (error) {
    result.errors.push(`Import failed: ${(error as Error).message}`);
    log.error({ err: error, batchId, scanId }, 'Infostealer data import failed');
  }

  return result;
}

/**
 * Validate infostealer data without importing
 * Useful for testing data format before actual import
 */
export function validateInfostealerData(data: unknown): {
  valid: boolean;
  errors: string[];
  recordCount?: number;
} {
  try {
    const parsed = InfostealerBatchImportSchema.parse(data);
    return {
      valid: true,
      errors: [],
      recordCount: parsed.records.length,
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        valid: false,
        errors: error.errors.map(e => `${e.path.join('.')}: ${e.message}`),
      };
    }
    return {
      valid: false,
      errors: [(error as Error).message],
    };
  }
}

// === Export Schema for Documentation ===

/**
 * Get JSON Schema for documentation/validation purposes
 */
export function getJsonSchema(): object {
  return {
    $schema: 'http://json-schema.org/draft-07/schema#',
    title: 'InfostealerBatchImport',
    description: 'Schema for importing custom infostealer/breach data',
    type: 'object',
    properties: {
      batch_id: { type: 'string', description: 'Unique identifier for this import batch' },
      source_system: { type: 'string', description: 'Name of the source system' },
      import_timestamp: { type: 'string', format: 'date-time' },
      target_domain: { type: 'string', description: 'Only import records matching this domain' },
      records: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            email: { type: 'string', format: 'email' },
            username: { type: 'string' },
            domain: { type: 'string' },
            url: { type: 'string', format: 'uri' },
            source: {
              type: 'object',
              required: ['name'],
              properties: {
                name: { type: 'string', description: 'Source name (e.g., "Stealer Logs", "Redline")' },
                type: { type: 'string', enum: ['infostealer', 'database_breach', 'paste', 'combo_list', 'other'] },
                breach_date: { type: 'string', format: 'date-time' },
                collection_date: { type: 'string', format: 'date-time' },
                confidence: { type: 'number', minimum: 0, maximum: 1 },
              },
            },
            fields: {
              type: 'object',
              properties: {
                has_password: { type: 'boolean' },
                has_cookies: { type: 'boolean' },
                has_autofill: { type: 'boolean' },
                has_browser_data: { type: 'boolean' },
                has_credit_card: { type: 'boolean' },
                has_crypto_wallet: { type: 'boolean' },
                has_2fa_tokens: { type: 'boolean' },
                has_keys: { type: 'boolean' },
              },
            },
            metadata: { type: 'object' },
          },
        },
      },
      metadata: { type: 'object' },
    },
    required: ['records'],
  };
}
