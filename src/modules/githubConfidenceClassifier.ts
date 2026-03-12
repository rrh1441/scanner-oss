/**
 * =============================================================================
 * MODULE: githubConfidenceClassifier.ts
 * =============================================================================
 * Classifies GitHub secret leads by confidence level for pipeline routing.
 *
 * Classification tiers:
 *   - HIGH (≥60):   Enrich immediately - high likelihood of live, actionable secret
 *   - MEDIUM (30-59): Slower campaign - possible false positive or test key
 *   - LOW (<30):    Log only - likely false positive, do not outbound
 *
 * Scoring factors:
 *   - Repo recency (new repos more likely to have live secrets)
 *   - Commit recency (active development = likely used)
 *   - Pattern type (AWS/Stripe/DB = higher value)
 *   - Test markers (test/, spec/, .example = false positive indicators)
 *   - Fork status (forks often copy secrets unknowingly)
 *   - Stars (popular repos = real projects)
 * =============================================================================
 */

import { request } from 'undici';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('githubConfidenceClassifier');

/* -------------------------------------------------------------------------- */
/*  Configuration                                                             */
/* -------------------------------------------------------------------------- */

const getApiToken = () => process.env.GITHUB_TOKEN ?? '';
const TIMEOUT_MS = parseInt(process.env.GITHUB_CONTENT_TIMEOUT_MS ?? '15000', 10);

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

export interface ConfidenceFactors {
  repo_age_days: number;
  last_commit_days: number;
  pattern_type: 'database' | 'payment' | 'cloud' | 'auth' | 'monitoring' | 'generic';
  has_env_example: boolean;
  has_test_markers: boolean;
  is_fork: boolean;
  repo_stars: number;
  file_path_quality: 'production' | 'config' | 'test' | 'example';
}

export interface ConfidenceResult {
  score: number;
  tier: 'high' | 'medium' | 'low';
  factors: ConfidenceFactors;
  breakdown: {
    base: number;
    repo_age: number;
    commit_recency: number;
    pattern_value: number;
    env_example_penalty: number;
    test_markers_penalty: number;
    fork_penalty: number;
    stars_bonus: number;
    file_path_adjustment: number;
  };
}

export interface RepoMetadata {
  created_at: string;
  pushed_at: string;
  fork: boolean;
  stargazers_count: number;
}

/* -------------------------------------------------------------------------- */
/*  Scoring Constants                                                         */
/* -------------------------------------------------------------------------- */

const SCORING = {
  BASE_SCORE: 50,

  // Repo age scoring (newer = more likely live)
  REPO_AGE: {
    UNDER_30_DAYS: 20,
    UNDER_90_DAYS: 10,
    UNDER_180_DAYS: 5,
    OVER_180_DAYS: 0,
  },

  // Commit recency (recent = active development)
  COMMIT_RECENCY: {
    UNDER_7_DAYS: 25,
    UNDER_30_DAYS: 15,
    UNDER_90_DAYS: 5,
    OVER_90_DAYS: 0,
  },

  // Pattern type value
  PATTERN_VALUE: {
    database: 20,    // DB credentials = direct access
    payment: 20,     // Stripe/PayPal = financial risk
    cloud: 15,       // AWS/GCP = infrastructure access
    auth: 10,        // Auth tokens = moderate risk
    monitoring: 5,   // Sentry/Datadog = lower risk
    generic: 0,      // Unknown patterns
  },

  // Penalties for false positive indicators
  ENV_EXAMPLE_PENALTY: -30,
  TEST_MARKERS_PENALTY: -25,
  FORK_PENALTY: -15,

  // Bonuses
  STARS_BONUS: {
    OVER_100: 10,
    OVER_10: 5,
    UNDER_10: 0,
  },

  // File path adjustments
  FILE_PATH: {
    production: 15,  // .env, config.json, application.properties
    config: 5,       // config/, settings/
    test: -20,       // test/, spec/, __tests__
    example: -25,    // example/, sample/, demo/
  },
} as const;

// Tier thresholds
const TIER_THRESHOLDS = {
  HIGH: 60,
  MEDIUM: 30,
} as const;

/* -------------------------------------------------------------------------- */
/*  File Path Analysis                                                        */
/* -------------------------------------------------------------------------- */

const PRODUCTION_FILE_PATTERNS = [
  /^\.env$/i,
  /^\.env\.local$/i,
  /^\.env\.production$/i,
  /^config\.json$/i,
  /^config\.ya?ml$/i,
  /^application\.properties$/i,
  /^settings\.py$/i,
  /^secrets\.json$/i,
  /^credentials\.json$/i,
];

const CONFIG_PATH_PATTERNS = [
  /^config\//i,
  /^settings\//i,
  /^conf\//i,
  /\/config\//i,
  /\/settings\//i,
];

const TEST_PATH_PATTERNS = [
  /test\//i,
  /tests\//i,
  /spec\//i,
  /specs\//i,
  /__tests__\//i,
  /__test__\//i,
  /\.test\./i,
  /\.spec\./i,
  /mock/i,
  /fixture/i,
];

const EXAMPLE_PATH_PATTERNS = [
  /example/i,
  /sample/i,
  /demo/i,
  /tutorial/i,
  /template/i,
  /skeleton/i,
  /boilerplate/i,
  /\.example/i,
  /\.sample/i,
];

function classifyFilePath(filePath: string): 'production' | 'config' | 'test' | 'example' {
  const lower = filePath.toLowerCase();

  // Check example patterns first (highest penalty)
  for (const pattern of EXAMPLE_PATH_PATTERNS) {
    if (pattern.test(lower)) return 'example';
  }

  // Check test patterns
  for (const pattern of TEST_PATH_PATTERNS) {
    if (pattern.test(lower)) return 'test';
  }

  // Check production patterns (exact file match)
  const fileName = lower.split('/').pop() ?? '';
  for (const pattern of PRODUCTION_FILE_PATTERNS) {
    if (pattern.test(fileName)) return 'production';
  }

  // Check config path patterns
  for (const pattern of CONFIG_PATH_PATTERNS) {
    if (pattern.test(lower)) return 'config';
  }

  // Default to config (neutral)
  return 'config';
}

/* -------------------------------------------------------------------------- */
/*  Repository Metadata Fetching                                              */
/* -------------------------------------------------------------------------- */

async function fetchRepoMetadata(owner: string, repo: string): Promise<RepoMetadata | null> {
  const token = getApiToken();
  if (!token) return null;

  try {
    const { body, statusCode } = await request(`https://api.github.com/repos/${owner}/${repo}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github.v3+json',
        'User-Agent': 'SecurityScanner-Scanner/1.0',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      headersTimeout: TIMEOUT_MS,
      bodyTimeout: TIMEOUT_MS,
    });

    if (statusCode !== 200) return null;

    const data = await body.json() as Record<string, unknown>;
    return {
      created_at: data.created_at as string,
      pushed_at: data.pushed_at as string,
      fork: data.fork as boolean,
      stargazers_count: data.stargazers_count as number,
    };
  } catch (err) {
    log.info({ err: (err as Error).message }, 'Failed to fetch repo metadata');
    return null;
  }
}

/**
 * Check if repo has .env.example or similar files
 */
async function checkForEnvExample(owner: string, repo: string): Promise<boolean> {
  const token = getApiToken();
  if (!token) return false;

  const filesToCheck = ['.env.example', '.env.sample', 'example.env', 'sample.env'];

  for (const file of filesToCheck) {
    try {
      const { statusCode } = await request(
        `https://api.github.com/repos/${owner}/${repo}/contents/${file}`,
        {
          method: 'HEAD',
          headers: {
            Authorization: `Bearer ${token}`,
            'User-Agent': 'SecurityScanner-Scanner/1.0',
            'X-GitHub-Api-Version': '2022-11-28',
          },
          headersTimeout: 5000,
        }
      );

      if (statusCode === 200) return true;
    } catch {
      // File doesn't exist, continue
    }
  }

  return false;
}

/* -------------------------------------------------------------------------- */
/*  Main Classification Function                                              */
/* -------------------------------------------------------------------------- */

/**
 * Calculate confidence score and classify a GitHub secret lead.
 */
export async function classifySecret(
  owner: string,
  repo: string,
  filePath: string,
  patternCategory: 'database' | 'payment' | 'cloud' | 'auth' | 'monitoring' | 'generic',
  options?: {
    skipApiCalls?: boolean;
    existingMetadata?: {
      repoStars?: number;
      isFork?: boolean;
      createdAt?: string;
      pushedAt?: string;
    };
  }
): Promise<ConfidenceResult> {
  const now = new Date();
  let repoMetadata: RepoMetadata | null = null;
  let hasEnvExample = false;

  // Fetch metadata if not provided and API calls allowed
  if (!options?.skipApiCalls) {
    [repoMetadata, hasEnvExample] = await Promise.all([
      options?.existingMetadata
        ? null
        : fetchRepoMetadata(owner, repo),
      checkForEnvExample(owner, repo),
    ]);
  }

  // Use provided or fetched metadata
  const stars = options?.existingMetadata?.repoStars ?? repoMetadata?.stargazers_count ?? 0;
  const isFork = options?.existingMetadata?.isFork ?? repoMetadata?.fork ?? false;
  const createdAt = options?.existingMetadata?.createdAt ?? repoMetadata?.created_at;
  const pushedAt = options?.existingMetadata?.pushedAt ?? repoMetadata?.pushed_at;

  // Calculate days
  const repoAgeDays = createdAt
    ? Math.floor((now.getTime() - new Date(createdAt).getTime()) / (1000 * 60 * 60 * 24))
    : 365; // Default to old if unknown

  const lastCommitDays = pushedAt
    ? Math.floor((now.getTime() - new Date(pushedAt).getTime()) / (1000 * 60 * 60 * 24))
    : 365; // Default to stale if unknown

  // Classify file path
  const filePathQuality = classifyFilePath(filePath);
  const hasTestMarkers = filePathQuality === 'test';

  // Build factors object
  const factors: ConfidenceFactors = {
    repo_age_days: repoAgeDays,
    last_commit_days: lastCommitDays,
    pattern_type: patternCategory,
    has_env_example: hasEnvExample,
    has_test_markers: hasTestMarkers,
    is_fork: isFork,
    repo_stars: stars,
    file_path_quality: filePathQuality,
  };

  // Calculate score components
  const breakdown = {
    base: SCORING.BASE_SCORE,

    repo_age:
      repoAgeDays < 30
        ? SCORING.REPO_AGE.UNDER_30_DAYS
        : repoAgeDays < 90
          ? SCORING.REPO_AGE.UNDER_90_DAYS
          : repoAgeDays < 180
            ? SCORING.REPO_AGE.UNDER_180_DAYS
            : SCORING.REPO_AGE.OVER_180_DAYS,

    commit_recency:
      lastCommitDays < 7
        ? SCORING.COMMIT_RECENCY.UNDER_7_DAYS
        : lastCommitDays < 30
          ? SCORING.COMMIT_RECENCY.UNDER_30_DAYS
          : lastCommitDays < 90
            ? SCORING.COMMIT_RECENCY.UNDER_90_DAYS
            : SCORING.COMMIT_RECENCY.OVER_90_DAYS,

    pattern_value: SCORING.PATTERN_VALUE[patternCategory],

    env_example_penalty: hasEnvExample ? SCORING.ENV_EXAMPLE_PENALTY : 0,

    test_markers_penalty: hasTestMarkers ? SCORING.TEST_MARKERS_PENALTY : 0,

    fork_penalty: isFork ? SCORING.FORK_PENALTY : 0,

    stars_bonus:
      stars > 100
        ? SCORING.STARS_BONUS.OVER_100
        : stars > 10
          ? SCORING.STARS_BONUS.OVER_10
          : SCORING.STARS_BONUS.UNDER_10,

    file_path_adjustment: SCORING.FILE_PATH[filePathQuality],
  };

  // Sum up total score
  const rawScore =
    breakdown.base +
    breakdown.repo_age +
    breakdown.commit_recency +
    breakdown.pattern_value +
    breakdown.env_example_penalty +
    breakdown.test_markers_penalty +
    breakdown.fork_penalty +
    breakdown.stars_bonus +
    breakdown.file_path_adjustment;

  // Clamp to 0-100
  const score = Math.max(0, Math.min(100, rawScore));

  // Determine tier
  const tier: 'high' | 'medium' | 'low' =
    score >= TIER_THRESHOLDS.HIGH
      ? 'high'
      : score >= TIER_THRESHOLDS.MEDIUM
        ? 'medium'
        : 'low';

  return { score, tier, factors, breakdown };
}

/**
 * Quick classification without API calls (uses existing data only).
 * Use this when processing in bulk to avoid rate limits.
 */
export function classifySecretQuick(
  filePath: string,
  patternCategory: 'database' | 'payment' | 'cloud' | 'auth' | 'monitoring' | 'generic',
  repoStars: number,
  isFork: boolean
): { score: number; tier: 'high' | 'medium' | 'low' } {
  const filePathQuality = classifyFilePath(filePath);
  const hasTestMarkers = filePathQuality === 'test';

  let score: number = SCORING.BASE_SCORE;

  // Add pattern value
  score += SCORING.PATTERN_VALUE[patternCategory];

  // Apply penalties
  if (hasTestMarkers) score += SCORING.TEST_MARKERS_PENALTY;
  if (isFork) score += SCORING.FORK_PENALTY;
  if (filePathQuality === 'example') score += SCORING.FILE_PATH.example;
  else if (filePathQuality === 'production') score += SCORING.FILE_PATH.production;

  // Apply star bonus
  if (repoStars > 100) score += SCORING.STARS_BONUS.OVER_100;
  else if (repoStars > 10) score += SCORING.STARS_BONUS.OVER_10;

  score = Math.max(0, Math.min(100, score));

  const tier: 'high' | 'medium' | 'low' =
    score >= TIER_THRESHOLDS.HIGH
      ? 'high'
      : score >= TIER_THRESHOLDS.MEDIUM
        ? 'medium'
        : 'low';

  return { score, tier };
}

/* -------------------------------------------------------------------------- */
/*  Batch Classification                                                      */
/* -------------------------------------------------------------------------- */

export interface LeadForClassification {
  id: number;
  repo_owner: string;
  repo_name: string;
  file_path: string;
  secret_type: string;
  repo_stars: number;
  repo_forks: number;
  is_fork?: boolean;
}

/**
 * Classify multiple leads in batch (quick mode, no API calls).
 */
export function classifyBatch(
  leads: LeadForClassification[]
): Map<number, { score: number; tier: 'high' | 'medium' | 'low' }> {
  const results = new Map<number, { score: number; tier: 'high' | 'medium' | 'low' }>();

  for (const lead of leads) {
    // Map secret_type to category
    const category = mapSecretTypeToCategory(lead.secret_type);

    const result = classifySecretQuick(
      lead.file_path,
      category,
      lead.repo_stars,
      lead.is_fork ?? false
    );

    results.set(lead.id, result);
  }

  return results;
}

/**
 * Map secret type name to category for scoring.
 */
export function mapSecretTypeToCategory(
  secretType: string
): 'database' | 'payment' | 'cloud' | 'auth' | 'monitoring' | 'generic' {
  const lower = secretType.toLowerCase();

  if (
    lower.includes('postgres') ||
    lower.includes('mysql') ||
    lower.includes('mongo') ||
    lower.includes('redis') ||
    lower.includes('supabase') ||
    lower.includes('neon') ||
    lower.includes('planetscale') ||
    lower.includes('database')
  ) {
    return 'database';
  }

  if (lower.includes('stripe') || lower.includes('payment')) {
    return 'payment';
  }

  if (lower.includes('aws') || lower.includes('google') || lower.includes('azure')) {
    return 'cloud';
  }

  if (
    lower.includes('github') ||
    lower.includes('slack') ||
    lower.includes('discord') ||
    lower.includes('auth0') ||
    lower.includes('token')
  ) {
    return 'auth';
  }

  if (
    lower.includes('sentry') ||
    lower.includes('datadog') ||
    lower.includes('newrelic') ||
    lower.includes('monitoring')
  ) {
    return 'monitoring';
  }

  return 'generic';
}

/* -------------------------------------------------------------------------- */
/*  Default Export                                                            */
/* -------------------------------------------------------------------------- */

export default {
  classifySecret,
  classifySecretQuick,
  classifyBatch,
  classifyFilePath,
  mapSecretTypeToCategory,
  SCORING,
  TIER_THRESHOLDS,
};
