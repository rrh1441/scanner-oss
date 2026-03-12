/**
 * Secret Pattern Configuration
 *
 * Defines patterns for detecting exposed secrets in code repositories.
 * Used by the GitHub Secret Search and TruffleHog modules.
 */

export interface SecretPattern {
  id: string;
  name: string;
  description: string;
  regex: RegExp;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  /** GitHub search query to find potential matches */
  searchQuery?: string;
  /** Validation function to reduce false positives */
  validate?: (match: string) => boolean;
  /** Service provider (aws, gcp, azure, github, etc.) */
  provider?: string;
  /** Secret category (database, payment, api_key, etc.) */
  category?: string;
}

/**
 * Patterns suitable for bulk GitHub Code Search
 * These use GitHub's query syntax rather than regex
 */
export const BULK_SEARCHABLE_PATTERNS: SecretPattern[] = [
  // AWS
  {
    id: 'aws_access_key',
    name: 'AWS Access Key ID',
    description: 'AWS Access Key ID (starts with AKIA)',
    regex: /AKIA[0-9A-Z]{16}/g,
    searchQuery: 'AKIA',
    severity: 'CRITICAL',
    provider: 'aws',
    validate: (match) => /^AKIA[0-9A-Z]{16}$/.test(match),
  },
  {
    id: 'aws_secret_key',
    name: 'AWS Secret Access Key',
    description: 'AWS Secret Access Key (40 character base64)',
    regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    searchQuery: 'aws_secret_access_key',
    severity: 'CRITICAL',
    provider: 'aws',
  },

  // GitHub
  {
    id: 'github_pat',
    name: 'GitHub Personal Access Token',
    description: 'GitHub PAT (classic or fine-grained)',
    regex: /ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}/g,
    searchQuery: 'ghp_ OR github_pat_',
    severity: 'CRITICAL',
    provider: 'github',
  },
  {
    id: 'github_oauth',
    name: 'GitHub OAuth Token',
    description: 'GitHub OAuth App Token',
    regex: /gho_[A-Za-z0-9]{36,}/g,
    searchQuery: 'gho_',
    severity: 'HIGH',
    provider: 'github',
  },

  // Google Cloud
  {
    id: 'gcp_api_key',
    name: 'Google Cloud API Key',
    description: 'Google Cloud API Key',
    regex: /AIza[A-Za-z0-9_-]{35}/g,
    searchQuery: 'AIza',
    severity: 'HIGH',
    provider: 'gcp',
  },
  {
    id: 'gcp_service_account',
    name: 'GCP Service Account Key',
    description: 'Google Cloud Service Account JSON Key',
    regex: /"type":\s*"service_account"/g,
    searchQuery: '"type": "service_account"',
    severity: 'CRITICAL',
    provider: 'gcp',
  },

  // Azure
  {
    id: 'azure_storage_key',
    name: 'Azure Storage Account Key',
    description: 'Azure Storage Account Access Key',
    regex: /AccountKey=[A-Za-z0-9+/=]{88}/g,
    searchQuery: 'AccountKey=',
    severity: 'CRITICAL',
    provider: 'azure',
  },
  {
    id: 'azure_connection_string',
    name: 'Azure Connection String',
    description: 'Azure Service Connection String',
    regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+/g,
    searchQuery: 'DefaultEndpointsProtocol=https AccountKey=',
    severity: 'CRITICAL',
    provider: 'azure',
  },

  // Stripe
  {
    id: 'stripe_secret_key',
    name: 'Stripe Secret Key',
    description: 'Stripe Live/Test Secret Key',
    regex: /sk_(live|test)_[A-Za-z0-9]{24,}/g,
    searchQuery: 'sk_live_ OR sk_test_',
    severity: 'CRITICAL',
    provider: 'stripe',
  },
  {
    id: 'stripe_publishable_key',
    name: 'Stripe Publishable Key',
    description: 'Stripe Publishable Key (lower severity)',
    regex: /pk_(live|test)_[A-Za-z0-9]{24,}/g,
    searchQuery: 'pk_live_ OR pk_test_',
    severity: 'LOW',
    provider: 'stripe',
  },

  // Slack
  {
    id: 'slack_token',
    name: 'Slack Token',
    description: 'Slack Bot/User/App Token',
    regex: /xox[baprs]-[A-Za-z0-9-]+/g,
    searchQuery: 'xoxb- OR xoxa- OR xoxp-',
    severity: 'HIGH',
    provider: 'slack',
  },
  {
    id: 'slack_webhook',
    name: 'Slack Webhook URL',
    description: 'Slack Incoming Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    searchQuery: 'hooks.slack.com/services',
    severity: 'MEDIUM',
    provider: 'slack',
  },

  // Twilio
  {
    id: 'twilio_api_key',
    name: 'Twilio API Key',
    description: 'Twilio API Key (SK prefix)',
    regex: /SK[a-f0-9]{32}/g,
    searchQuery: 'twilio SK',
    severity: 'HIGH',
    provider: 'twilio',
  },

  // SendGrid
  {
    id: 'sendgrid_api_key',
    name: 'SendGrid API Key',
    description: 'SendGrid API Key (SG. prefix)',
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    searchQuery: 'SG.',
    severity: 'HIGH',
    provider: 'sendgrid',
  },

  // Mailchimp
  {
    id: 'mailchimp_api_key',
    name: 'Mailchimp API Key',
    description: 'Mailchimp API Key',
    regex: /[a-f0-9]{32}-us[0-9]{1,2}/g,
    searchQuery: 'mailchimp api key',
    severity: 'MEDIUM',
    provider: 'mailchimp',
  },

  // JWT
  {
    id: 'jwt_secret',
    name: 'JWT Secret',
    description: 'Potential JWT signing secret',
    regex: /jwt[_-]?secret['":\s]*[=:]\s*['"]*[A-Za-z0-9+/=]{16,}/gi,
    searchQuery: 'jwt_secret OR jwt-secret',
    severity: 'CRITICAL',
    provider: 'generic',
  },

  // Private Keys
  {
    id: 'private_key_rsa',
    name: 'RSA Private Key',
    description: 'RSA Private Key (PEM format)',
    regex: /-----BEGIN RSA PRIVATE KEY-----/g,
    searchQuery: '"-----BEGIN RSA PRIVATE KEY-----"',
    severity: 'CRITICAL',
    provider: 'generic',
  },
  {
    id: 'private_key_generic',
    name: 'Private Key',
    description: 'Generic Private Key (PEM format)',
    regex: /-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    searchQuery: '"-----BEGIN PRIVATE KEY-----"',
    severity: 'CRITICAL',
    provider: 'generic',
  },

  // Database Connection Strings
  {
    id: 'postgres_uri',
    name: 'PostgreSQL Connection String',
    description: 'PostgreSQL connection URI with credentials',
    regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/]+/gi,
    searchQuery: 'postgresql://',
    severity: 'CRITICAL',
    provider: 'database',
  },
  {
    id: 'mysql_uri',
    name: 'MySQL Connection String',
    description: 'MySQL connection URI with credentials',
    regex: /mysql:\/\/[^:]+:[^@]+@[^/]+/gi,
    searchQuery: 'mysql://',
    severity: 'CRITICAL',
    provider: 'database',
  },
  {
    id: 'mongodb_uri',
    name: 'MongoDB Connection String',
    description: 'MongoDB connection URI with credentials',
    regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/]+/gi,
    searchQuery: 'mongodb+srv://',
    severity: 'CRITICAL',
    provider: 'database',
  },

  // NPM
  {
    id: 'npm_token',
    name: 'NPM Auth Token',
    description: 'NPM Authentication Token',
    regex: /\/\/registry\.npmjs\.org\/:_authToken=[A-Za-z0-9-]+/g,
    searchQuery: 'registry.npmjs.org :_authToken',
    severity: 'HIGH',
    provider: 'npm',
  },

  // Heroku
  {
    id: 'heroku_api_key',
    name: 'Heroku API Key',
    description: 'Heroku API Key',
    regex: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    searchQuery: 'HEROKU_API_KEY',
    severity: 'HIGH',
    provider: 'heroku',
  },

  // Discord
  {
    id: 'discord_token',
    name: 'Discord Bot Token',
    description: 'Discord Bot Authentication Token',
    regex: /[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g,
    searchQuery: 'discord token',
    severity: 'HIGH',
    provider: 'discord',
  },
  {
    id: 'discord_webhook',
    name: 'Discord Webhook URL',
    description: 'Discord Webhook URL',
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
    searchQuery: 'discord.com/api/webhooks',
    severity: 'MEDIUM',
    provider: 'discord',
  },

  // OpenAI
  {
    id: 'openai_api_key',
    name: 'OpenAI API Key',
    description: 'OpenAI API Key (sk- prefix)',
    regex: /sk-[A-Za-z0-9]{48}/g,
    searchQuery: 'OPENAI_API_KEY sk-',
    severity: 'HIGH',
    provider: 'openai',
  },

  // Anthropic
  {
    id: 'anthropic_api_key',
    name: 'Anthropic API Key',
    description: 'Anthropic/Claude API Key',
    regex: /sk-ant-[A-Za-z0-9-]{95}/g,
    searchQuery: 'ANTHROPIC_API_KEY sk-ant-',
    severity: 'HIGH',
    provider: 'anthropic',
  },
];

/**
 * Build a GitHub search query for a pattern, optionally scoped to a domain
 */
export function buildGitHubSearchQuery(pattern: SecretPattern, domain?: string): string {
  const baseQuery = pattern.searchQuery || pattern.id;

  // If domain provided, scope search to that domain
  if (domain) {
    const domainWithoutTld = domain.split('.')[0];
    return `${baseQuery} ${domain} OR ${domainWithoutTld}`;
  }

  // Otherwise just search the pattern
  return baseQuery;
}

/**
 * Get a safe preview of a secret (mask middle portion)
 */
export function getSecretPreview(secret: string, visibleChars: number = 6): string {
  if (secret.length <= visibleChars * 2) {
    return '*'.repeat(secret.length);
  }

  const start = secret.slice(0, visibleChars);
  const end = secret.slice(-visibleChars);
  const masked = '*'.repeat(Math.min(secret.length - visibleChars * 2, 20));

  return `${start}${masked}${end}`;
}

/**
 * Match secret patterns against text content
 */
export function matchSecretPatterns(content: string, patterns: SecretPattern[] = BULK_SEARCHABLE_PATTERNS): Array<{
  pattern: SecretPattern;
  matches: string[];
}> {
  const results: Array<{ pattern: SecretPattern; matches: string[] }> = [];

  for (const pattern of patterns) {
    const matches: string[] = [];
    let match;

    // Reset regex state for global patterns
    pattern.regex.lastIndex = 0;

    while ((match = pattern.regex.exec(content)) !== null) {
      const value = match[0];

      // Apply validation if available
      if (!pattern.validate || pattern.validate(value)) {
        matches.push(value);
      }

      // Prevent infinite loops on zero-length matches
      if (match.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++;
      }
    }

    if (matches.length > 0) {
      results.push({ pattern, matches });
    }
  }

  return results;
}

/**
 * Get all patterns for a specific provider
 */
export function getPatternsByProvider(provider: string): SecretPattern[] {
  return BULK_SEARCHABLE_PATTERNS.filter(p => p.provider === provider);
}

/**
 * Get high-severity patterns (CRITICAL and HIGH)
 */
export function getHighSeverityPatterns(): SecretPattern[] {
  return BULK_SEARCHABLE_PATTERNS.filter(p => p.severity === 'CRITICAL' || p.severity === 'HIGH');
}
