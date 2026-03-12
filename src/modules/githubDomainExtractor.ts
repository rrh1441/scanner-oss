/**
 * =============================================================================
 * MODULE: githubDomainExtractor.ts
 * =============================================================================
 * Extracts company/domain information from GitHub repositories.
 *
 * Extraction strategies:
 *   1. GitHub organization profile (website, email, company fields)
 *   2. Repository homepage field
 *   3. README content analysis
 *   4. package.json fields (homepage, repository, author)
 *   5. Config file patterns (.env.example, etc.)
 *
 * This module helps convert GitHub repository leads into company leads
 * for the enrichment pipeline.
 * =============================================================================
 */

import { request } from 'undici';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('githubDomainExtractor');
import { getRepoInfo, getOrgInfo, type OrgInfo, type RepoInfo } from './githubSecretSearch.js';

/* -------------------------------------------------------------------------- */
/*  Configuration                                                             */
/* -------------------------------------------------------------------------- */

const getApiToken = () => process.env.GITHUB_TOKEN ?? '';

// Timeout for content fetching
const TIMEOUT_MS = parseInt(process.env.GITHUB_CONTENT_TIMEOUT_MS ?? '15000', 10);

// Maximum README size to process (avoid huge files)
const MAX_README_SIZE = 100_000;

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

export interface ExtractedDomainInfo {
  domains: string[];
  emails: string[];
  companyName: string | null;
  orgWebsite: string | null;
  confidence: 'high' | 'medium' | 'low';
  sources: string[]; // Which extraction methods found data
}

/* -------------------------------------------------------------------------- */
/*  Domain/Email Extraction Patterns                                          */
/* -------------------------------------------------------------------------- */

// Domain extraction regex - finds URLs and converts to domains
const URL_REGEX = /https?:\/\/(?:www\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,})/gi;

// Email extraction regex
const EMAIL_REGEX = /[a-z0-9._%+-]+@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,})/gi;

// Domains to exclude (too generic or false positives)
const EXCLUDED_DOMAINS = new Set([
  // GitHub and related
  'github.com',
  'github.io',
  'githubusercontent.com',
  'githubassets.com',
  'githubcopilot.com',

  // Package registries
  'npmjs.com',
  'npmjs.org',
  'pypi.org',
  'pypi.python.org',
  'rubygems.org',
  'crates.io',
  'packagist.org',
  'nuget.org',
  'maven.org',
  'mvnrepository.com',

  // Cloud providers
  'amazonaws.com',
  'azure.com',
  'azure.net',
  'cloudfront.net',
  'cloudflare.com',
  'googleapis.com',
  'googlecloud.com',
  'digitalocean.com',
  'herokuapp.com',
  'vercel.app',
  'netlify.app',
  'netlify.com',
  'render.com',

  // CDNs
  'cdnjs.com',
  'jsdelivr.net',
  'unpkg.com',
  'esm.sh',
  'cloudflare.com',

  // Documentation/Examples
  'example.com',
  'example.org',
  'example.net',
  'test.com',
  'localhost',
  'placeholder.com',

  // Social/Common
  'twitter.com',
  'x.com',
  'facebook.com',
  'linkedin.com',
  'youtube.com',
  'medium.com',
  'dev.to',
  'stackoverflow.com',

  // Dev tools
  'shields.io',
  'badge.fury.io',
  'img.shields.io',
  'codecov.io',
  'coveralls.io',
  'travis-ci.org',
  'travis-ci.com',
  'circleci.com',
  'appveyor.com',
  'sentry.io',
]);

// Common company TLDs that indicate a real company domain
const COMPANY_TLDS = new Set([
  'com',
  'co',
  'io',
  'ai',
  'app',
  'dev',
  'tech',
  'org',
  'net',
  'biz',
]);

/* -------------------------------------------------------------------------- */
/*  Utility Functions                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Extract domains from text, filtering out excluded ones.
 */
function extractDomains(text: string): string[] {
  const domains = new Set<string>();

  // Extract from URLs
  for (const match of text.matchAll(URL_REGEX)) {
    const domain = match[1].toLowerCase();
    if (!isExcludedDomain(domain)) {
      domains.add(domain);
    }
  }

  return Array.from(domains);
}

/**
 * Extract email domains from text.
 */
function extractEmailDomains(text: string): { emails: string[]; domains: string[] } {
  const emails: string[] = [];
  const domains = new Set<string>();

  for (const match of text.matchAll(EMAIL_REGEX)) {
    const email = match[0].toLowerCase();
    const domain = match[1].toLowerCase();

    // Skip generic email providers
    if (isGenericEmailDomain(domain)) continue;
    if (isExcludedDomain(domain)) continue;

    emails.push(email);
    domains.add(domain);
  }

  return { emails, domains: Array.from(domains) };
}

/**
 * Check if a domain should be excluded.
 */
function isExcludedDomain(domain: string): boolean {
  const lower = domain.toLowerCase();

  // Direct match
  if (EXCLUDED_DOMAINS.has(lower)) return true;

  // Check if it's a subdomain of excluded domain
  for (const excluded of EXCLUDED_DOMAINS) {
    if (lower.endsWith(`.${excluded}`)) return true;
  }

  // Check for common patterns
  if (lower.includes('example') || lower.includes('placeholder')) return true;
  if (lower.includes('test') || lower.includes('demo')) return true;

  return false;
}

/**
 * Check if an email domain is a generic provider.
 */
function isGenericEmailDomain(domain: string): boolean {
  const genericDomains = new Set([
    'gmail.com',
    'googlemail.com',
    'yahoo.com',
    'hotmail.com',
    'outlook.com',
    'live.com',
    'msn.com',
    'aol.com',
    'icloud.com',
    'me.com',
    'mail.com',
    'protonmail.com',
    'proton.me',
    'yandex.com',
    'qq.com',
    '163.com',
    '126.com',
  ]);

  return genericDomains.has(domain.toLowerCase());
}

/**
 * Score a domain by how likely it is to be a real company domain.
 */
function scoreDomain(domain: string): number {
  const lower = domain.toLowerCase();
  let score = 50; // Base score

  // TLD scoring
  const tld = lower.split('.').pop() ?? '';
  if (COMPANY_TLDS.has(tld)) score += 20;
  if (tld === 'com') score += 10;

  // Length scoring (shorter domains often more valuable)
  const name = lower.split('.').slice(0, -1).join('.');
  if (name.length < 10) score += 10;
  if (name.length < 6) score += 10;

  // Penalize very long or complex domains
  if (name.length > 30) score -= 20;
  if (name.includes('-') && name.split('-').length > 2) score -= 10;

  return Math.max(0, Math.min(100, score));
}

/**
 * Extract company name from GitHub organization or user profile.
 */
function extractCompanyName(orgInfo: OrgInfo | null, repoInfo: RepoInfo | null): string | null {
  // Try org name first
  if (orgInfo?.name) return orgInfo.name;
  if (orgInfo?.company) return orgInfo.company;

  // Try repo description for company hints
  if (repoInfo?.description) {
    // Look for patterns like "Company Name's ..." or "By Company Name"
    const byPattern = /(?:by|from)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/;
    const match = repoInfo.description.match(byPattern);
    if (match) return match[1];
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/*  Content Fetching                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Fetch raw content from GitHub.
 */
async function fetchRawContent(
  owner: string,
  repo: string,
  path: string
): Promise<string | null> {
  const token = getApiToken();
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;

  try {
    const { body, statusCode } = await request(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github.v3.raw',
        'User-Agent': 'SecurityScanner-Scanner/1.0',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      headersTimeout: TIMEOUT_MS,
      bodyTimeout: TIMEOUT_MS,
    });

    if (statusCode === 404) return null;
    if (statusCode >= 400) return null;

    const text = await body.text();
    return text.length <= MAX_README_SIZE ? text : text.slice(0, MAX_README_SIZE);
  } catch (err) {
    log.info(`[DomainExtractor] Failed to fetch ${path}: ${(err as Error).message}`);
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/*  Extraction Strategies                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Strategy 1: Extract from GitHub organization profile.
 */
async function extractFromOrg(owner: string): Promise<Partial<ExtractedDomainInfo>> {
  const orgInfo = await getOrgInfo(owner);
  if (!orgInfo) return { sources: [] };

  const domains: string[] = [];
  const emails: string[] = [];
  const sources: string[] = [];

  // Organization website
  if (orgInfo.blog) {
    const blogDomains = extractDomains(orgInfo.blog);
    domains.push(...blogDomains);
    if (blogDomains.length > 0) sources.push('org_website');
  }

  // Organization email
  if (orgInfo.email) {
    const { emails: orgEmails, domains: emailDomains } = extractEmailDomains(orgInfo.email);
    emails.push(...orgEmails);
    domains.push(...emailDomains);
    if (orgEmails.length > 0) sources.push('org_email');
  }

  return {
    domains,
    emails,
    companyName: orgInfo.name ?? orgInfo.login,
    orgWebsite: orgInfo.blog ?? null,
    sources,
  };
}

/**
 * Strategy 2: Extract from repository info.
 */
async function extractFromRepo(owner: string, repo: string): Promise<Partial<ExtractedDomainInfo>> {
  const repoInfo = await getRepoInfo(owner, repo);
  if (!repoInfo) return { sources: [] };

  const domains: string[] = [];
  const sources: string[] = [];

  // Repository homepage
  if (repoInfo.homepage) {
    const homepageDomains = extractDomains(repoInfo.homepage);
    domains.push(...homepageDomains);
    if (homepageDomains.length > 0) sources.push('repo_homepage');
  }

  // Repository description
  if (repoInfo.description) {
    const descDomains = extractDomains(repoInfo.description);
    domains.push(...descDomains);
    if (descDomains.length > 0) sources.push('repo_description');
  }

  return { domains, sources };
}

/**
 * Strategy 3: Extract from README.
 */
async function extractFromReadme(owner: string, repo: string): Promise<Partial<ExtractedDomainInfo>> {
  // Try common README filenames
  const readmeFiles = ['README.md', 'readme.md', 'README', 'README.rst', 'README.txt'];
  let readmeContent: string | null = null;

  for (const filename of readmeFiles) {
    readmeContent = await fetchRawContent(owner, repo, filename);
    if (readmeContent) break;
  }

  if (!readmeContent) return { sources: [] };

  const domains = extractDomains(readmeContent);
  const { emails, domains: emailDomains } = extractEmailDomains(readmeContent);

  // Combine and dedupe
  const allDomains = [...new Set([...domains, ...emailDomains])];

  const sources: string[] = [];
  if (allDomains.length > 0) sources.push('readme');
  if (emails.length > 0) sources.push('readme_emails');

  return { domains: allDomains, emails, sources };
}

/**
 * Strategy 4: Extract from package.json.
 */
async function extractFromPackageJson(owner: string, repo: string): Promise<Partial<ExtractedDomainInfo>> {
  const content = await fetchRawContent(owner, repo, 'package.json');
  if (!content) return { sources: [] };

  try {
    const pkg = JSON.parse(content);
    const domains: string[] = [];
    const emails: string[] = [];
    const sources: string[] = [];

    // Homepage
    if (pkg.homepage) {
      const homepageDomains = extractDomains(pkg.homepage);
      domains.push(...homepageDomains);
      if (homepageDomains.length > 0) sources.push('package_homepage');
    }

    // Repository URL
    if (pkg.repository?.url) {
      const repoDomains = extractDomains(pkg.repository.url);
      domains.push(...repoDomains);
    }

    // Bugs URL
    if (pkg.bugs?.url) {
      const bugsDomains = extractDomains(pkg.bugs.url);
      domains.push(...bugsDomains);
    }

    // Author
    if (pkg.author) {
      const authorStr = typeof pkg.author === 'string' ? pkg.author : (pkg.author.email ?? '');
      const { emails: authorEmails, domains: authorDomains } = extractEmailDomains(authorStr);
      emails.push(...authorEmails);
      domains.push(...authorDomains);
      if (authorEmails.length > 0) sources.push('package_author');

      // Check for URL in author field
      if (pkg.author.url) {
        const authorUrlDomains = extractDomains(pkg.author.url);
        domains.push(...authorUrlDomains);
      }
    }

    // Contributors
    if (Array.isArray(pkg.contributors)) {
      for (const contrib of pkg.contributors.slice(0, 5)) { // Limit to first 5
        const contribStr = typeof contrib === 'string' ? contrib : (contrib.email ?? '');
        const { emails: contribEmails, domains: contribDomains } = extractEmailDomains(contribStr);
        emails.push(...contribEmails);
        domains.push(...contribDomains);
      }
    }

    return {
      domains: [...new Set(domains)],
      emails: [...new Set(emails)],
      sources,
    };
  } catch {
    return { sources: [] };
  }
}

/**
 * Strategy 5: Extract from git commit authors (via GitHub API).
 * This finds developer emails from actual commits, not just metadata.
 */
async function extractFromCommits(owner: string, repo: string): Promise<Partial<ExtractedDomainInfo>> {
  const token = getApiToken();
  const url = `https://api.github.com/repos/${owner}/${repo}/commits?per_page=30`;

  try {
    const { body, statusCode } = await request(url, {
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

    if (statusCode >= 400) return { sources: [] };

    const commits = await body.json() as Array<{
      commit?: { author?: { email?: string; name?: string } };
      author?: { login?: string };
    }>;

    const emails: string[] = [];
    const domains = new Set<string>();
    const seenEmails = new Set<string>();

    for (const commit of commits) {
      const email = commit.commit?.author?.email?.toLowerCase();
      if (!email || seenEmails.has(email)) continue;
      seenEmails.add(email);

      // Skip noreply GitHub emails
      if (email.includes('noreply') || email.includes('github.com')) continue;

      // Extract domain from email
      const atIndex = email.indexOf('@');
      if (atIndex === -1) continue;

      const domain = email.slice(atIndex + 1);

      // Skip generic email providers
      if (isGenericEmailDomain(domain)) continue;
      if (isExcludedDomain(domain)) continue;

      emails.push(email);
      domains.add(domain);
    }

    const sources: string[] = [];
    if (emails.length > 0) sources.push('git_commits');

    log.info(`[DomainExtractor] Found ${emails.length} emails from commits`);

    return {
      emails,
      domains: Array.from(domains),
      sources,
    };
  } catch (err) {
    log.info(`[DomainExtractor] Failed to fetch commits: ${(err as Error).message}`);
    return { sources: [] };
  }
}

/**
 * Strategy 6: Extract from config files (.env.example, etc.)
 */
async function extractFromConfigFiles(owner: string, repo: string): Promise<Partial<ExtractedDomainInfo>> {
  const configFiles = [
    '.env.example',
    '.env.sample',
    'config.example.json',
    'config.example.yaml',
    'config.example.yml',
  ];

  const domains: string[] = [];
  const emails: string[] = [];
  const sources: string[] = [];

  for (const filename of configFiles) {
    const content = await fetchRawContent(owner, repo, filename);
    if (!content) continue;

    const fileDomains = extractDomains(content);
    const { emails: fileEmails, domains: emailDomains } = extractEmailDomains(content);

    domains.push(...fileDomains, ...emailDomains);
    emails.push(...fileEmails);

    if (fileDomains.length > 0 || fileEmails.length > 0) {
      sources.push('config_files');
      break; // One config file is enough
    }
  }

  return {
    domains: [...new Set(domains)],
    emails: [...new Set(emails)],
    sources,
  };
}

/* -------------------------------------------------------------------------- */
/*  Main Extraction Function                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Extract domain and company information from a GitHub repository.
 *
 * @param owner - Repository owner (user or organization)
 * @param repo - Repository name
 * @returns Extracted domain information with confidence score
 */
export async function extractDomainInfo(
  owner: string,
  repo: string
): Promise<ExtractedDomainInfo> {
  log.info(`[DomainExtractor] Extracting domains for ${owner}/${repo}`);

  // Run all extraction strategies
  const [orgResult, repoResult, readmeResult, packageResult, configResult, commitsResult] = await Promise.all([
    extractFromOrg(owner),
    extractFromRepo(owner, repo),
    extractFromReadme(owner, repo),
    extractFromPackageJson(owner, repo),
    extractFromConfigFiles(owner, repo),
    extractFromCommits(owner, repo),
  ]);

  // Combine all results
  const allDomains: string[] = [
    ...(orgResult.domains ?? []),
    ...(repoResult.domains ?? []),
    ...(readmeResult.domains ?? []),
    ...(packageResult.domains ?? []),
    ...(configResult.domains ?? []),
    ...(commitsResult.domains ?? []),
  ];

  const allEmails: string[] = [
    ...(orgResult.emails ?? []),
    ...(readmeResult.emails ?? []),
    ...(packageResult.emails ?? []),
    ...(configResult.emails ?? []),
    ...(commitsResult.emails ?? []),
  ];

  const allSources: string[] = [
    ...(orgResult.sources ?? []),
    ...(repoResult.sources ?? []),
    ...(readmeResult.sources ?? []),
    ...(packageResult.sources ?? []),
    ...(configResult.sources ?? []),
    ...(commitsResult.sources ?? []),
  ];

  // Dedupe and score domains
  const uniqueDomains = [...new Set(allDomains)];
  const scoredDomains = uniqueDomains
    .map((d) => ({ domain: d, score: scoreDomain(d) }))
    .sort((a, b) => b.score - a.score)
    .map((d) => d.domain);

  const uniqueEmails = [...new Set(allEmails)];
  const uniqueSources = [...new Set(allSources)];

  // Determine confidence
  let confidence: 'high' | 'medium' | 'low' = 'low';
  if (uniqueSources.includes('org_website') || uniqueSources.includes('org_email')) {
    confidence = 'high';
  } else if (uniqueSources.includes('git_commits')) {
    // Commit emails are high-quality - actual developer addresses
    confidence = 'high';
  } else if (uniqueSources.includes('repo_homepage') || uniqueSources.includes('package_author')) {
    confidence = 'medium';
  } else if (uniqueSources.length >= 2) {
    confidence = 'medium';
  }

  // Extract company name
  let companyName = orgResult.companyName ?? null;
  if (!companyName) {
    const repoInfo = await getRepoInfo(owner, repo);
    const orgInfo = await getOrgInfo(owner);
    companyName = extractCompanyName(orgInfo, repoInfo);
  }

  const result: ExtractedDomainInfo = {
    domains: scoredDomains,
    emails: uniqueEmails,
    companyName,
    orgWebsite: orgResult.orgWebsite ?? null,
    confidence,
    sources: uniqueSources,
  };

  log.info(`[DomainExtractor] Found ${result.domains.length} domains, ${result.emails.length} emails (confidence: ${confidence})`);

  return result;
}

/**
 * Quick check if a repository is worth extracting (has org or homepage).
 */
export async function isWorthExtracting(owner: string, repo: string): Promise<boolean> {
  const [orgInfo, repoInfo] = await Promise.all([
    getOrgInfo(owner),
    getRepoInfo(owner, repo),
  ]);

  // Has organization with website
  if (orgInfo?.blog) return true;

  // Has repository homepage
  if (repoInfo?.homepage && !repoInfo.homepage.includes('github')) return true;

  return false;
}

/* -------------------------------------------------------------------------- */
/*  Default Export                                                            */
/* -------------------------------------------------------------------------- */

export default {
  extractDomainInfo,
  isWorthExtracting,
  extractDomains,
  extractEmailDomains,
  scoreDomain,
};
