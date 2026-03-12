/**
 * =============================================================================
 * MODULE: monetizationSignals.ts
 * =============================================================================
 * Detects monetization and business signals to verify ICP quality.
 *
 * Used in the WordPress pipeline to ensure leads are real businesses worth pursuing.
 *
 * Signal categories:
 *   - Payment: Stripe, PayPal, Square, Shopify Payments, WooCommerce
 *   - CRM/Marketing: HubSpot, Salesforce, Marketo, Mailchimp, ActiveCampaign
 *   - Analytics: Google Analytics (not just Tag Manager), Mixpanel, Segment
 *   - E-commerce: WooCommerce, Shopify, Magento, BigCommerce
 *   - Professional Email: Not Gmail/Yahoo/Hotmail MX records
 *   - Business Indicators: Contact forms, pricing pages, team pages
 *
 * Scoring:
 *   - HIGH (≥70): Clear monetization signals, worth immediate enrichment
 *   - MEDIUM (40-69): Some signals, may be worth slower pursuit
 *   - LOW (<40): Likely hobby/personal site, deprioritize
 * =============================================================================
 */

import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('monetizationSignals');
import dns from 'node:dns/promises';
import { httpClient } from '../net/httpClient.js';

/* -------------------------------------------------------------------------- */
/*  Types                                                                      */
/* -------------------------------------------------------------------------- */

export interface MonetizationSignal {
  category: 'payment' | 'crm' | 'marketing' | 'analytics' | 'ecommerce' | 'email' | 'business';
  name: string;
  confidence: number;  // 0-100
  source: 'html' | 'script' | 'header' | 'dns' | 'meta';
  details?: string;
}

export interface MonetizationResult {
  score: number;
  tier: 'high' | 'medium' | 'low';
  signals: MonetizationSignal[];
  hasPayment: boolean;
  hasCRM: boolean;
  hasEcommerce: boolean;
  hasProfessionalEmail: boolean;
  summary: string;
}

/* -------------------------------------------------------------------------- */
/*  Signal Patterns                                                            */
/* -------------------------------------------------------------------------- */

// Payment processors (highest value - indicates real revenue)
const PAYMENT_PATTERNS = [
  { pattern: /stripe\.com|js\.stripe\.com|checkout\.stripe\.com/i, name: 'Stripe', weight: 25 },
  { pattern: /paypal\.com|paypalobjects\.com/i, name: 'PayPal', weight: 20 },
  { pattern: /square\.com|squareup\.com/i, name: 'Square', weight: 20 },
  { pattern: /braintree-?api|braintreegateway/i, name: 'Braintree', weight: 20 },
  { pattern: /authorize\.net/i, name: 'Authorize.net', weight: 15 },
  { pattern: /2checkout|avangate/i, name: '2Checkout', weight: 15 },
  { pattern: /recurly\.com/i, name: 'Recurly', weight: 18 },
  { pattern: /chargebee\.com/i, name: 'Chargebee', weight: 18 },
  { pattern: /paddle\.com/i, name: 'Paddle', weight: 18 },
  { pattern: /gocardless\.com/i, name: 'GoCardless', weight: 15 },
];

// CRM/Sales tools (high value - indicates sales operations)
const CRM_PATTERNS = [
  { pattern: /hubspot\.com|hs-scripts\.com|hs-analytics/i, name: 'HubSpot', weight: 20 },
  { pattern: /salesforce\.com|force\.com|pardot\.com/i, name: 'Salesforce', weight: 22 },
  { pattern: /marketo\.com|mktoresp\.com|marketo\.net/i, name: 'Marketo', weight: 18 },
  { pattern: /intercom\.io|intercomcdn\.com/i, name: 'Intercom', weight: 15 },
  { pattern: /drift\.com|driftt\.com/i, name: 'Drift', weight: 12 },
  { pattern: /zendesk\.com|zdassets\.com/i, name: 'Zendesk', weight: 12 },
  { pattern: /pipedrive\.com/i, name: 'Pipedrive', weight: 15 },
  { pattern: /freshsales|freshdesk|freshworks/i, name: 'Freshworks', weight: 12 },
  { pattern: /activecampaign\.com/i, name: 'ActiveCampaign', weight: 15 },
  { pattern: /close\.com|close\.io/i, name: 'Close', weight: 15 },
];

// Marketing automation (medium value)
const MARKETING_PATTERNS = [
  { pattern: /mailchimp\.com|mc\.us|list-manage\.com/i, name: 'Mailchimp', weight: 10 },
  { pattern: /constantcontact\.com/i, name: 'Constant Contact', weight: 8 },
  { pattern: /klaviyo\.com/i, name: 'Klaviyo', weight: 12 },
  { pattern: /sendgrid\.com|sendgrid\.net/i, name: 'SendGrid', weight: 8 },
  { pattern: /mailgun\.org|mailgun\.com/i, name: 'Mailgun', weight: 6 },
  { pattern: /convertkit\.com/i, name: 'ConvertKit', weight: 10 },
  { pattern: /drip\.com/i, name: 'Drip', weight: 10 },
  { pattern: /getresponse\.com/i, name: 'GetResponse', weight: 8 },
  { pattern: /aweber\.com/i, name: 'AWeber', weight: 6 },
  { pattern: /customer\.io/i, name: 'Customer.io', weight: 12 },
];

// Analytics (confirms real traffic/business intent)
const ANALYTICS_PATTERNS = [
  { pattern: /google-analytics\.com|googletagmanager\.com.*UA-|gtag.*UA-/i, name: 'Google Analytics', weight: 8 },
  { pattern: /googletagmanager\.com.*G-|gtag.*G-/i, name: 'Google Analytics 4', weight: 10 },
  { pattern: /mixpanel\.com/i, name: 'Mixpanel', weight: 12 },
  { pattern: /segment\.com|segment\.io|cdn\.segment/i, name: 'Segment', weight: 15 },
  { pattern: /amplitude\.com/i, name: 'Amplitude', weight: 12 },
  { pattern: /heap\.io|heapanalytics/i, name: 'Heap', weight: 10 },
  { pattern: /hotjar\.com/i, name: 'Hotjar', weight: 8 },
  { pattern: /fullstory\.com/i, name: 'FullStory', weight: 10 },
  { pattern: /clarity\.ms|clarityms/i, name: 'Microsoft Clarity', weight: 5 },
  { pattern: /posthog\.com/i, name: 'PostHog', weight: 10 },
];

// E-commerce platforms (strong monetization signal)
const ECOMMERCE_PATTERNS = [
  { pattern: /woocommerce|wc-blocks|wc-api/i, name: 'WooCommerce', weight: 20 },
  { pattern: /shopify\.com|cdn\.shopify/i, name: 'Shopify', weight: 22 },
  { pattern: /magento|mage2/i, name: 'Magento', weight: 18 },
  { pattern: /bigcommerce\.com/i, name: 'BigCommerce', weight: 18 },
  { pattern: /prestashop/i, name: 'PrestaShop', weight: 15 },
  { pattern: /opencart/i, name: 'OpenCart', weight: 12 },
  { pattern: /ecwid\.com/i, name: 'Ecwid', weight: 12 },
  { pattern: /volusion/i, name: 'Volusion', weight: 10 },
  { pattern: /3dcart|shift4shop/i, name: 'Shift4Shop', weight: 10 },
  { pattern: /squarespace.*commerce|\/commerce\//i, name: 'Squarespace Commerce', weight: 15 },
];

// Business page indicators (contextual signals)
const BUSINESS_PAGE_PATTERNS = [
  { pattern: /\/pricing[\/\?]?|pricing\.html|\/plans[\/\?]?/i, name: 'Pricing Page', weight: 12 },
  { pattern: /\/contact[\/\?]?|contact-us|\/get-in-touch/i, name: 'Contact Page', weight: 5 },
  { pattern: /\/team[\/\?]?|\/about-us|\/our-team/i, name: 'Team Page', weight: 5 },
  { pattern: /\/careers[\/\?]?|\/jobs[\/\?]?|work-with-us/i, name: 'Careers Page', weight: 8 },
  { pattern: /\/demo[\/\?]?|book-a-demo|schedule-demo/i, name: 'Demo Request', weight: 15 },
  { pattern: /\/enterprise[\/\?]?|for-enterprise/i, name: 'Enterprise Page', weight: 10 },
  { pattern: /\/case-studies|\/customers[\/\?]?|\/testimonials/i, name: 'Social Proof', weight: 8 },
];

// Consumer/personal email domains (negative signal)
const CONSUMER_EMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com',
  'yahoo.com', 'yahoo.co.uk', 'ymail.com',
  'hotmail.com', 'outlook.com', 'live.com', 'msn.com',
  'aol.com',
  'icloud.com', 'me.com', 'mac.com',
  'protonmail.com', 'proton.me',
  'mail.com', 'gmx.com', 'gmx.net',
  'zoho.com',
  'yandex.com', 'yandex.ru',
  'mail.ru',
  'qq.com', '163.com', '126.com',
]);

// Business email providers (positive signal)
const BUSINESS_EMAIL_PROVIDERS = [
  { pattern: /google\.com|googlemail\.com.*aspmx/i, name: 'Google Workspace', weight: 10 },
  { pattern: /outlook\.com.*protection|microsoft\.com/i, name: 'Microsoft 365', weight: 10 },
  { pattern: /zoho\.com/i, name: 'Zoho Mail', weight: 5 },
  { pattern: /proofpoint\.com/i, name: 'Proofpoint', weight: 8 },
  { pattern: /mimecast\.com/i, name: 'Mimecast', weight: 8 },
  { pattern: /barracuda/i, name: 'Barracuda', weight: 6 },
  { pattern: /sendgrid/i, name: 'SendGrid (transactional)', weight: 3 },
];

/* -------------------------------------------------------------------------- */
/*  Signal Detection Functions                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Detect signals in HTML content
 */
function detectSignalsInHtml(html: string): MonetizationSignal[] {
  const signals: MonetizationSignal[] = [];

  // Payment
  for (const { pattern, name, weight } of PAYMENT_PATTERNS) {
    if (pattern.test(html)) {
      signals.push({
        category: 'payment',
        name,
        confidence: weight * 4,  // Scale to 100
        source: 'html',
      });
    }
  }

  // CRM
  for (const { pattern, name, weight } of CRM_PATTERNS) {
    if (pattern.test(html)) {
      signals.push({
        category: 'crm',
        name,
        confidence: weight * 4,
        source: 'html',
      });
    }
  }

  // Marketing
  for (const { pattern, name, weight } of MARKETING_PATTERNS) {
    if (pattern.test(html)) {
      signals.push({
        category: 'marketing',
        name,
        confidence: weight * 5,
        source: 'html',
      });
    }
  }

  // Analytics
  for (const { pattern, name, weight } of ANALYTICS_PATTERNS) {
    if (pattern.test(html)) {
      signals.push({
        category: 'analytics',
        name,
        confidence: weight * 5,
        source: 'html',
      });
    }
  }

  // E-commerce
  for (const { pattern, name, weight } of ECOMMERCE_PATTERNS) {
    if (pattern.test(html)) {
      signals.push({
        category: 'ecommerce',
        name,
        confidence: weight * 4,
        source: 'html',
      });
    }
  }

  // Business page indicators
  for (const { pattern, name, weight } of BUSINESS_PAGE_PATTERNS) {
    if (pattern.test(html)) {
      signals.push({
        category: 'business',
        name,
        confidence: weight * 5,
        source: 'html',
      });
    }
  }

  return signals;
}

/**
 * Check MX records for professional email
 */
async function checkEmailInfrastructure(domain: string): Promise<MonetizationSignal[]> {
  const signals: MonetizationSignal[] = [];

  try {
    const mxRecords = await dns.resolveMx(domain);
    if (!mxRecords || mxRecords.length === 0) {
      return signals;
    }

    const mxHosts = mxRecords.map(r => r.exchange.toLowerCase()).join(' ');

    // Check for business email providers
    let foundBusinessEmail = false;
    for (const { pattern, name, weight } of BUSINESS_EMAIL_PROVIDERS) {
      if (pattern.test(mxHosts)) {
        signals.push({
          category: 'email',
          name: `Business Email (${name})`,
          confidence: weight * 8,
          source: 'dns',
          details: mxRecords[0].exchange,
        });
        foundBusinessEmail = true;
        break;  // Only count once
      }
    }

    // Check if MX is self-hosted (custom domain email = positive)
    if (!foundBusinessEmail) {
      const hasSelfHosted = mxRecords.some(r =>
        r.exchange.includes(domain) ||
        !CONSUMER_EMAIL_DOMAINS.has(r.exchange.split('.').slice(-2).join('.'))
      );

      if (hasSelfHosted) {
        signals.push({
          category: 'email',
          name: 'Custom Email Domain',
          confidence: 60,
          source: 'dns',
          details: mxRecords[0].exchange,
        });
      }
    }

  } catch (err) {
    // No MX records or DNS failure - not a signal either way
    log.info(`[MonetizationSignals] MX lookup failed for ${domain}: ${(err as Error).message}`);
  }

  return signals;
}

/**
 * Analyze detected tech stack for monetization signals
 */
export function analyzeExistingTechStack(
  technologies: Array<{ name: string; slug?: string; categories?: string[] }>
): MonetizationSignal[] {
  const signals: MonetizationSignal[] = [];

  for (const tech of technologies) {
    const name = tech.name.toLowerCase();
    const slug = tech.slug?.toLowerCase() || name;

    // Payment platforms
    if (/stripe|paypal|square|braintree|authorize\.net|recurly|chargebee/i.test(name)) {
      signals.push({
        category: 'payment',
        name: tech.name,
        confidence: 85,
        source: 'script',
      });
    }

    // CRM platforms
    if (/hubspot|salesforce|pardot|marketo|intercom|drift|zendesk|pipedrive/i.test(name)) {
      signals.push({
        category: 'crm',
        name: tech.name,
        confidence: 80,
        source: 'script',
      });
    }

    // E-commerce platforms
    if (/woocommerce|shopify|magento|bigcommerce|prestashop|opencart|ecwid/i.test(name)) {
      signals.push({
        category: 'ecommerce',
        name: tech.name,
        confidence: 90,
        source: 'script',
      });
    }

    // Analytics
    if (/google.*analytics|mixpanel|segment|amplitude|heap|hotjar|fullstory/i.test(name)) {
      signals.push({
        category: 'analytics',
        name: tech.name,
        confidence: 70,
        source: 'script',
      });
    }

    // Marketing
    if (/mailchimp|klaviyo|sendgrid|activecampaign|convertkit|drip|customer\.io/i.test(name)) {
      signals.push({
        category: 'marketing',
        name: tech.name,
        confidence: 65,
        source: 'script',
      });
    }
  }

  return signals;
}

/* -------------------------------------------------------------------------- */
/*  Main Detection Function                                                    */
/* -------------------------------------------------------------------------- */

const TIMEOUT_MS = parseInt(process.env.MONETIZATION_TIMEOUT_MS || '10000', 10);
const TIER_THRESHOLDS = {
  HIGH: 70,
  MEDIUM: 40,
};

/**
 * Detect monetization signals for a domain
 */
export async function detectMonetizationSignals(
  domain: string,
  options?: {
    existingTechStack?: Array<{ name: string; slug?: string; categories?: string[] }>;
    skipHtmlFetch?: boolean;
    existingHtml?: string;
  }
): Promise<MonetizationResult> {
  const signals: MonetizationSignal[] = [];

  // 1. Analyze existing tech stack if provided
  if (options?.existingTechStack && options.existingTechStack.length > 0) {
    const techSignals = analyzeExistingTechStack(options.existingTechStack);
    signals.push(...techSignals);
  }

  // 2. Fetch and analyze HTML (unless skipped or provided)
  if (!options?.skipHtmlFetch) {
    let html = options?.existingHtml;

    if (!html) {
      try {
        const response = await httpClient.get(`https://${domain}`, {
          timeout: TIMEOUT_MS,
          maxRedirects: 3,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
          },
        });
        html = typeof response.data === 'string' ? response.data : '';
      } catch (err) {
        log.info(`[MonetizationSignals] Failed to fetch ${domain}: ${(err as Error).message}`);
      }
    }

    if (html) {
      const htmlSignals = detectSignalsInHtml(html);
      signals.push(...htmlSignals);
    }
  }

  // 3. Check email infrastructure
  const emailSignals = await checkEmailInfrastructure(domain);
  signals.push(...emailSignals);

  // Deduplicate signals by category+name
  const seen = new Set<string>();
  const uniqueSignals = signals.filter(s => {
    const key = `${s.category}:${s.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Calculate score from weighted signals
  let score = 0;
  for (const signal of uniqueSignals) {
    // Different categories have different base weights
    const categoryMultiplier = {
      payment: 1.2,
      ecommerce: 1.1,
      crm: 1.0,
      marketing: 0.7,
      analytics: 0.5,
      email: 0.8,
      business: 0.4,
    }[signal.category] || 0.5;

    score += (signal.confidence / 100) * 25 * categoryMultiplier;
  }

  // Cap at 100
  score = Math.min(100, Math.round(score));

  // Determine tier
  const tier: 'high' | 'medium' | 'low' =
    score >= TIER_THRESHOLDS.HIGH
      ? 'high'
      : score >= TIER_THRESHOLDS.MEDIUM
        ? 'medium'
        : 'low';

  // Compute category flags
  const hasPayment = uniqueSignals.some(s => s.category === 'payment');
  const hasCRM = uniqueSignals.some(s => s.category === 'crm');
  const hasEcommerce = uniqueSignals.some(s => s.category === 'ecommerce');
  const hasProfessionalEmail = uniqueSignals.some(s => s.category === 'email');

  // Build summary
  const topSignals = uniqueSignals
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 3)
    .map(s => s.name);

  const summary = topSignals.length > 0
    ? `${tier.toUpperCase()} confidence (${score}): ${topSignals.join(', ')}`
    : `LOW confidence (${score}): No monetization signals detected`;

  return {
    score,
    tier,
    signals: uniqueSignals,
    hasPayment,
    hasCRM,
    hasEcommerce,
    hasProfessionalEmail,
    summary,
  };
}

/**
 * Quick check without HTTP fetch (uses existing data only)
 */
export function detectMonetizationSignalsQuick(
  domain: string,
  existingTechStack: Array<{ name: string; slug?: string; categories?: string[] }>,
  hasProfessionalEmail: boolean = false
): { score: number; tier: 'high' | 'medium' | 'low'; summary: string } {
  const signals = analyzeExistingTechStack(existingTechStack);

  // Add email signal if known
  if (hasProfessionalEmail) {
    signals.push({
      category: 'email',
      name: 'Professional Email',
      confidence: 60,
      source: 'dns',
    });
  }

  let score = 0;
  for (const signal of signals) {
    const categoryMultiplier = {
      payment: 1.2,
      ecommerce: 1.1,
      crm: 1.0,
      marketing: 0.7,
      analytics: 0.5,
      email: 0.8,
      business: 0.4,
    }[signal.category] || 0.5;

    score += (signal.confidence / 100) * 25 * categoryMultiplier;
  }

  score = Math.min(100, Math.round(score));

  const tier: 'high' | 'medium' | 'low' =
    score >= TIER_THRESHOLDS.HIGH
      ? 'high'
      : score >= TIER_THRESHOLDS.MEDIUM
        ? 'medium'
        : 'low';

  const summary = signals.length > 0
    ? `${tier.toUpperCase()} (${score}): ${signals.slice(0, 2).map(s => s.name).join(', ')}`
    : `LOW (${score}): No signals`;

  return { score, tier, summary };
}

/* -------------------------------------------------------------------------- */
/*  Export                                                                     */
/* -------------------------------------------------------------------------- */

export default {
  detectMonetizationSignals,
  detectMonetizationSignalsQuick,
  analyzeExistingTechStack,
  TIER_THRESHOLDS,
};
