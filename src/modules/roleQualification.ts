/**
 * =============================================================================
 * MODULE: roleQualification.ts
 * =============================================================================
 * Filters contacts by role seniority to ensure outreach reaches decision-makers.
 *
 * Used in:
 *   - Infostealer pipeline: MUST have authority to act on credential exposure
 *   - GitHub Secrets pipeline: Prioritize security/engineering leadership
 *   - WordPress pipeline: Technical leadership preferred
 *
 * Qualification tiers:
 *   - TIER_1: Direct security authority (CISO, VP Security) - always qualify
 *   - TIER_2: Executive authority (CEO, CTO, COO) - qualify
 *   - TIER_3: Technical leadership (VP Engineering, Director IT) - qualify with caution
 *   - DISQUALIFIED: No authority roles (IT Manager, Admin) - skip or downgrade
 *
 * Why this matters:
 *   - Wrong role = panic without authority = backfire
 *   - IT Manager receives infostealer alert → can't authorize response → frustrated
 *   - CISO receives alert → has authority → takes action → grateful
 * =============================================================================
 */

import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('roleQualification');

/* -------------------------------------------------------------------------- */
/*  Types                                                                      */
/* -------------------------------------------------------------------------- */

export type QualificationTier = 'tier_1' | 'tier_2' | 'tier_3' | 'disqualified' | 'unknown';
export type QualificationStatus = 'qualified' | 'downgrade' | 'skip';

export interface RoleQualificationResult {
  status: QualificationStatus;
  tier: QualificationTier;
  matchedPattern?: string;
  priority: number;  // 1 = highest priority for contact selection
  reason: string;
}

export interface ContactForQualification {
  name?: string;
  title?: string;
  email?: string;
  seniority?: string;  // Apollo seniority field
}

/* -------------------------------------------------------------------------- */
/*  Role Patterns by Tier                                                      */
/* -------------------------------------------------------------------------- */

// Tier 1: Direct security authority - ALWAYS qualify
const TIER_1_PATTERNS = [
  { pattern: /\bCISO\b/i, name: 'CISO', priority: 1 },
  { pattern: /chief\s+(information\s+)?security\s+officer/i, name: 'Chief Information Security Officer', priority: 1 },
  { pattern: /\bCSO\b.*security/i, name: 'CSO (Security)', priority: 2 },
  { pattern: /VP[\s,]+(?:of\s+)?(?:information\s+)?security/i, name: 'VP Security', priority: 3 },
  { pattern: /VP[\s,]+(?:of\s+)?IT\s+security/i, name: 'VP IT Security', priority: 3 },
  { pattern: /vice\s+president.*security/i, name: 'Vice President Security', priority: 3 },
  { pattern: /head\s+of\s+(?:information\s+)?security/i, name: 'Head of Security', priority: 4 },
  { pattern: /director.*(?:information\s+)?security/i, name: 'Director of Security', priority: 5 },
  { pattern: /\bCTO\b/i, name: 'CTO', priority: 6 },
  { pattern: /chief\s+technolog/i, name: 'Chief Technology Officer', priority: 6 },
];

// Tier 2: Executive authority - qualify (can authorize action)
const TIER_2_PATTERNS = [
  { pattern: /\bCEO\b/i, name: 'CEO', priority: 10 },
  { pattern: /chief\s+executive/i, name: 'Chief Executive', priority: 10 },
  { pattern: /\bCOO\b/i, name: 'COO', priority: 11 },
  { pattern: /chief\s+operat/i, name: 'Chief Operating Officer', priority: 11 },
  { pattern: /\bCFO\b/i, name: 'CFO', priority: 12 },
  { pattern: /chief\s+financ/i, name: 'Chief Financial Officer', priority: 12 },
  { pattern: /\bpresident\b/i, name: 'President', priority: 13 },
  { pattern: /\bowner\b/i, name: 'Owner', priority: 14 },
  { pattern: /\bfounder\b/i, name: 'Founder', priority: 15 },
  { pattern: /\bco-?founder\b/i, name: 'Co-Founder', priority: 15 },
  { pattern: /managing\s+director/i, name: 'Managing Director', priority: 16 },
  { pattern: /general\s+manager/i, name: 'General Manager', priority: 17 },
];

// Tier 3: Technical leadership - qualify with caution
const TIER_3_PATTERNS = [
  { pattern: /VP[\s,]+(?:of\s+)?(?:information\s+)?technology/i, name: 'VP IT', priority: 20 },
  { pattern: /VP[\s,]+(?:of\s+)?IT\b/i, name: 'VP IT', priority: 20 },
  { pattern: /VP[\s,]+(?:of\s+)?engineering/i, name: 'VP Engineering', priority: 21 },
  { pattern: /vice\s+president.*(?:IT|engineering|technology)/i, name: 'VP Technical', priority: 21 },
  { pattern: /head\s+of\s+(?:IT|engineering|technology)/i, name: 'Head of IT/Engineering', priority: 22 },
  { pattern: /director.*(?:IT|engineering|technology)/i, name: 'Director IT/Engineering', priority: 23 },
  { pattern: /\bCIO\b/i, name: 'CIO', priority: 24 },
  { pattern: /chief\s+information\s+officer/i, name: 'Chief Information Officer', priority: 24 },
  { pattern: /IT\s+director/i, name: 'IT Director', priority: 25 },
  { pattern: /engineering\s+director/i, name: 'Engineering Director', priority: 25 },
  { pattern: /technology\s+director/i, name: 'Technology Director', priority: 25 },
  { pattern: /senior\s+director.*(?:IT|engineering|security)/i, name: 'Senior Director', priority: 26 },
];

// Disqualified roles - skip (no authority to act)
const DISQUALIFIED_PATTERNS = [
  { pattern: /\bIT\s+manager\b/i, name: 'IT Manager', reason: 'No authority to authorize security response' },
  { pattern: /\bIT\s+administrator\b/i, name: 'IT Administrator', reason: 'Operational role, no budget authority' },
  { pattern: /\bsystems?\s+administrator\b/i, name: 'Systems Administrator', reason: 'Operational role' },
  { pattern: /\bnetwork\s+administrator\b/i, name: 'Network Administrator', reason: 'Operational role' },
  { pattern: /\bsecurity\s+analyst\b/i, name: 'Security Analyst', reason: 'Analyst role, no authority' },
  { pattern: /\bsecurity\s+engineer\b/i, name: 'Security Engineer', reason: 'IC role, may escalate but no authority' },
  { pattern: /\boperations\s+manager\b/i, name: 'Operations Manager', reason: 'Wrong domain' },
  { pattern: /\bHR\s+manager\b/i, name: 'HR Manager', reason: 'Wrong domain entirely' },
  { pattern: /\boffice\s+manager\b/i, name: 'Office Manager', reason: 'Wrong domain' },
  { pattern: /\bmarketing\s+manager\b/i, name: 'Marketing Manager', reason: 'Wrong domain' },
  { pattern: /\bsales\s+manager\b/i, name: 'Sales Manager', reason: 'Wrong domain' },
  { pattern: /\brecruiter\b/i, name: 'Recruiter', reason: 'Wrong domain' },
  { pattern: /\bintern\b/i, name: 'Intern', reason: 'No authority' },
  { pattern: /\bjunior\b/i, name: 'Junior', reason: 'No authority' },
  { pattern: /\bassistant\b/i, name: 'Assistant', reason: 'No authority' },
  { pattern: /\bcoordinator\b/i, name: 'Coordinator', reason: 'No authority' },
  { pattern: /\bspecialist\b/i, name: 'Specialist', reason: 'IC role, no authority' },
  { pattern: /\banalyst\b/i, name: 'Analyst', reason: 'IC role, no authority' },
  { pattern: /\bsupport\b/i, name: 'Support', reason: 'Operational role' },
  { pattern: /\bhelpdesk\b/i, name: 'Helpdesk', reason: 'Operational role' },
  { pattern: /\btechnician\b/i, name: 'Technician', reason: 'Operational role' },
];

/* -------------------------------------------------------------------------- */
/*  Seniority Level Mapping (Apollo)                                           */
/* -------------------------------------------------------------------------- */

// Apollo seniority field values and their tier mapping
const SENIORITY_TIERS: Record<string, QualificationTier> = {
  'c_suite': 'tier_2',
  'vp': 'tier_3',
  'director': 'tier_3',
  'manager': 'disqualified',  // Managers typically don't have authority
  'senior': 'disqualified',   // Senior IC
  'entry': 'disqualified',
  'intern': 'disqualified',
  'partner': 'tier_2',        // Partners often have authority
  'owner': 'tier_2',
};

/* -------------------------------------------------------------------------- */
/*  Main Qualification Function                                                */
/* -------------------------------------------------------------------------- */

/**
 * Qualify a contact's role for outreach eligibility.
 *
 * @param title - Job title to evaluate
 * @param seniority - Optional Apollo seniority level
 * @returns Qualification result with status, tier, and priority
 */
export function qualifyRole(title: string | undefined, seniority?: string): RoleQualificationResult {
  if (!title || title.trim() === '') {
    return {
      status: 'skip',
      tier: 'unknown',
      priority: 999,
      reason: 'No title provided',
    };
  }

  const normalizedTitle = title.trim();

  // Check Tier 1 (highest priority - security leadership)
  for (const { pattern, name, priority } of TIER_1_PATTERNS) {
    if (pattern.test(normalizedTitle)) {
      return {
        status: 'qualified',
        tier: 'tier_1',
        matchedPattern: name,
        priority,
        reason: `Security leadership: ${name}`,
      };
    }
  }

  // Check Tier 2 (executive authority)
  for (const { pattern, name, priority } of TIER_2_PATTERNS) {
    if (pattern.test(normalizedTitle)) {
      return {
        status: 'qualified',
        tier: 'tier_2',
        matchedPattern: name,
        priority,
        reason: `Executive authority: ${name}`,
      };
    }
  }

  // Check Tier 3 (technical leadership)
  for (const { pattern, name, priority } of TIER_3_PATTERNS) {
    if (pattern.test(normalizedTitle)) {
      return {
        status: 'qualified',
        tier: 'tier_3',
        matchedPattern: name,
        priority,
        reason: `Technical leadership: ${name}`,
      };
    }
  }

  // Check disqualified patterns
  for (const { pattern, name, reason } of DISQUALIFIED_PATTERNS) {
    if (pattern.test(normalizedTitle)) {
      return {
        status: 'skip',
        tier: 'disqualified',
        matchedPattern: name,
        priority: 999,
        reason: `Disqualified: ${reason}`,
      };
    }
  }

  // Fall back to Apollo seniority if available
  if (seniority) {
    const seniorityTier = SENIORITY_TIERS[seniority.toLowerCase()];
    if (seniorityTier) {
      if (seniorityTier === 'tier_2') {
        return {
          status: 'qualified',
          tier: 'tier_2',
          matchedPattern: `seniority:${seniority}`,
          priority: 50,
          reason: `Apollo seniority: ${seniority}`,
        };
      } else if (seniorityTier === 'tier_3') {
        return {
          status: 'qualified',
          tier: 'tier_3',
          matchedPattern: `seniority:${seniority}`,
          priority: 60,
          reason: `Apollo seniority: ${seniority}`,
        };
      } else if (seniorityTier === 'disqualified') {
        return {
          status: 'skip',
          tier: 'disqualified',
          matchedPattern: `seniority:${seniority}`,
          priority: 999,
          reason: `Apollo seniority too low: ${seniority}`,
        };
      }
    }
  }

  // Unknown role - conservative skip (can be overridden with 'downgrade')
  return {
    status: 'skip',
    tier: 'unknown',
    priority: 999,
    reason: `Unknown role: "${title}"`,
  };
}

/**
 * Find the best qualified contact from a list.
 *
 * @param contacts - Array of contacts to evaluate
 * @returns Best contact or null if none qualify
 */
export function findBestContact(contacts: ContactForQualification[]): {
  contact: ContactForQualification;
  qualification: RoleQualificationResult;
} | null {
  if (!contacts || contacts.length === 0) {
    return null;
  }

  const qualified: Array<{
    contact: ContactForQualification;
    qualification: RoleQualificationResult;
  }> = [];

  for (const contact of contacts) {
    const qualification = qualifyRole(contact.title, contact.seniority);
    if (qualification.status === 'qualified') {
      qualified.push({ contact, qualification });
    }
  }

  if (qualified.length === 0) {
    return null;
  }

  // Sort by priority (lower = better)
  qualified.sort((a, b) => a.qualification.priority - b.qualification.priority);

  return qualified[0];
}

/**
 * Filter contacts to only qualified ones, sorted by priority.
 *
 * @param contacts - Array of contacts to filter
 * @returns Qualified contacts sorted by priority
 */
export function filterQualifiedContacts(contacts: ContactForQualification[]): Array<{
  contact: ContactForQualification;
  qualification: RoleQualificationResult;
}> {
  if (!contacts || contacts.length === 0) {
    return [];
  }

  const qualified: Array<{
    contact: ContactForQualification;
    qualification: RoleQualificationResult;
  }> = [];

  for (const contact of contacts) {
    const qualification = qualifyRole(contact.title, contact.seniority);
    if (qualification.status === 'qualified') {
      qualified.push({ contact, qualification });
    }
  }

  // Sort by priority (lower = better)
  qualified.sort((a, b) => a.qualification.priority - b.qualification.priority);

  return qualified;
}

/**
 * Check if ANY contacts in a list are qualified.
 * Useful for quick pre-check before expensive operations.
 */
export function hasQualifiedContact(contacts: ContactForQualification[]): boolean {
  if (!contacts || contacts.length === 0) {
    return false;
  }

  for (const contact of contacts) {
    const qualification = qualifyRole(contact.title, contact.seniority);
    if (qualification.status === 'qualified') {
      return true;
    }
  }

  return false;
}

/**
 * Get qualification stats for a batch of contacts.
 */
export function getQualificationStats(contacts: ContactForQualification[]): {
  total: number;
  qualified: number;
  tier1: number;
  tier2: number;
  tier3: number;
  disqualified: number;
  unknown: number;
} {
  const stats = {
    total: contacts.length,
    qualified: 0,
    tier1: 0,
    tier2: 0,
    tier3: 0,
    disqualified: 0,
    unknown: 0,
  };

  for (const contact of contacts) {
    const qualification = qualifyRole(contact.title, contact.seniority);
    if (qualification.status === 'qualified') {
      stats.qualified++;
    }
    switch (qualification.tier) {
      case 'tier_1':
        stats.tier1++;
        break;
      case 'tier_2':
        stats.tier2++;
        break;
      case 'tier_3':
        stats.tier3++;
        break;
      case 'disqualified':
        stats.disqualified++;
        break;
      case 'unknown':
        stats.unknown++;
        break;
    }
  }

  return stats;
}

/* -------------------------------------------------------------------------- */
/*  Export                                                                     */
/* -------------------------------------------------------------------------- */

export default {
  qualifyRole,
  findBestContact,
  filterQualifiedContacts,
  hasQualifiedContact,
  getQualificationStats,
  TIER_1_PATTERNS,
  TIER_2_PATTERNS,
  TIER_3_PATTERNS,
  DISQUALIFIED_PATTERNS,
  SENIORITY_TIERS,
};
