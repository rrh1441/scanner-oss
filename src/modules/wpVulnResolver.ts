/* =============================================================================
 * MODULE: wpVulnResolver.ts
 * =============================================================================
 * Fast, keyless WordPress plugin vulnerability resolver for Tier-1.
 * - Consumes `wordpress_plugin_inventory` artifact from wpPluginQuickScan
 * - Queries NVD CVE API (free) per plugin slug with heuristic filters
 * - Attempts version-range evaluation from NVD configurations
 * - Emits vulnerability artifacts and a summary; caches in-memory per run
 * =============================================================================
 */

import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { httpClient } from '../net/httpClient.js';
import { request } from 'undici';
import { createModuleLogger } from '../core/logger.js';
import { Severity } from '../core/types.js';
import semver from 'semver';
import { getEpssScores } from '../util/epss.js';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';

const log = createModuleLogger('wpVulnResolver');

interface RunJob { scanId: string; domain: string; }

interface InventoryPlugin { slug: string; version?: string | null; evidence?: string[]; confirmed_via_readme?: boolean; }

interface NvdCveItem {
  cve?: { id?: string; }
  id?: string; // some responses use top-level id
  vulnerabilities?: any[]; // wrapper form (NVD v2 top-level)
}

interface NvdResponse {
  vulnerabilities?: Array<{
    cve: {
      id: string;
      sourceIdentifier?: string;
      published?: string;
      lastModified?: string;
      descriptions?: Array<{ lang: string; value: string }>;
      metrics?: any;
      references?: Array<{ url: string; tags?: string[] }>;
      configurations?: {
        nodes?: Array<{
          cpeMatch?: Array<{
            vulnerable?: boolean;
            criteria?: string; // CPE 2.3 URI
            versionStartIncluding?: string;
            versionStartExcluding?: string;
            versionEndIncluding?: string;
            versionEndExcluding?: string;
          }>;
        }>;
      };
    };
  }>;
}

// In-memory TTL cache (per process)
const CACHE_TTL_MS = Number(process.env.WP_VULN_CACHE_TTL_MS || 7 * 24 * 60 * 60 * 1000); // 7 days
const nvdCache = new Map<string, { ts: number; data: NvdResponse | null }>();
const osvCache = new Map<string, { ts: number; data: OsvVuln[] | null }>();
const DISK_CACHE_FILE = process.env.WP_VULN_CACHE_FILE || path.join('scan-artifacts', 'wpvuln-cache.json');

type DiskCache = {
  ts: number;
  nvd: Record<string, { ts: number; data: NvdResponse | null }>;
  osv: Record<string, { ts: number; data: OsvVuln[] | null }>;
};

async function loadDiskCache(): Promise<void> {
  try {
    const data = await fs.readFile(DISK_CACHE_FILE, 'utf-8');
    const parsed = JSON.parse(data) as DiskCache;
    const now = Date.now();
    // Rehydrate if within TTL (per-entry)
    for (const [k, v] of Object.entries(parsed.nvd || {})) {
      if (now - v.ts < CACHE_TTL_MS) nvdCache.set(k, v);
    }
    for (const [k, v] of Object.entries(parsed.osv || {})) {
      if (now - v.ts < CACHE_TTL_MS) osvCache.set(k, v);
    }
  } catch {
    // ignore
  }
}

async function saveDiskCache(): Promise<void> {
  try {
    // Ensure directory exists
    await fs.mkdir(path.dirname(DISK_CACHE_FILE), { recursive: true });
    const out: DiskCache = { ts: Date.now(), nvd: {}, osv: {} };
    for (const [k, v] of nvdCache.entries()) out.nvd[k] = v;
    for (const [k, v] of osvCache.entries()) out.osv[k] = v;
    await fs.writeFile(DISK_CACHE_FILE, JSON.stringify(out, null, 2), 'utf-8');
  } catch {
    // ignore
  }
}

function mapCvssToSeverity(score?: number): Severity {
  if (!score && score !== 0) return 'MEDIUM';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

function normalizeSlugVariants(slug: string): string[] {
  const s = slug.trim();
  const variants = new Set<string>([s, s.replace(/-/g, '_'), s.replace(/_/g, '-')]);
  return Array.from(variants);
}

function coerceVersion(v?: string | null): semver.SemVer | null {
  if (!v) return null;
  const c = semver.coerce(v);
  return c || null;
}

function versionInRange(target: string | null | undefined, startInc?: string, startExc?: string, endInc?: string, endExc?: string): boolean | null {
  const tv = coerceVersion(target || undefined);
  if (!tv) return null; // unknown

  const geStart = startInc ? semver.gte(tv, semver.coerce(startInc) || tv) : startExc ? semver.gt(tv, semver.coerce(startExc) || tv) : true;
  const leEnd = endInc ? semver.lte(tv, semver.coerce(endInc) || tv) : endExc ? semver.lt(tv, semver.coerce(endExc) || tv) : true;
  return geStart && leEnd;
}

function extractCvssV3Score(cve: any): number | undefined {
  const m = cve.metrics;
  if (!m) return undefined;
  const v3 = m.cvssMetricV31?.[0] || m.cvssMetricV30?.[0];
  return v3?.cvssData?.baseScore || v3?.baseScore;
}

function cpeLooksLikePlugin(criteria: string, slugVariants: string[]): boolean {
  // Strict matching: vendor or product must match slug variant exactly (not substring)
  // CPE format: "cpe:2.3:a:<vendor>:<product>:<version>:..."
  const parts = criteria.split(':');
  if (parts.length < 6) return false;
  const vendor = (parts[3] || '').toLowerCase();
  const product = (parts[4] || '').toLowerCase();

  // Normalize product name (remove common suffixes/prefixes)
  const productNormalized = product
    .replace(/_/g, '-')
    .replace(/-plugin$/, '')
    .replace(/-for-wordpress$/, '')
    .replace(/^wordpress-/, '');

  return slugVariants.some(v => {
    const slug = v.toLowerCase();
    const slugNormalized = slug.replace(/_/g, '-');
    // Exact match on vendor or product (not substring match)
    return vendor === slug ||
           vendor === slugNormalized ||
           product === slug ||
           product === slugNormalized ||
           productNormalized === slug ||
           productNormalized === slugNormalized;
  });
}

function descriptionMentionsSlug(descs: Array<{ lang: string; value: string }> | undefined, slugVariants: string[]): boolean {
  if (!descs) return false;
  const text = descs.map(d => d.value.toLowerCase()).join(' \n ');
  return slugVariants.some(v => text.includes(v.toLowerCase()));
}

/**
 * Extract the actual plugin name from a CVE description.
 * NVD descriptions typically follow patterns like:
 * - "The Plugin Name plugin for WordPress is vulnerable..."
 * - "The Plugin Name – Extra Info plugin for WordPress..."
 * - "Plugin Name for WordPress before 1.2.3 allows..."
 */
function extractPluginNameFromDescription(descs: Array<{ lang: string; value: string }> | undefined): string | null {
  if (!descs) return null;
  const text = descs.find(d => d.lang === 'en')?.value || descs[0]?.value || '';

  // Pattern 1: "The <plugin name> plugin for WordPress"
  const match1 = text.match(/^The\s+(.+?)\s+plugin\s+for\s+WordPress/i);
  if (match1) {
    // Clean up: remove version info, extra dashes, etc.
    return match1[1]
      .replace(/\s*[-–—]\s*.*$/, '')  // Remove anything after dash
      .replace(/\s+(?:FREE|Pro|Premium|Starter|Starter|Starter)$/i, '')  // Remove edition suffixes
      .trim()
      .toLowerCase();
  }

  // Pattern 2: "<plugin name> for WordPress before/through/up to"
  const match2 = text.match(/^(.+?)\s+for\s+WordPress\s+(?:before|through|up\s+to)/i);
  if (match2) {
    return match2[1]
      .replace(/\s*[-–—]\s*.*$/, '')
      .trim()
      .toLowerCase();
  }

  return null;
}

/**
 * Check if the extracted plugin name matches our slug variants.
 * This catches cases where description mentions "Elementor" but the actual
 * plugin is "Best Addons For Elementor" or "Elementor Contact Form Builder".
 */
function pluginNameMatchesSlug(pluginName: string | null, slugVariants: string[]): boolean {
  if (!pluginName) return true; // Can't determine, allow through for other checks

  const normalized = pluginName
    .replace(/[_-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  return slugVariants.some(slug => {
    const slugNorm = slug.replace(/[_-]/g, ' ').toLowerCase();
    // Exact match or plugin name IS the slug (not just contains it)
    return normalized === slugNorm ||
           normalized === slugNorm + ' page builder' ||
           normalized === slugNorm + ' website builder' ||
           normalized.startsWith(slugNorm + ' ') === false && normalized.endsWith(' ' + slugNorm) === false;
  });
}

/**
 * Stricter check: does the CVE description clearly name a DIFFERENT plugin?
 * Returns true if we should SKIP this CVE (it's for a different plugin).
 */
function descriptionNamesOtherPlugin(descs: Array<{ lang: string; value: string }> | undefined, slugVariants: string[]): boolean {
  const extractedName = extractPluginNameFromDescription(descs);
  if (!extractedName) return false; // Can't determine, don't skip

  const extractedNormalized = extractedName.replace(/[_-]/g, ' ').replace(/\s+/g, ' ').trim();

  // Check if the extracted plugin name contains our slug as a SUFFIX or PART of a longer name
  // e.g., "best addons for elementor" contains "elementor" but IS NOT the elementor plugin
  for (const slug of slugVariants) {
    const slugNorm = slug.replace(/[_-]/g, ' ').toLowerCase();

    // If extracted name equals our slug, it's a match (don't skip)
    if (extractedNormalized === slugNorm) return false;
    if (extractedNormalized === slugNorm + ' page builder') return false;
    if (extractedNormalized === slugNorm + ' website builder') return false;

    // If extracted name contains our slug as part of a longer plugin name, skip it
    // e.g., "best addons for elementor", "elementor contact form builder", "droit elementor addons"
    if (extractedNormalized.includes(slugNorm) && extractedNormalized !== slugNorm) {
      return true; // It's a different plugin that happens to mention our slug
    }
  }

  return false;
}

async function queryNvdForSlug(slug: string): Promise<NvdResponse | null> {
  const ck = slug.toLowerCase();
  const cached = nvdCache.get(ck);
  const now = Date.now();
  if (cached && now - cached.ts < CACHE_TTL_MS) {
    log.info(`Using cached NVD result for ${slug} (${cached.data ? 'hits' : 'no hits'})`);
    return cached.data;
  }
  log.info(`Querying NVD for slug: ${slug} (not in cache)`);
  const base = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  const headers: Record<string, string> = {
    'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
    'Accept': 'application/json'
  };
  const apiKey = process.env.NVD_API_KEY?.trim();
  if (apiKey) headers['apiKey'] = apiKey;

  // Build keyword attempts: primary + known hints
  const slugLower = slug.toLowerCase();
  const primary = `${slug} wordpress plugin`;
  const niceSlug = slugLower.replace(/[-_]+/g, ' ');
  const SLUG_NVD_HINTS: Record<string, string[]> = {
    'woocommerce': ['woocommerce', 'automattic woocommerce'],
    'yoast-seo': ['yoast seo', 'yoast wordpress seo'],
    'contact-form-7': ['contact form 7'],
    'elementor': ['elementor website builder', 'elementor'],
    'wordfence': ['wordfence security', 'defiant wordfence'],
    'wpforms-lite': ['wpforms', 'wpforms lite'],
    'all-in-one-wp-migration': ['all-in-one wp migration', 'servmask all-in-one wp migration'],
    'slider-revolution': ['slider revolution', 'revslider', 'themepunch slider revolution'],
    'revslider': ['slider revolution', 'revslider', 'themepunch slider revolution'],
    'ninja-forms': ['ninja forms'],
    'wp-fastest-cache': ['wp fastest cache'],
    'all-in-one-seo-pack': ['all in one seo', 'aioseo', 'semper plugins all in one seo'],
    'nextgen-gallery': ['nextgen gallery', 'imagely nextgen'],
    'wp-super-cache': ['wp super cache', 'automattic wp super cache'],
    'duplicator': ['duplicator plugin', 'snapcreek duplicator'],
    'jetpack': ['automattic jetpack', 'jetpack plugin']
  };
  const hints = [primary, niceSlug, ...(SLUG_NVD_HINTS[slugLower] || [])];

  const aggregate: any[] = [];
  const seen = new Set<string>();

  for (const key of hints.slice(0, 4)) {
    try {
      const keyword = encodeURIComponent(key);
      const url = `${base}?keywordSearch=${keyword}&resultsPerPage=200`;

      // Use undici directly to avoid httpClient issues with NVD
      log.info(`Querying NVD: ${url.substring(0, 100)}...`);
      const { statusCode, body, headers: respHeaders } = await request(url, {
        method: 'GET',
        headers,
        bodyTimeout: 10000,
        headersTimeout: 10000
      });

      if (statusCode !== 200) {
        log.info(`NVD query failed for "${key}": HTTP ${statusCode}`);
        log.info(`Response headers: ${JSON.stringify(respHeaders)}`);
        continue;
      }
      log.info(`NVD returned ${statusCode} OK`);

      const chunks: Buffer[] = [];
      for await (const chunk of body) {
        chunks.push(chunk);
      }
      const responseText = Buffer.concat(chunks).toString('utf-8');
      const data: NvdResponse = JSON.parse(responseText);

      const items = data?.vulnerabilities || [];
      for (const it of items) {
        const id = it?.cve?.id;
        if (!id || seen.has(id)) continue;
        seen.add(id);
        aggregate.push(it);
      }
      if (aggregate.length >= 1) break; // stop early once we have hits
    } catch (e: any) {
      log.info(`NVD query error for "${key}": ${e.message}`);
      // continue to next hint
    }
  }

  if (aggregate.length) {
    const data: NvdResponse = { vulnerabilities: aggregate };
    nvdCache.set(ck, { ts: now, data });
    return data;
  }

  nvdCache.set(ck, { ts: now, data: null });
  return null;
}

// ──────────────────────────────────────────────────────────────────────────────
// OSV batch integration (best-effort; no API key required)
// ──────────────────────────────────────────────────────────────────────────────

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version?: string;
}

interface OsvBatchRequest { queries: OsvQuery[] }

interface OsvVuln {
  id: string; // may be GHSA-... or CVE-...
  summary?: string;
  details?: string;
  aliases?: string[]; // CVE ids often here
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{
      type?: string; // e.g., ECOSYSTEM
      events?: Array<{ introduced?: string; fixed?: string }>
    }>;
  }>;
  references?: Array<{ type?: string; url: string }>;
}

interface OsvBatchResponse { results: Array<{ vulns?: OsvVuln[] }>; }

const OSV_ECOSYSTEM_CANDIDATES = ['WordPress', 'wordpress'];

function osvScoreToNumber(v?: Array<{ type: string; score: string }>): number | undefined {
  if (!v || !v.length) return undefined;
  const cvss = v.find(s => (s.type || '').toUpperCase().startsWith('CVSS'));
  if (!cvss?.score) return undefined;
  const n = Number(cvss.score);
  return Number.isFinite(n) ? n : undefined;
}

function versionAffectedByOsvRanges(version: string | null, affected?: OsvVuln['affected']): boolean | null {
  if (!version || !affected) return null; // unknown
  const tv = coerceVersion(version);
  if (!tv) return null;
  for (const a of affected) {
    for (const r of a.ranges || []) {
      const events = r.events || [] as Array<{introduced?: string; fixed?: string}>;
      let introduced: string | null = null;
      for (const ev of events) {
        if (ev.introduced !== undefined) {
          introduced = ev.introduced; // may be '0'
          continue;
        }
        if (ev.fixed !== undefined) {
          const inRange = versionInRange(version, introduced || undefined, undefined, undefined, ev.fixed || undefined);
          if (inRange) return true;
          introduced = null;
        }
      }
      if (introduced !== null) {
        const inRange = versionInRange(version, introduced || undefined, undefined, undefined, undefined);
        if (inRange) return true;
      }
    }
  }
  return false;
}

async function queryOsvBatch(plugins: InventoryPlugin[]): Promise<Map<string, OsvVuln[]>> {
  const out = new Map<string, OsvVuln[]>();
  if (!plugins.length) return out;
  const queries: OsvQuery[] = [];
  const order: Array<{ slug: string }>[] = [] as any;
  const seen = new Set<string>();
  const now = Date.now();
  for (const p of plugins.slice(0, 100)) {
    const ver = p.version || undefined;
    const row: Array<{ slug: string }> = [];
    for (const eco of OSV_ECOSYSTEM_CANDIDATES) {
      const key = `${eco}:${p.slug}:${ver || ''}`.toLowerCase();
      if (seen.has(key)) { row.push({ slug: p.slug }); continue; }
      seen.add(key);
      // cache check per slug+ver
      const cacheKey = `${p.slug}:${ver || ''}`.toLowerCase();
      const cached = osvCache.get(cacheKey);
      if (cached && now - cached.ts < CACHE_TTL_MS) {
        if (cached.data && cached.data.length) out.set(p.slug, cached.data);
        row.push({ slug: p.slug });
        continue;
      }
      const q: OsvQuery = { package: { name: p.slug, ecosystem: eco } };
      if (ver) q.version = ver;
      queries.push(q);
      row.push({ slug: p.slug });
    }
    order.push(row);
  }
  if (queries.length === 0) return out;
  try {
    const res = await httpClient.post<OsvBatchResponse>('https://api.osv.dev/v1/querybatch', { queries } as OsvBatchRequest, { timeout: 7000 } as any);
    if (res.status === 200 && res.data && Array.isArray(res.data.results)) {
      let idx = 0;
      for (const row of order) {
        let merged: OsvVuln[] = [];
        for (let i = 0; i < row.length; i++) {
          const r = res.data.results[idx++];
          if (r?.vulns?.length) merged = merged.concat(r.vulns);
        }
        const slug = row[0].slug;
        if (merged.length) {
          out.set(slug, merged);
          const cacheKey = `${slug}:${plugins.find(p => p.slug === slug)?.version || ''}`.toLowerCase();
          osvCache.set(cacheKey, { ts: now, data: merged });
        } else {
          const cacheKey = `${slug}:${plugins.find(p => p.slug === slug)?.version || ''}`.toLowerCase();
          osvCache.set(cacheKey, { ts: now, data: [] });
        }
      }
    }
  } catch (e) {
    // best-effort only
  }
  return out;
}

async function getInventoryPlugins(scanId: string): Promise<InventoryPlugin[]> {
  try {
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();
    const result = await store.query<any>(
      'SELECT metadata FROM artifacts WHERE scan_id = $1 AND type = $2',
      [scanId, 'wordpress_plugin_inventory']
    );
    const out: InventoryPlugin[] = [];
    for (const row of result.rows) {
      const plugins = row.metadata?.plugins || [];
      for (const p of plugins) {
        if (p?.slug) out.push({ slug: String(p.slug), version: p.version || undefined, evidence: p.evidence || [], confirmed_via_readme: !!p.confirmed_via_readme });
      }
    }
    return out;
  } catch (e) {
    log.info({ err: e as Error }, 'Failed to load plugin inventory');
    return [];
  }
}

export async function runWpVulnResolver(job: RunJob): Promise<number> {
  const { scanId, domain } = job;
  const start = Date.now();
  log.info(`START scan_id=${scanId} domain=${domain}`);

  await loadDiskCache();

  const inventory = await getInventoryPlugins(scanId);
  if (inventory.length === 0) {
    log.info('No plugin inventory found; skipping');
    return 0;
  }

  // Deduplicate by slug; keep a representative version if present
  const bySlug = new Map<string, InventoryPlugin>();
  for (const p of inventory) {
    if (!bySlug.has(p.slug)) bySlug.set(p.slug, p);
    else if (!bySlug.get(p.slug)!.version && p.version) bySlug.get(p.slug)!.version = p.version;
  }
  const plugins = Array.from(bySlug.values());

  // NVD stage (concurrency)
  const limit = Number(process.env.WP_VULN_RESOLVER_CONCURRENCY || '4');
  let totalFindings = 0;
  const queue = plugins.slice();
  const emittedBySlug = new Map<string, Set<string>>();

  async function nvdWorker(): Promise<void> {
    while (queue.length) {
      const item = queue.shift();
      if (!item) break;
      try {
        const set = emittedBySlug.get(item.slug) || new Set<string>();
        emittedBySlug.set(item.slug, set);
        const findings = await resolvePluginNvd(scanId, item, set);
        totalFindings += findings;
      } catch (e) {
        log.info(`Resolver error (NVD) for ${item.slug}: ${(e as Error).message}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(limit, plugins.length) }, () => nvdWorker()));

  // OSV batch stage
  try {
    const osvMap = await queryOsvBatch(plugins);
    totalFindings += await resolveOsvFindings(scanId, plugins, osvMap, emittedBySlug);
  } catch (e) {
    log.info({ err: e as Error }, 'OSV batch stage error');
  }

  // WordPress.org readme/changelog heuristics for plugins without hits
  try {
    totalFindings += await resolveWordPressOrgHeuristics(scanId, plugins, emittedBySlug);
  } catch (e) {
    log.info({ err: e as Error }, 'WP.org heuristics stage error');
  }

  await saveDiskCache();

  await insertArtifact({
    type: 'scan_summary',
    val_text: `WP plugin vulnerability resolution complete – ${totalFindings} finding(s)`,
    severity: totalFindings ? 'HIGH' : 'INFO',
    meta: { scan_id: scanId, scan_module: 'wpVulnResolver', plugins_checked: plugins.length, duration_ms: Date.now() - start, sources: ['NVD','OSV'] }
  });

  log.info(`COMPLETE findings=${totalFindings} duration_ms=${Date.now() - start}`);
  return totalFindings;
}

async function resolvePluginNvd(scanId: string, plugin: InventoryPlugin, dedup: Set<string>): Promise<number> {
  const slug = plugin.slug;
  const slugVariants = normalizeSlugVariants(slug);
  const version = plugin.version || null;

  const nvd = await queryNvdForSlug(slug);
  if (!nvd?.vulnerabilities || nvd.vulnerabilities.length === 0) return 0;

  let findings = 0;
  for (const v of nvd.vulnerabilities) {
    const cve = v.cve;
    const cveId = cve.id;
    if (dedup.has(cveId)) continue;
    // Quick screen: description must mention slug variant
    if (!descriptionMentionsSlug(cve.descriptions, slugVariants)) continue;

    // Skip if description clearly names a DIFFERENT plugin (e.g., "Best Addons For Elementor")
    if (descriptionNamesOtherPlugin(cve.descriptions, slugVariants)) continue;

    // Version gating using configurations when possible
    let affected: boolean | null = null; // null = unknown
    let hasCpeConfigs = false;  // Track if CPE data exists at all
    let foundMatchingCpe = false;  // Track if any CPE matched our plugin

    // NVD configurations is an array of config objects, each with a nodes array
    const configs = cve.configurations || [];
    const configNodes = (configs as any[]).flatMap((c: any) => c.nodes || []);
    for (const node of configNodes) {
      for (const m of node.cpeMatch || []) {
        if (m.vulnerable !== false && m.criteria) {
          hasCpeConfigs = true;
          if (cpeLooksLikePlugin(m.criteria, slugVariants)) {
            foundMatchingCpe = true;
            const inRange = versionInRange(version, m.versionStartIncluding, m.versionStartExcluding, m.versionEndIncluding, m.versionEndExcluding);
            if (inRange === null) {
              affected = affected ?? null; // unknown, keep looking
            } else if (inRange) {
              affected = true; break;
            } else {
              // Version is definitively NOT in vulnerable range - mark as not affected
              affected = false;
            }
          }
        }
      }
      if (affected === true) break;
    }

    // Decision logic:
    // 1. If we have CPE configs but NONE matched our plugin -> skip (CVE is for different plugin)
    // 2. If we have matching CPEs with version info -> use that result
    // 3. If version unknown, only flag if EPSS >= 5% (actively exploited)
    if (hasCpeConfigs && !foundMatchingCpe) {
      // CVE has CPE data but it's for a different plugin - skip
      continue;
    }

    const score = extractCvssV3Score(cve);
    // EPSS enrichment per-CVE
    let epssScore: number | undefined = undefined;
    try {
      const m = await getEpssScores([cveId]);
      epssScore = m.get(cveId);
    } catch {}

    // If version unknown (affected === null), only flag if actively exploited (EPSS >= 5%)
    if (affected === null) {
      if (epssScore !== undefined && epssScore >= 0.05) {
        affected = true; // High EPSS - worth flagging even without version confirmation
        log.info({ cveId, epss: epssScore, slug }, 'Flagging CVE without version due to high EPSS');
      } else {
        // Can't confirm vulnerability and not actively exploited - skip
        continue;
      }
    }
    if (!affected) continue;
    // Severity with EPSS bump: if EPSS >= 0.2, bump to CRITICAL; >= 0.05 bump to HIGH
    let severity: Severity = mapCvssToSeverity(score);
    if (epssScore !== undefined) {
      if (epssScore >= 0.2) severity = 'CRITICAL';
      else if (epssScore >= 0.05 && severity === 'MEDIUM') severity = 'HIGH';
    }

    const artifactId = await insertArtifact({
      type: 'vuln',
      val_text: `WP Plugin ${slug}${version ? ' ' + version : ''} - ${cveId}`,
      severity,
      meta: {
        scan_id: scanId,
        scan_module: 'wpVulnResolver',
        plugin: { slug, version },
        cve_id: cveId,
        cvss_v3: score,
        published: cve.published,
        last_modified: cve.lastModified,
        refs: (cve.references || []).map((r: any) => r.url),
        epss: epssScore
      }
    });

    await insertFinding(artifactId, 'WP_PLUGIN_VULNERABILITY', 'Update/patch the affected plugin to a non-vulnerable version immediately.', `Detected ${cveId} affecting plugin ${slug}${version ? ' v' + version : ''}.`, undefined);
    findings++;
    dedup.add(cveId);
  }
  return findings;
}

async function resolveOsvFindings(
  scanId: string,
  plugins: InventoryPlugin[],
  osvMap: Map<string, OsvVuln[]>,
  dedupBySlug: Map<string, Set<string>>
): Promise<number> {
  let findings = 0;
  for (const p of plugins) {
    const vulns = osvMap.get(p.slug) || [];
    if (!vulns.length) continue;
    const dedup = dedupBySlug.get(p.slug) || new Set<string>();
    dedupBySlug.set(p.slug, dedup);
    for (const v of vulns) {
      const cveId = (v.aliases || []).find(a => a.toUpperCase().startsWith('CVE-')) || v.id;
      if (!cveId || dedup.has(cveId)) continue;
      const affected = versionAffectedByOsvRanges(p.version || null, v.affected);
      if (affected === false) continue;
      const score = osvScoreToNumber(v.severity);
      let epssScore: number | undefined = undefined;
      try {
        const m = await getEpssScores([cveId]);
        epssScore = m.get(cveId);
      } catch {}
      let severity: Severity = mapCvssToSeverity(score);
      if (epssScore !== undefined) {
        if (epssScore >= 0.2) severity = 'CRITICAL';
        else if (epssScore >= 0.05 && severity === 'MEDIUM') severity = 'HIGH';
      }
      const artifactId = await insertArtifact({
        type: 'vuln',
        val_text: `WP Plugin ${p.slug}${p.version ? ' ' + p.version : ''} - ${cveId}`,
        severity,
        meta: {
          scan_id: scanId,
          scan_module: 'wpVulnResolver',
          plugin: { slug: p.slug, version: p.version },
          cve_id: cveId,
          osv_id: v.id,
          cvss_v3: score,
          epss: epssScore,
          refs: (v.references || []).map(r => r.url)
        }
      });
      await insertFinding(artifactId, 'WP_PLUGIN_VULNERABILITY', 'Update/patch the affected plugin to a non-vulnerable version immediately.', `Detected ${cveId} affecting plugin ${p.slug}${p.version ? ' v' + p.version : ''} (OSV).`, undefined);
      findings++;
      dedup.add(cveId);
    }
  }
  return findings;
}

export default { runWpVulnResolver };

// ──────────────────────────────────────────────────────────────────────────────
// WordPress.org readme/changelog heuristics
// ──────────────────────────────────────────────────────────────────────────────

async function fetchWpOrgReadme(slug: string): Promise<string | null> {
  const urls = [
    `https://plugins.svn.wordpress.org/${slug}/trunk/readme.txt`,
    `https://plugins.svn.wordpress.org/${slug}/readme.txt`,
    `https://wordpress.org/plugins/${slug}/`,
  ];
  for (const u of urls) {
    try {
      const res = await httpClient.get<string>(u, { timeout: 5000, responseType: 'text' } as any);
      if (res.status === 200 && typeof res.data === 'string' && res.data.length > 0) {
        return res.data;
      }
    } catch {
      // try next
    }
  }
  return null;
}

function parseReadmeSections(readme: string): Array<{ version: string; body: string }> {
  // Extract sections like "= 1.2.3 =" under Changelog or globally
  const lines = readme.split(/\r?\n/);
  const out: Array<{ version: string; body: string }> = [];
  let current: { version: string; body: string } | null = null;
  let inChangelog = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lc = line.toLowerCase();
    if (lc.includes('== changelog ==') || lc.includes('= changelog =')) {
      inChangelog = true;
      continue;
    }
    const m = line.match(/^=+\s*([0-9][0-9a-zA-Z._-]*)\s*=+\s*$/);
    if (m) {
      // start new section
      if (current) out.push(current);
      current = { version: m[1], body: '' };
      continue;
    }
    if (inChangelog && current) {
      current.body += line + '\n';
    }
  }
  if (current) out.push(current);
  return out;
}

function sectionMentionsSecurity(body: string): boolean {
  const lc = body.toLowerCase();
  return /(security|vulnerab|xss|sql injection|cve-\d{4}-\d{4,})/.test(lc);
}

function extractCveIds(body: string): string[] {
  const ids = new Set<string>();
  const re = /CVE-\d{4}-\d{4,}/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) ids.add(m[0].toUpperCase());
  return Array.from(ids);
}

async function resolveWordPressOrgHeuristics(
  scanId: string,
  plugins: InventoryPlugin[],
  dedupBySlug: Map<string, Set<string>>
): Promise<number> {
  let findings = 0;
  for (const p of plugins) {
    const existing = dedupBySlug.get(p.slug);
    if (existing && existing.size > 0) continue; // already have CVEs
    const readme = await fetchWpOrgReadme(p.slug);
    if (!readme) continue;
    const sections = parseReadmeSections(readme);
    if (sections.length === 0) continue;
    // Look for the nearest higher version section that mentions security
    const tv = coerceVersion(p.version || null);
    let best: { version: string; body: string } | null = null;
    for (const s of sections) {
      if (!sectionMentionsSecurity(s.body)) continue;
      if (!tv) { best = s; break; }
      const sv = coerceVersion(s.version);
      if (!sv) continue;
      if (semver.gt(sv, tv)) {
        if (!best) best = s;
        else if (semver.lt(coerceVersion(best.version)!, sv)) best = s; // pick closest higher
      }
    }
    if (!best) continue;
    const cves = extractCveIds(best.body);
    const severity: Severity = cves.length ? 'HIGH' : 'MEDIUM';
    const artifactId = await insertArtifact({
      type: 'vuln',
      val_text: `WP Plugin ${p.slug}${p.version ? ' ' + p.version : ''} - Security fix noted in changelog ${best.version}`,
      severity,
      meta: {
        scan_id: scanId,
        scan_module: 'wpVulnResolver',
        plugin: { slug: p.slug, version: p.version },
        heuristic: 'wordpress.org changelog',
        fixed_in: best.version,
        cve_ids: cves
      }
    });
    await insertFinding(
      artifactId,
      'WP_PLUGIN_SECURITY_CHANGELOG',
      'Update the plugin to at least the noted fixed version to address security changes.',
      `Changelog indicates security-related changes in version ${best.version}. ${cves.length ? 'CVEs: ' + cves.join(', ') : ''}`
    );
    findings++;
    if (!dedupBySlug.has(p.slug)) dedupBySlug.set(p.slug, new Set());
  }
  return findings;
}
