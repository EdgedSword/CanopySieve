'use strict';

const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const { URL } = require('url');

const RED   = '\x1b[31m';
const RESET = '\x1b[0m';
const BOLD  = '\x1b[1m';

const LICENSES_FILE = 'licenses.json';

const ALL_LISTS = [
  { name: 'EasyList',                    url: 'https://easylist.to/easylist/easylist.txt' },
  { name: 'EasyPrivacy',                 url: 'https://easylist.to/easylist/easyprivacy.txt' },
  { name: "Peter Lowe's",               url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0' },
  { name: 'AdGuard Tracking Protection', url: 'https://filters.adtidy.org/extension/chromium/filters/3.txt' },
  { name: 'Fanboy Annoyances',           url: 'https://easylist.to/easylist/fanboy-annoyance.txt' },
  { name: 'AdGuard Annoyances',          url: 'https://filters.adtidy.org/extension/chromium/filters/14.txt' },
  { name: 'AdGuard Mobile Ads',          url: 'https://filters.adtidy.org/extension/chromium/filters/11.txt' },
  { name: 'URLhaus Malware',             url: 'https://urlhaus-filter.pages.dev/urlhaus-filter-online.txt' },
  { name: 'Phishing Army',               url: 'https://phishing.army/download/phishing_army_blocklist_extended.txt' },
  { name: 'AdGuard Social Media',        url: 'https://filters.adtidy.org/extension/chromium/filters/4.txt' },
  { name: 'Spam404',                     url: 'https://raw.githubusercontent.com/Spam404/lists/master/adblock-list.txt' },
];

const EXTENSION_1 = {
  listNames: ['EasyList', 'EasyPrivacy', "Peter Lowe's", 'AdGuard Tracking Protection'],
  output: 'blocklist.json',
  ceiling: 130_000,
  label: 'Extension 1 (primary)',
};

const EXTENSION_2 = {
  listNames: ['Fanboy Annoyances', 'AdGuard Annoyances', 'AdGuard Mobile Ads'],
  output: 'blocklist-annoyances.json',
  ceiling: 120_000,
  label: 'Extension 2 (annoyances)',
};

const EXTENSION_3 = {
  listNames: ['URLhaus Malware', 'Phishing Army'],
  output: 'blocklist-security.json',
  ceiling: 140_000,
  label: 'Extension 3 (security)',
};

const EXTENSION_4 = {
  listNames: ['AdGuard Social Media', 'Spam404'],
  output: 'blocklist-social.json',
  ceiling: 100_000,
  label: 'Extension 4 (social)',
};

const UNSUPPORTED_MODIFIERS = ['csp=', 'redirect=', 'removeparam=', 'rewrite='];

// Lines that change every update and should not affect license comparison.
const VOLATILE_PATTERNS = [
  /last modified/i,
  /last updated/i,
  /^\s*!\s*updated:/i,
  /^\s*!\s*timeupdated:/i,
  /^\s*!\s*checksum:/i,
  /^\s*!\s*diff-path:/i,
  /\bexpires\b/i,
  /^\s*!\s*\d{4}-\d{2}-\d{2}/,
  /version:/i,
];

function extractLicenseHeader(text) {
  const lines = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line.startsWith('!')) break;
    if (VOLATILE_PATTERNS.some(p => p.test(line))) continue;
    lines.push(line);
  }
  return lines.join('\n');
}

function hashString(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function loadSavedLicenses() {
  try {
    return JSON.parse(fs.readFileSync(LICENSES_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function download(urlString) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      headers: { 'User-Agent': 'CanopySieve/1.0' },
    };
    https.get(options, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return download(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    }).on('error', reject);
  });
}

function escapeRegex(str) {
  return str.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

function parseList(text) {
  const networkRules = [];
  const cssRules = [];
  let parsed = 0;
  let skipped = 0;

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    // Skip blank and comment lines. ABP uses '!'; hosts/plain lists use '#'.
    // Must NOT skip '##' or '#@#' which are ABP element hiding syntax, not comments.
    if (!line || line.startsWith('!') || line.startsWith('[')) continue;
    if (line.startsWith('#') && !line.startsWith('##') && !line.startsWith('#@#')) continue;

    parsed++;

    if (line.startsWith('@@')) { skipped++; continue; }

    if (line.includes('##+js(') || line.includes('##:') || line.includes('#?#')) {
      skipped++;
      continue;
    }

    if (line.includes('##') && !line.includes('#@#')) {
      const sep = line.indexOf('##');
      const domainPart = line.substring(0, sep);
      const selector = line.substring(sep + 2);

      if (/^:|\bhas\(|\bupward\(|\bmatches-css/.test(selector)) {
        skipped++;
        continue;
      }

      if (domainPart === '') {
        cssRules.push({
          trigger: { 'url-filter': '.*' },
          action: { type: 'css-display-none', selector },
        });
      } else {
        const parts = domainPart.split(',').map(d => d.trim()).filter(Boolean);
        const ifDomains = parts.filter(d => !d.startsWith('~')).map(d => `*${d}`);
        const unlessDomains = parts.filter(d => d.startsWith('~')).map(d => `*${d.substring(1)}`);

        if (ifDomains.length === 0) { skipped++; continue; }

        const trigger = { 'url-filter': '.*', 'if-domain': ifDomains };
        if (unlessDomains.length > 0) trigger['unless-domain'] = unlessDomains;

        cssRules.push({ trigger, action: { type: 'css-display-none', selector } });
      }
      continue;
    }

    // ABP network rules: ||domain^ or ||domain/path^
    if (line.startsWith('||')) {
      if (line.includes('$') && UNSUPPORTED_MODIFIERS.some(m => line.includes(m))) {
        skipped++;
        continue;
      }

      let urlPart = line.substring(2);
      if (urlPart.includes('$')) urlPart = urlPart.substring(0, urlPart.indexOf('$'));
      urlPart = urlPart.replace(/\^+$/, '');

      if (!urlPart || urlPart.includes('*') || urlPart.includes('[') || urlPart.includes('(')) {
        skipped++;
        continue;
      }

      networkRules.push({
        trigger: { 'url-filter': `.*${escapeRegex(urlPart)}` },
        action: { type: 'block' },
      });
      continue;
    }

    // Hosts file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
    const hostsMatch = line.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)$/);
    if (hostsMatch) {
      const domain = hostsMatch[1];
      if (!domain.includes('.') || domain === 'localhost') { skipped++; continue; }
      networkRules.push({
        trigger: { 'url-filter': `.*${escapeRegex(domain)}` },
        action: { type: 'block' },
      });
      continue;
    }

    // Plain domain list format (one domain per line, e.g. Phishing Army)
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9-]{1,63})+$/.test(line)) {
      networkRules.push({
        trigger: { 'url-filter': `.*${escapeRegex(line)}` },
        action: { type: 'block' },
      });
      continue;
    }

    skipped++;
  }

  return { networkRules, cssRules, parsed, skipped };
}

function deduplicate(rules) {
  const seen = new Set();
  return rules.filter(rule => {
    const key = JSON.stringify(rule);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function bar(count, max, width = 20) {
  const filled = Math.min(Math.round((count / max) * width), width);
  return '[' + '▓'.repeat(filled) + '░'.repeat(width - filled) + ']';
}

function buildOutput(listResults, listNames, ceiling, outputFile, overflowIn = []) {
  const selected = listResults.filter(r => listNames.includes(r.list.name));
  // Own rules first, overflow fills remaining capacity and is deduped against own rules.
  const combined = [...selected.flatMap(r => [...r.networkRules, ...r.cssRules]), ...overflowIn];
  const beforeDedup = combined.length;
  const deduped = deduplicate(combined);
  const duplicatesRemoved = beforeDedup - deduped.length;

  const ceilingHit = deduped.length > ceiling;
  const final = ceilingHit ? deduped.slice(0, ceiling) : deduped;
  const overflowOut = ceilingHit ? deduped.slice(ceiling) : [];

  fs.writeFileSync(outputFile, JSON.stringify(final, null, 2));

  return {
    total: final.length,
    overflowIn: overflowIn.length,
    overflowOut,
    networkRules: selected.reduce((n, r) => n + r.networkRules.length, 0),
    cssRules: selected.reduce((n, r) => n + r.cssRules.length, 0),
    skipped: selected.reduce((n, r) => n + r.skipped, 0),
    duplicatesRemoved,
    ceilingHit,
    ceiling,
    outputFile,
  };
}

async function main() {
  const savedLicenses = loadSavedLicenses();
  const currentLicenses = {};
  const licenseChanges = [];
  const listResults = [];

  console.log('Downloading source lists...\n');

  for (const list of ALL_LISTS) {
    try {
      process.stdout.write(`  Downloading ${list.name}...`);
      const text = await download(list.url);
      const kb = (Buffer.byteLength(text, 'utf8') / 1024).toFixed(0);
      process.stdout.write(` ${kb} KB\n`);

      const header = extractLicenseHeader(text);
      const hash = hashString(header);
      currentLicenses[list.name] = { hash, header };

      if (savedLicenses[list.name]) {
        if (savedLicenses[list.name].hash !== hash) {
          licenseChanges.push(list.name);
        }
      }

      const { networkRules, cssRules, parsed, skipped } = parseList(text);
      listResults.push({ list, networkRules, cssRules, parsed, converted: networkRules.length + cssRules.length, skipped, failed: false });
    } catch (err) {
      process.stdout.write('\n');
      console.error(`  ✗ ${list.name} — ${err.message}`);
      listResults.push({ list, networkRules: [], cssRules: [], parsed: 0, converted: 0, skipped: 0, failed: true });
    }
  }

  if (licenseChanges.length > 0) {
    console.log('');
    console.log(`${RED}${BOLD}⚠ LICENSE HEADER CHANGED — review before committing:${RESET}`);
    for (const name of licenseChanges) {
      console.log(`${RED}  • ${name}${RESET}`);
      const prev = savedLicenses[name]?.header ?? '(no previous record)';
      const curr = currentLicenses[name]?.header ?? '';
      console.log(`${RED}    Previous:${RESET}`);
      prev.split('\n').slice(0, 8).forEach(l => console.log(`${RED}      ${l}${RESET}`));
      console.log(`${RED}    Current:${RESET}`);
      curr.split('\n').slice(0, 8).forEach(l => console.log(`${RED}      ${l}${RESET}`));
    }
    console.log('');
  }

  const successCount = listResults.filter(r => !r.failed).length;
  if (successCount === 0) {
    console.error('\nAll lists failed. Aborting.');
    process.exit(1);
  }

  let ext1, ext2, ext3, ext4;
  try {
    ext1 = buildOutput(listResults, EXTENSION_1.listNames, EXTENSION_1.ceiling, EXTENSION_1.output);
    ext2 = buildOutput(listResults, EXTENSION_2.listNames, EXTENSION_2.ceiling, EXTENSION_2.output, ext1.overflowOut);
    ext3 = buildOutput(listResults, EXTENSION_3.listNames, EXTENSION_3.ceiling, EXTENSION_3.output);
    ext4 = buildOutput(listResults, EXTENSION_4.listNames, EXTENSION_4.ceiling, EXTENSION_4.output, [...ext3.overflowOut, ...ext2.overflowOut]);
  } catch (err) {
    console.error(`\nFailed to write output: ${err.message}`);
    process.exit(1);
  }

  // Save updated license hashes only if no changes flagged (so unreviewed changes stay flagged next run)
  const toSave = { ...savedLicenses };
  for (const [name, data] of Object.entries(currentLicenses)) {
    if (!licenseChanges.includes(name)) {
      toSave[name] = data;
    }
  }
  fs.writeFileSync(LICENSES_FILE, JSON.stringify(toSave, null, 2));

  function printExtReport(label, ext, results, listNames) {
    const pct = Math.round((ext.total / ext.ceiling) * 100);
    console.log(`\n── ${label} → ${ext.outputFile} ──`);
    for (const r of results.filter(r => listNames.includes(r.list.name))) {
      const mark = r.failed ? '✗' : '✓';
      console.log(`  ${mark} ${r.list.name.padEnd(26)} — ${String(r.parsed).padStart(6)} parsed, ${String(r.converted).padStart(6)} converted`);
    }
    console.log(`  Network block rules    ${String(ext.networkRules).padStart(6)}`);
    console.log(`  CSS hide rules         ${String(ext.cssRules).padStart(6)}`);
    console.log(`  Skipped (incompatible) ${String(ext.skipped).padStart(6)}`);
    console.log(`  Duplicates removed     ${String(ext.duplicatesRemoved).padStart(6)}`);
    if (ext.overflowIn > 0) {
      console.log(`  Overflow rules added   ${String(ext.overflowIn).padStart(6)}`);
    }
    if (ext.overflowOut.length > 0) {
      console.log(`  Overflow rules out     ${String(ext.overflowOut.length).padStart(6)}`);
    }
    console.log(`  TOTAL                  ${String(ext.total).padStart(6)} / ${ext.ceiling.toLocaleString()}`);
    console.log(`  ${bar(ext.total, ext.ceiling)} ${pct}%`);
    console.log(ext.ceilingHit ? '  Status: ⚠ CEILING HIT — rules trimmed' : '  Status: ✓ Within safe ceiling');
  }

  console.log('\n' + '═'.repeat(50));
  console.log('  Safari Blocklist Conversion Report');
  console.log('═'.repeat(50));

  printExtReport(EXTENSION_1.label, ext1, listResults, EXTENSION_1.listNames);
  printExtReport(EXTENSION_2.label, ext2, listResults, EXTENSION_2.listNames);
  printExtReport(EXTENSION_3.label, ext3, listResults, EXTENSION_3.listNames);
  printExtReport(EXTENSION_4.label, ext4, listResults, EXTENSION_4.listNames);

  const combinedTotal = ext1.total + ext2.total + ext3.total + ext4.total;
  console.log(`\n  Combined total: ${combinedTotal.toLocaleString()} rules across all four extensions`);
  console.log(`\nOutput: ${EXTENSION_1.output}, ${EXTENSION_2.output}, ${EXTENSION_3.output}, and ${EXTENSION_4.output} written successfully.`);
  if (licenseChanges.length > 0) {
    console.log(`\n${RED}${BOLD}⚠ Review license changes above before running git commit.${RESET}`);
  }
  console.log('\nNext step: git add blocklist.json blocklist-annoyances.json blocklist-security.json blocklist-social.json licenses.json && git commit -m "Update blocklist" && git push\n');
}

main();
