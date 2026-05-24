'use strict';

const https = require('https');
const fs = require('fs');
const { URL } = require('url');

const LISTS = [
  { name: 'EasyList',          url: 'https://easylist.to/easylist/easylist.txt' },
  { name: 'EasyPrivacy',       url: 'https://easylist.to/easylist/easyprivacy.txt' },
  { name: "Peter Lowe's",      url: 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0' },
  { name: 'Fanboy Annoyances', url: 'https://easylist.to/easylist/fanboy-annoyance.txt' },
];

const MAX_RULES = 120_000;
const OUTPUT_FILE = 'blocklist.json';

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

const UNSUPPORTED_MODIFIERS = ['csp=', 'redirect=', 'removeparam=', 'rewrite='];

function parseList(text) {
  const networkRules = [];
  const cssRules = [];
  let parsed = 0;
  let skipped = 0;

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();

    // Skip blank lines, comments, and header blocks
    if (!line || line.startsWith('!') || line.startsWith('[')) continue;

    parsed++;

    // Exception/allowlist rules
    if (line.startsWith('@@')) { skipped++; continue; }

    // Script injection and extended CSS — not supported by Apple's engine
    if (line.includes('##+js(') || line.includes('##:') || line.includes('#?#')) {
      skipped++;
      continue;
    }

    // Cosmetic / element-hiding rules
    if (line.includes('##') && !line.includes('#@#')) {
      const sep = line.indexOf('##');
      const domainPart = line.substring(0, sep);
      const selector = line.substring(sep + 2);

      // Skip extended CSS selectors
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
        const domains = domainPart
          .split(',')
          .map(d => d.trim())
          .filter(d => d && !d.startsWith('~'))
          .map(d => `*${d}`);

        if (domains.length === 0) { skipped++; continue; }

        cssRules.push({
          trigger: { 'url-filter': '.*', 'if-domain': domains },
          action: { type: 'css-display-none', selector },
        });
      }
      continue;
    }

    // Network blocking rules
    if (line.startsWith('||')) {
      // Check for unsupported modifiers
      if (line.includes('$') && UNSUPPORTED_MODIFIERS.some(m => line.includes(m))) {
        skipped++;
        continue;
      }

      let domain = line.substring(2);
      if (domain.includes('$')) domain = domain.substring(0, domain.indexOf('$'));
      domain = domain.replace(/[\^/]+$/, '');

      // Skip if it looks like a path or regex, not a plain domain
      if (!domain || domain.includes('/') || domain.includes('*') ||
          domain.includes('[') || domain.includes('(')) {
        skipped++;
        continue;
      }

      networkRules.push({
        trigger: { 'url-filter': `.*${escapeRegex(domain)}` },
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

async function main() {
  const results = [];

  for (const list of LISTS) {
    try {
      process.stdout.write(`  Downloading ${list.name}...`);
      const text = await download(list.url);
      const kb = (Buffer.byteLength(text, 'utf8') / 1024).toFixed(0);
      process.stdout.write(` ${kb} KB\n`);
      const { networkRules, cssRules, parsed, skipped } = parseList(text);
      results.push({ list, networkRules, cssRules, parsed, converted: networkRules.length + cssRules.length, skipped, failed: false });
    } catch (err) {
      process.stdout.write('\n');
      console.error(`  ✗ ${list.name} — ${err.message}`);
      results.push({ list, networkRules: [], cssRules: [], parsed: 0, converted: 0, skipped: 0, failed: true });
    }
  }

  if (results.every(r => r.failed)) {
    console.error('All lists failed. Aborting.');
    process.exit(1);
  }

  // Combine in priority order (EasyList first, Fanboy last — so Fanboy gets trimmed first)
  const combined = results.flatMap(r => [...r.networkRules, ...r.cssRules]);
  const beforeDedup = combined.length;
  const deduped = deduplicate(combined);
  const duplicatesRemoved = beforeDedup - deduped.length;

  let final = deduped;
  const ceilingHit = final.length > MAX_RULES;
  if (ceilingHit) final = final.slice(0, MAX_RULES);

  try {
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(final, null, 2));
  } catch (err) {
    console.error(`Failed to write ${OUTPUT_FILE}: ${err.message}`);
    process.exit(1);
  }

  const totalNetwork = results.reduce((n, r) => n + r.networkRules.length, 0);
  const totalCSS     = results.reduce((n, r) => n + r.cssRules.length, 0);
  const totalSkipped = results.reduce((n, r) => n + r.skipped, 0);
  const total        = final.length;
  const pct          = Math.round((total / MAX_RULES) * 100);

  console.log('\n═'.repeat(39));
  console.log('  Safari Blocklist Conversion Report');
  console.log('═'.repeat(39) + '\n');
  console.log('Source lists downloaded:');
  for (const r of results) {
    const mark = r.failed ? '✗' : '✓';
    console.log(`  ${mark} ${r.list.name.padEnd(20)} — ${String(r.parsed).padStart(6)} rules parsed, ${String(r.converted).padStart(6)} converted`);
  }
  console.log('\nRule breakdown:');
  console.log(`  Network block rules    ${String(totalNetwork).padStart(6)}`);
  console.log(`  CSS hide rules         ${String(totalCSS).padStart(6)}`);
  console.log(`  Skipped (incompatible) ${String(totalSkipped).padStart(6)}`);
  console.log(`  Duplicates removed     ${String(duplicatesRemoved).padStart(6)}`);
  console.log('');
  console.log(`  TOTAL in ${OUTPUT_FILE} ${String(total).padStart(6)} / ${MAX_RULES.toLocaleString()}`);
  console.log('');
  console.log(`  ${bar(total, MAX_RULES)} ${pct}% of safe ceiling`);
  console.log('');
  console.log(ceilingHit
    ? 'Status: ⚠ CEILING HIT — rules trimmed'
    : 'Status: ✓ Within safe ceiling');
  console.log('');
  console.log(`Output: ${OUTPUT_FILE} written successfully.`);
  console.log('');
  console.log('Next step: git add blocklist.json && git commit -m "Update blocklist" && git push');
  console.log('');
}

main();
