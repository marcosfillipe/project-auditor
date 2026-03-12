'use strict';

const fs = require('fs');

function readFileSafe(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); } catch { return null; }
}

// ─── Pattern Definitions ──────────────────────────────────────────────────────

const PERF_PATTERNS = [
  {
    label: 'N+1 Query Risk',
    severity: 'HIGH',
    patterns: [
      { regex: /for\s*\(.*\)\s*\{[^}]*\.(find|findOne|query|select|where)\s*\(/gs, desc: 'DB query inside a loop — classic N+1 problem' },
      { regex: /\.forEach\s*\([^)]*\)\s*=>\s*\{[^}]*await\s+\w+\.(find|get|query)/gs, desc: 'Async DB call inside forEach (N+1 risk)' },
      { regex: /\.map\s*\([^)]*=>\s*\{?[^}]*await\s+\w+\.(find|findOne|findById)/gs, desc: 'await inside .map() — consider Promise.all or batch query' },
    ]
  },
  {
    label: 'Missing Pagination',
    severity: 'MEDIUM',
    patterns: [
      { regex: /\.find\s*\(\s*\{[^}]*\}\s*\)(?!\s*\.limit|\s*\.skip)/g, desc: 'find() without .limit() or .skip() — may return unbounded results' },
      { regex: /SELECT\s+\*?\s+FROM\s+\w+(?!\s+WHERE|\s+LIMIT|\s+WHERE)/gi, desc: 'SELECT without LIMIT clause (verify pagination)' },
      { regex: /findAll\s*\(\s*\{(?![^}]*limit)[^}]*\}\s*\)/g, desc: 'ORM findAll() without limit — full table scan possible' },
    ]
  },
  {
    label: 'Synchronous / Blocking Operation',
    severity: 'HIGH',
    patterns: [
      { regex: /readFileSync\s*\(/g, desc: 'readFileSync() blocks event loop — use async version' },
      { regex: /writeFileSync\s*\(/g, desc: 'writeFileSync() blocks event loop — use async version' },
      { regex: /execSync\s*\(/g, desc: 'execSync() blocks event loop — use exec() or spawn()' },
      { regex: /\bJSON\.parse\b.*large/gi, desc: 'Large JSON.parse() — may block event loop for big payloads' },
    ]
  },
  {
    label: 'Missing Cache Strategy',
    severity: 'LOW',
    patterns: [
      { regex: /app\.(get|router\.get)\s*\(['"][^'"]+['"]/g, desc: 'GET endpoint — verify cache headers or in-memory cache applied' },
      { regex: /res\.(json|send)\s*\(/g, desc: 'Response without explicit cache control header (verify if needed)' },
    ]
  },
  {
    label: 'High Complexity Loop',
    severity: 'MEDIUM',
    patterns: [
      { regex: /for\s*\([^)]+\)\s*\{[^}]*for\s*\([^)]+\)\s*\{[^}]*for\s*\(/gs, desc: 'Triple nested loop — O(n³) complexity risk' },
      { regex: /while\s*\(\s*true\s*\)/g, desc: 'Infinite while loop — verify break condition' },
    ]
  },
  {
    label: 'Unoptimized React Rendering',
    severity: 'MEDIUM',
    patterns: [
      { regex: /useEffect\s*\(\s*\(\s*\)\s*=>/g, desc: 'useEffect without dependency array — runs on every render' },
      { regex: /\.map\s*\([^)]+\)\s*=>[^}]+<(?!React\.Fragment)/g, desc: 'List render without key prop (verify keys present)' },
      { regex: /setState.*\{.*\}.*setState/g, desc: 'Multiple setState calls — consider batching or useReducer' },
    ]
  },
  {
    label: 'Large Bundle / Import Risk',
    severity: 'LOW',
    patterns: [
      { regex: /import\s+\*\s+as\s+\w+\s+from/g, desc: 'Wildcard import (*) — prevents tree-shaking' },
      { regex: /require\s*\(\s*['"]lodash['"]\s*\)/g, desc: 'Full lodash import — use named imports: lodash/get' },
      { regex: /require\s*\(\s*['"]moment['"]\s*\)/g, desc: 'moment.js import — consider lighter alternative (date-fns, dayjs)' },
    ]
  },
];

// ─── Response Time Heuristics ─────────────────────────────────────────────────

const RESPONSE_TIME_PATTERNS = [
  { regex: /setTimeout\s*\([^,]+,\s*(\d{5,})\)/g, desc: 'Timeout > 10s detected', severity: 'MEDIUM' },
  { regex: /axios\.get\s*\([^)]+\)(?!\s*\.timeout|\s*\{[^}]*timeout)/g, desc: 'HTTP request without explicit timeout', severity: 'MEDIUM' },
  { regex: /fetch\s*\(\s*['"`][^'"`]+['"`]\s*\)(?!\s*,\s*\{[^}]*signal)/g, desc: 'fetch() without AbortController timeout', severity: 'LOW' },
];

// ─── Main Export ──────────────────────────────────────────────────────────────

function analyzeFile(filePath) {
  const content = readFileSafe(filePath);
  if (!content) return [];

  const results = [];
  const lines = content.split('\n');

  for (const category of PERF_PATTERNS) {
    for (const { regex, desc } of category.patterns) {
      // Line-by-line scan for single-line patterns
      lines.forEach((line, idx) => {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          results.push({
            file: filePath,
            line: idx + 1,
            lineContent: line.trim().substring(0, 120),
            description: desc,
            severity: category.severity,
            label: category.label,
          });
        }
        regex.lastIndex = 0;
      });
    }
  }

  // Response time checks
  lines.forEach((line, idx) => {
    for (const { regex, desc, severity } of RESPONSE_TIME_PATTERNS) {
      regex.lastIndex = 0;
      if (regex.test(line)) {
        results.push({
          file: filePath,
          line: idx + 1,
          lineContent: line.trim().substring(0, 120),
          description: desc,
          severity,
          label: 'Response Time / Timeout',
        });
      }
    }
  });

  return results;
}

function analyzeProjectConfig(projectRoot) {
  const issues = [];
  const pkgPath = require('path').join(projectRoot, 'package.json');
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };

    if (!deps['compression'] && !deps['@fastify/compress']) {
      issues.push({ severity: 'LOW', label: 'No HTTP Compression', description: 'No compression middleware found. Consider gzip/brotli for API responses.' });
    }
    if (!deps['redis'] && !deps['ioredis'] && !deps['node-cache'] && !deps['lru-cache']) {
      issues.push({ severity: 'LOW', label: 'No Caching Layer', description: 'No caching library found (Redis, ioredis, lru-cache). Heavy endpoints may benefit from caching.' });
    }
  } catch { /* skip */ }
  return issues;
}

module.exports = { analyzeFile, analyzeProjectConfig };
