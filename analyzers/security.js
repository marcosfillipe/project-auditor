'use strict';

const fs = require('fs');
const path = require('path');

// ─── Pattern Definitions ──────────────────────────────────────────────────────

const PATTERNS = {
  sqlInjection: {
    label: 'SQL Injection Risk',
    severity: 'CRITICAL',
    patterns: [
      { regex: /(['"`])\s*\+\s*\w+\s*\+\s*\1/g, desc: 'String concatenation in query context' },
      { regex: /query\s*\(\s*[`'"]\s*SELECT.*\$\{/gi, desc: 'Template literal in raw SQL query' },
      { regex: /\.query\s*\(`[^`]*\$\{/g, desc: 'Interpolated variable in DB query' },
      { regex: /WHERE\s+\w+\s*=\s*['"]\s*\+/gi, desc: 'Direct concatenation in WHERE clause' },
      { regex: /execute\s*\(\s*[`'"]\s*(SELECT|INSERT|UPDATE|DELETE)/gi, desc: 'Raw SQL in execute()' },
    ]
  },
  xss: {
    label: 'Cross-Site Scripting (XSS)',
    severity: 'HIGH',
    patterns: [
      { regex: /innerHTML\s*=\s*(?!['"`]<)/g, desc: 'Direct innerHTML assignment with variable' },
      { regex: /document\.write\s*\(/g, desc: 'document.write() usage' },
      { regex: /dangerouslySetInnerHTML/g, desc: 'React dangerouslySetInnerHTML (verify sanitization)' },
      { regex: /eval\s*\(/g, desc: 'eval() usage' },
      { regex: /new\s+Function\s*\(/g, desc: 'Dynamic Function constructor' },
    ]
  },
  hardcodedSecrets: {
    label: 'Hardcoded Secrets / Credentials',
    severity: 'CRITICAL',
    patterns: [
      { regex: /password\s*[:=]\s*['"`][^'"`\s]{4,}['"`]/gi, desc: 'Hardcoded password value' },
      { regex: /secret\s*[:=]\s*['"`][^'"`\s]{8,}['"`]/gi, desc: 'Hardcoded secret value' },
      { regex: /api[_-]?key\s*[:=]\s*['"`][^'"`\s]{8,}['"`]/gi, desc: 'Hardcoded API key' },
      { regex: /token\s*[:=]\s*['"`][^'"`\s]{20,}['"`]/gi, desc: 'Hardcoded token value' },
      { regex: /private[_-]?key\s*[:=]\s*['"`]/gi, desc: 'Hardcoded private key' },
    ]
  },
  envExposure: {
    label: 'Environment / Config Exposure',
    severity: 'HIGH',
    patterns: [
      { regex: /console\.(log|info|debug)\s*\(.*process\.env/g, desc: 'Logging environment variables' },
      { regex: /res\.(json|send)\s*\(.*process\.env/g, desc: 'Sending env vars in HTTP response' },
      { regex: /JSON\.stringify\s*\(.*process\.env\b/g, desc: 'Serializing env vars to JSON' },
    ]
  },
  authIssues: {
    label: 'Authentication / Authorization Weakness',
    severity: 'HIGH',
    patterns: [
      { regex: /jwt\.verify\s*\([^,]+,\s*['"`]{2}\s*['"`]/g, desc: 'JWT verified with empty secret' },
      { regex: /algorithm\s*:\s*['"`]none['"`]/gi, desc: 'JWT algorithm set to "none"' },
      { regex: /\.sign\s*\([^,]+,\s*process\.env\.\w+\s*\|\|\s*['"`]/g, desc: 'JWT secret with insecure fallback' },
      { regex: /md5\s*\(/gi, desc: 'MD5 used for hashing (insecure for passwords)' },
      { regex: /createHash\s*\(\s*['"`]md5['"`]\s*\)/gi, desc: 'MD5 hash function usage' },
      { regex: /Math\.random\s*\(\s*\).*token/gi, desc: 'Math.random() for token generation (non-cryptographic)' },
    ]
  },
  cors: {
    label: 'CORS Misconfiguration',
    severity: 'MEDIUM',
    patterns: [
      { regex: /origin\s*:\s*['"]\*['"]/g, desc: 'CORS origin set to wildcard *' },
      { regex: /cors\s*\(\s*\)/g, desc: 'CORS enabled without explicit configuration' },
      { regex: /Access-Control-Allow-Origin.*\*/gi, desc: 'Wildcard CORS header manually set' },
    ]
  },
  pathTraversal: {
    label: 'Path Traversal / File Injection',
    severity: 'HIGH',
    patterns: [
      { regex: /readFile[Sync]*\s*\(\s*req\.(params|query|body)/g, desc: 'Reading file from user-supplied path' },
      { regex: /path\.join\s*\(.*req\.(params|query|body)/g, desc: 'path.join with user input (verify normalization)' },
      { regex: /require\s*\(\s*req\./g, desc: 'Dynamic require() with request data' },
    ]
  },
  rateLimit: {
    label: 'Missing Rate Limiting',
    severity: 'MEDIUM',
    patterns: [
      { regex: /router\.(post|put|delete)\s*\(\s*['"]/g, desc: 'Mutation endpoint (verify rate limiting applied)' },
      { regex: /app\.(post|put|delete)\s*\(\s*['"]\/(?:login|auth|register|reset)/gi, desc: 'Auth endpoint without visible rate limit' },
    ]
  },
};

const SENSITIVE_FILES = ['.env', '.env.local', '.env.production', 'config/database.yml', 'secrets.json'];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

function findInContent(content, filePath, category) {
  const findings = [];
  const lines = content.split('\n');

  for (const { regex, desc } of category.patterns) {
    regex.lastIndex = 0;
    lines.forEach((line, idx) => {
      regex.lastIndex = 0;
      if (regex.test(line)) {
        findings.push({
          file: filePath,
          line: idx + 1,
          lineContent: line.trim().substring(0, 120),
          description: desc,
          severity: category.severity,
          label: category.label,
        });
      }
    });
  }
  return findings;
}

// ─── Main Export ──────────────────────────────────────────────────────────────

function analyzeFile(filePath) {
  const content = readFileSafe(filePath);
  if (!content) return [];

  const results = [];
  for (const category of Object.values(PATTERNS)) {
    results.push(...findInContent(content, filePath, category));
  }
  return results;
}

function analyzeGitignore(projectRoot) {
  const issues = [];
  const gitignorePath = path.join(projectRoot, '.gitignore');
  const content = readFileSafe(gitignorePath);

  const mustIgnore = ['.env', 'node_modules', '*.log', '.env.*'];
  if (!content) {
    issues.push({ severity: 'HIGH', label: 'Missing .gitignore', description: 'No .gitignore found in project root — sensitive files may be exposed in version control.' });
    return issues;
  }

  for (const entry of mustIgnore) {
    if (!content.includes(entry)) {
      issues.push({ severity: 'MEDIUM', label: '.gitignore Gap', description: `"${entry}" is not in .gitignore — consider adding it.` });
    }
  }
  return issues;
}

function checkSensitiveFiles(projectRoot) {
  const found = [];
  for (const f of SENSITIVE_FILES) {
    const fullPath = path.join(projectRoot, f);
    if (fs.existsSync(fullPath)) {
      found.push({ severity: 'INFO', label: 'Sensitive File Detected', description: `File "${f}" exists — ensure it's gitignored and never committed.`, file: fullPath });
    }
  }
  return found;
}

function checkDependencyAudit(projectRoot) {
  const pkgPath = path.join(projectRoot, 'package.json');
  const content = readFileSafe(pkgPath);
  if (!content) return [];

  try {
    const pkg = JSON.parse(content);
    const issues = [];
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };

    // Flag packages with known historic vulnerabilities (basic heuristic)
    const riskyPackages = ['node-serialize', 'serialize-to-js', 'js-yaml@3', 'lodash@4.0', 'minimist@1.2.0'];
    for (const [name] of Object.entries(deps)) {
      if (riskyPackages.some(r => name === r.split('@')[0])) {
        issues.push({ severity: 'HIGH', label: 'Potentially Vulnerable Dependency', description: `Package "${name}" has had critical CVEs in past versions. Run npm audit.` });
      }
    }

    if (!deps['helmet'] && !deps['@fastify/helmet']) {
      issues.push({ severity: 'MEDIUM', label: 'Missing Helmet.js / Security Headers', description: 'No helmet or @fastify/helmet found. Security headers (CSP, HSTS, etc.) may not be set.' });
    }

    if (!deps['express-rate-limit'] && !deps['@fastify/rate-limit'] && !deps['rate-limiter-flexible']) {
      issues.push({ severity: 'MEDIUM', label: 'No Rate Limiting Package', description: 'No rate limiting library detected in package.json. APIs may be vulnerable to brute force.' });
    }

    return issues;
  } catch {
    return [];
  }
}

module.exports = { analyzeFile, analyzeGitignore, checkSensitiveFiles, checkDependencyAudit };
