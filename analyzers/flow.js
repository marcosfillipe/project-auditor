'use strict';

const fs = require('fs');
const path = require('path');

function readFileSafe(filePath) {
  try { return fs.readFileSync(filePath, 'utf8'); } catch { return null; }
}

// ─── Code Quality Patterns ────────────────────────────────────────────────────

const QUALITY_PATTERNS = [
  {
    label: 'Unhandled Promise / Async Error',
    severity: 'HIGH',
    patterns: [
      { regex: /\.then\s*\([^)]+\)(?!\s*\.catch)/g, desc: '.then() without .catch() — unhandled rejection risk' },
      { regex: /async\s+function[^{]+\{(?![^}]*try)/g, desc: 'async function without try/catch (verify error handling)' },
      { regex: /await\s+\w+[^;]*(?<!\s*}\s*catch)/g, desc: 'await outside try/catch (verify caller handles errors)' },
    ]
  },
  {
    label: 'Missing Input Validation',
    severity: 'HIGH',
    patterns: [
      { regex: /req\.(body|params|query)\.\w+(?!\s*&&|\s*\|\||\s*===|\s*!==)/g, desc: 'Request param used without visible null/type check' },
      { regex: /parseInt\s*\(\s*req\./g, desc: 'parseInt on user input without NaN check' },
      { regex: /Number\s*\(\s*req\./g, desc: 'Number() cast on user input without validation' },
    ]
  },
  {
    label: 'Dead / Debug Code',
    severity: 'LOW',
    patterns: [
      { regex: /console\.(log|debug|info)\s*\(/g, desc: 'console.log/debug left in code (remove for production)' },
      { regex: /\/\/\s*TODO/gi, desc: 'TODO comment — unfinished work' },
      { regex: /\/\/\s*FIXME/gi, desc: 'FIXME comment — known bug or issue' },
      { regex: /\/\/\s*HACK/gi, desc: 'HACK comment — technical debt marker' },
      { regex: /debugger\s*;/g, desc: 'debugger statement left in code' },
    ]
  },
  {
    label: 'Broad Error Suppression',
    severity: 'MEDIUM',
    patterns: [
      { regex: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g, desc: 'Empty catch block — errors silently swallowed' },
      { regex: /catch\s*\([^)]+\)\s*\{\s*\/\//g, desc: 'Catch block with only a comment — error not handled' },
      { regex: /process\.on\s*\(\s*['"]uncaughtException['"]/g, desc: 'uncaughtException handler — ensure proper logging/restart' },
    ]
  },
  {
    label: 'SQL / Database Flow',
    severity: 'MEDIUM',
    patterns: [
      { regex: /transaction(?!\s*\()/gi, desc: 'Transaction reference — verify rollback on error' },
      { regex: /\.commit\s*\(\s*\)(?![^}]*\.rollback)/g, desc: 'commit() without visible rollback in same scope' },
      { regex: /pool\.query(?!\s*\([^)]+,\s*\[)/g, desc: 'pool.query() without parameterized args array (SQL injection risk)' },
    ]
  },
  {
    label: 'Exposed Internal Routes',
    severity: 'HIGH',
    patterns: [
      { regex: /router\.(get|post|put|delete)\s*\(\s*['"]\/admin/gi, desc: '/admin route — verify authentication middleware applied' },
      { regex: /router\.(get|post|put|delete)\s*\(\s*['"]\/internal/gi, desc: '/internal route — should not be publicly accessible' },
      { regex: /router\.(get|post|put|delete)\s*\(\s*['"]\/debug/gi, desc: '/debug route — must be disabled in production' },
      { regex: /router\.(get|post)\s*\(\s*['"]\/health/gi, desc: '/health endpoint — verify it doesn\'t expose sensitive system info' },
    ]
  },
  {
    label: 'React / Frontend Anti-patterns',
    severity: 'MEDIUM',
    patterns: [
      { regex: /localStorage\.(setItem|getItem)\s*\(.*(?:token|password|secret)/gi, desc: 'Sensitive data in localStorage — use httpOnly cookies instead' },
      { regex: /sessionStorage\.\w+\s*=.*(?:token|password)/gi, desc: 'Sensitive data in sessionStorage' },
      { regex: /window\.__INITIAL_STATE__.*password/gi, desc: 'Sensitive data in initial state (exposed to client)' },
      { regex: /process\.env\.\w+(?!_PUBLIC_).*API.*KEY/gi, desc: 'Non-public env var in frontend code (will be exposed in bundle)' },
    ]
  },
];

// ─── Function Size Heuristic ──────────────────────────────────────────────────

function findLargeFunctions(content, filePath) {
  const issues = [];
  const lines = content.split('\n');
  const THRESHOLD = 80;

  let funcStart = null;
  let braceDepth = 0;
  let funcName = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const funcMatch = line.match(/(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>|(\w+)\s*:\s*(?:async\s+)?function)/);

    if (funcMatch && braceDepth === 0) {
      funcStart = i;
      funcName = funcMatch[1] || funcMatch[2] || funcMatch[3] || 'anonymous';
    }

    braceDepth += (line.match(/\{/g) || []).length;
    braceDepth -= (line.match(/\}/g) || []).length;

    if (funcStart !== null && braceDepth <= 0 && i > funcStart) {
      const length = i - funcStart;
      if (length > THRESHOLD) {
        issues.push({
          file: filePath,
          line: funcStart + 1,
          lineContent: lines[funcStart].trim().substring(0, 80),
          description: `Function "${funcName}" is ${length} lines long — consider splitting (threshold: ${THRESHOLD})`,
          severity: 'LOW',
          label: 'Oversized Function',
        });
      }
      funcStart = null;
      braceDepth = 0;
    }
  }
  return issues;
}

// ─── Main Export ──────────────────────────────────────────────────────────────

function analyzeFile(filePath) {
  const content = readFileSafe(filePath);
  if (!content) return [];

  const results = [];
  const lines = content.split('\n');

  for (const category of QUALITY_PATTERNS) {
    for (const { regex, desc } of category.patterns) {
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

  results.push(...findLargeFunctions(content, filePath));
  return results;
}

function analyzeProjectStructure(projectRoot) {
  const issues = [];

  // Check for test coverage
  const testDirs = ['test', 'tests', '__tests__', 'spec'];
  const hasTests = testDirs.some(d => fs.existsSync(path.join(projectRoot, d)));
  if (!hasTests) {
    issues.push({ severity: 'MEDIUM', label: 'No Test Directory Found', description: 'No test/ or __tests__/ directory detected. Consider adding unit/integration tests.' });
  }

  // Check for error handling middleware (Express)
  const appFiles = ['app.js', 'src/app.js', 'src/index.js', 'index.js', 'server.js'];
  for (const f of appFiles) {
    const content = readFileSafe(path.join(projectRoot, f));
    if (content) {
      if (!/app\.use\s*\(\s*\(\s*err/.test(content) && !/errorHandler|error-handler/.test(content)) {
        issues.push({ severity: 'HIGH', label: 'Missing Global Error Handler', description: `No Express error handler (app.use((err, req, res, next) =>...)) found in ${f}.`, file: f });
      }
      if (!/\.env/.test(content) && !/dotenv/.test(content) && !/config/.test(content)) {
        issues.push({ severity: 'MEDIUM', label: 'No dotenv / Config Loading Detected', description: `${f} doesn't appear to load environment config — hardcoded values may exist.`, file: f });
      }
      break;
    }
  }

  return issues;
}

module.exports = { analyzeFile, analyzeProjectStructure };
