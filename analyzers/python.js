'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    // Injeção
    { regex: /eval\s*\(/g,                                             severity: 'CRITICAL', desc: 'eval() em Python — execução de código arbitrário' },
    { regex: /exec\s*\(\s*(?:request|input|data|body)/g,              severity: 'CRITICAL', desc: 'exec() com dado do usuário — RCE direto' },
    { regex: /os\.system\s*\(/g,                                       severity: 'HIGH',     desc: 'os.system() — prefira subprocess com lista de argumentos' },
    { regex: /subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True/g, severity: 'HIGH',   desc: 'subprocess com shell=True — vulnerável a shell injection se entrada não sanitizada' },
    { regex: /pickle\.(loads|load)\s*\(/g,                             severity: 'CRITICAL', desc: 'pickle.loads() com dado externo — deserialização insegura, RCE possível' },
    { regex: /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g, severity: 'HIGH',   desc: 'yaml.load() sem SafeLoader — use yaml.safe_load()' },
    // SQL
    { regex: /cursor\.execute\s*\(\s*["'`][^"'`]*%\s*(?:\w+|\()/g,   severity: 'CRITICAL', desc: 'SQL com % formatação — injeção SQL, use parâmetros (?, %s)' },
    { regex: /cursor\.execute\s*\(\s*f["']/g,                          severity: 'CRITICAL', desc: 'SQL com f-string — interpolação direta, risco de SQL injection' },
    { regex: /\.raw\s*\(\s*f["']/g,                                    severity: 'CRITICAL', desc: 'ORM .raw() com f-string — SQL injection em ORM (Django/SQLAlchemy)' },
    // Secrets
    { regex: /(?:password|secret|api_key|token)\s*=\s*["'][^"']{4,}["']/gi, severity: 'HIGH', desc: 'Credencial hardcoded em Python' },
    { regex: /SECRET_KEY\s*=\s*["'][^"']{8,}["']/g,                   severity: 'HIGH',     desc: 'Django SECRET_KEY hardcoded — use variável de ambiente' },
    { regex: /DEBUG\s*=\s*True/g,                                      severity: 'HIGH',     desc: 'DEBUG = True em Python/Django — nunca em produção' },
  ],
  performance: [
    { regex: /for\s+\w+\s+in\s+\w+[^:]*:\s*[\s\S]{0,200}\.query\s*\(/g, severity: 'MEDIUM', desc: 'Query dentro de loop — padrão N+1' },
    { regex: /time\.sleep\s*\(\s*\d{2,}/g,                            severity: 'MEDIUM',   desc: 'sleep() com valor alto em código de produção' },
    { regex: /import\s+\*\s+from/g,                                    severity: 'LOW',      desc: 'from X import * — polui namespace, dificulta rastreabilidade' },
  ],
  flow: [
    { regex: /except\s*:/g,                                            severity: 'HIGH',     desc: 'except sem tipo — captura todos os erros incluindo KeyboardInterrupt e SystemExit' },
    { regex: /except\s+Exception\s*:/g,                               severity: 'MEDIUM',   desc: 'except Exception: — muito genérico, considere capturar erros específicos' },
    { regex: /pass\s*$/gm,                                             severity: 'LOW',      desc: 'Bloco com pass — lógica pode estar faltando' },
    { regex: /#\s*TODO|#\s*FIXME|#\s*HACK/gi,                        severity: 'LOW',      desc: 'Débito técnico marcado' },
    { regex: /print\s*\(\s*(?:password|token|secret|key)/gi,          severity: 'HIGH',     desc: 'print() com dado sensível — remova para produção' },
    { regex: /logging\.(debug|info)\s*\([^)]*(?:password|token|secret)/gi, severity: 'HIGH', desc: 'Log com dado sensível — pode vazar em arquivos de log' },
  ],
};

function analyzeFile(filePath) {
  let src;
  try { src = fs.readFileSync(filePath, 'utf8'); } catch { return []; }
  const lines = src.split('\n');
  const findings = [];

  for (const [label, patterns] of Object.entries(PATTERNS)) {
    for (const { regex, severity, desc } of patterns) {
      lines.forEach((line, i) => {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ severity, label: `Python/${label}`, description: desc, file: filePath, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

function analyzeProject(projectRoot) {
  const issues = [];

  // requirements.txt
  const reqPath = path.join(projectRoot, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    const req = fs.readFileSync(reqPath, 'utf8');
    if (/^django==/im.test(req) && !/(django-csp|django-security|django-defender)/i.test(req))
      issues.push({ severity: 'MEDIUM', label: 'Python/Config', description: 'Django sem django-csp ou django-defender — considere adicionar proteções extras.', file: reqPath });
    if (/^flask==/im.test(req) && !/(flask-talisman|flask-seasurf|flask-limiter)/i.test(req))
      issues.push({ severity: 'MEDIUM', label: 'Python/Config', description: 'Flask sem flask-talisman/flask-limiter — headers de segurança e rate limiting podem estar ausentes.', file: reqPath });
  }

  // settings.py (Django)
  const settingsPaths = [
    path.join(projectRoot, 'settings.py'),
    path.join(projectRoot, 'config', 'settings.py'),
  ];
  for (const p of settingsPaths) {
    if (!fs.existsSync(p)) continue;
    const s = fs.readFileSync(p, 'utf8');
    if (/ALLOWED_HOSTS\s*=\s*\[['"\s]*\*['"\s]*\]/g.test(s))
      issues.push({ severity: 'HIGH', label: 'Python/Django', description: 'ALLOWED_HOSTS = ["*"] — aceita qualquer host, vulnerável a Host Header attacks.', file: p });
    if (!/SECURE_HSTS_SECONDS/g.test(s))
      issues.push({ severity: 'MEDIUM', label: 'Python/Django', description: 'SECURE_HSTS_SECONDS não configurado — HTTPS não enforçado.', file: p });
    if (!/CSRF_COOKIE_SECURE/g.test(s))
      issues.push({ severity: 'MEDIUM', label: 'Python/Django', description: 'CSRF_COOKIE_SECURE não configurado — cookie CSRF pode ser enviado em HTTP.', file: p });
  }

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
