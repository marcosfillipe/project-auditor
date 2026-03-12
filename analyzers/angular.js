'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    { regex: /bypassSecurityTrustHtml\s*\(/g,                  severity: 'CRITICAL', desc: 'bypassSecurityTrustHtml() desativa sanitização do Angular — risco de XSS' },
    { regex: /bypassSecurityTrustScript\s*\(/g,                severity: 'CRITICAL', desc: 'bypassSecurityTrustScript() — execução de script arbitrário possível' },
    { regex: /bypassSecurityTrustUrl\s*\(/g,                   severity: 'HIGH',     desc: 'bypassSecurityTrustUrl() — valide a origem da URL antes de usar' },
    { regex: /bypassSecurityTrustResourceUrl\s*\(/g,           severity: 'HIGH',     desc: 'bypassSecurityTrustResourceUrl() — verifique se a URL é confiável' },
    { regex: /\[innerHTML\]\s*=/g,                             severity: 'HIGH',     desc: '[innerHTML] binding — Angular sanitiza, mas confirme se não há bypassSecurity' },
    { regex: /localStorage\.(setItem)\s*\(.*(?:token|jwt|password|secret)/gi, severity: 'HIGH', desc: 'Token/senha em localStorage — prefira httpOnly cookies' },
    { regex: /eval\s*\(/g,                                     severity: 'CRITICAL', desc: 'eval() detectado' },
  ],
  performance: [
    { regex: /ChangeDetectionStrategy\.Default/g,              severity: 'LOW',    desc: 'ChangeDetectionStrategy.Default — considere OnPush para componentes puros' },
    { regex: /\*ngFor(?!.*trackBy)/g,                          severity: 'MEDIUM', desc: '*ngFor sem trackBy — causa re-renderização total da lista' },
    { regex: /subscribe\s*\([^)]*\)(?![^}]*unsubscribe|[^}]*takeUntil|[^}]*async)/g, severity: 'MEDIUM', desc: 'subscribe() sem unsubscribe/takeUntil — possível memory leak' },
    { regex: /new\s+Subject\s*\(\s*\)(?![^}]*complete)/g,     severity: 'LOW',    desc: 'Subject sem complete() no ngOnDestroy — verifique cleanup' },
  ],
  flow: [
    { regex: /@Component\s*\(\s*\{(?![^}]*changeDetection)/g, severity: 'LOW',    desc: '@Component sem changeDetection definido — explicitamente prefira OnPush' },
    { regex: /constructor\s*\([^)]*private\s+http:\s*HttpClient/g, severity: 'INFO', desc: 'HttpClient injetado — verifique se interceptors de auth/erro estão configurados' },
    { regex: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g,              severity: 'HIGH',   desc: 'Catch vazio — erros silenciados' },
    { regex: /\bany\b/g,                                       severity: 'LOW',    desc: 'Tipo "any" — perde benefícios do TypeScript, use tipo específico' },
    { regex: /\/\/\s*TODO|\/\/\s*FIXME/gi,                    severity: 'LOW',    desc: 'Débito técnico marcado' },
    { regex: /@Injectable\s*\(\s*\)(?!\s*\{[^}]*providedIn)/g,severity: 'LOW',    desc: '@Injectable sem providedIn — escopo do serviço não definido explicitamente' },
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
          findings.push({ severity, label: `Angular/${label}`, description: desc, file: filePath, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

function analyzeProject(projectRoot) {
  const issues = [];
  const pkgPath = path.join(projectRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return issues;
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch { return issues; }
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  if (!deps['@angular/router'])
    issues.push({ severity: 'LOW', label: 'Angular/Config', description: '@angular/router não detectado — verifique guards de rota (canActivate).', file: pkgPath });

  if (!deps['@ngrx/store'] && !deps['akita'])
    issues.push({ severity: 'INFO', label: 'Angular/Config', description: 'Nenhum gerenciador de estado (NgRx/Akita) detectado — OK para apps simples.', file: pkgPath });

  // Verifica se environments/ expõe chaves
  const envFile = path.join(projectRoot, 'src', 'environments', 'environment.ts');
  if (fs.existsSync(envFile)) {
    const env = fs.readFileSync(envFile, 'utf8');
    if (/apiKey\s*:|secretKey\s*:|password\s*:/gi.test(env))
      issues.push({ severity: 'HIGH', label: 'Angular/Config', description: 'Possível chave/senha no arquivo environment.ts — será incluída no bundle.', file: envFile });
  }

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
