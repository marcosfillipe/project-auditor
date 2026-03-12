'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    { regex: /@Public\s*\(\s*\)/g,                                     severity: 'MEDIUM',   desc: '@Public() — rota sem autenticação, verifique se intencional' },
    { regex: /@Roles\s*\(\s*\)(?!\s*\/\/\s*public)/g,                  severity: 'MEDIUM',   desc: '@Roles() sem argumentos — guard pode não estar aplicando restrições' },
    { regex: /new\s+ValidationPipe\s*\(\s*\)(?!\s*\{)/g,               severity: 'MEDIUM',   desc: 'ValidationPipe sem opções — whitelist: true e forbidNonWhitelisted recomendados' },
    { regex: /@Body\s*\(\s*\)(?![^)]*ValidationPipe|[^)]*ParsePipe)/g, severity: 'MEDIUM',   desc: '@Body() sem pipe de validação — dado do cliente não validado' },
    { regex: /eval\s*\(/g,                                             severity: 'CRITICAL',  desc: 'eval() detectado' },
    { regex: /process\.env\.\w+(?=.*@Get|.*@Post|.*@Put)/g,           severity: 'HIGH',      desc: 'Env var em endpoint — verifique se não está sendo exposta na resposta' },
  ],
  performance: [
    { regex: /@Injectable\s*\(\s*\)(?!\s*\{[^}]*scope)/g,             severity: 'LOW',      desc: '@Injectable sem Scope definido — padrão é Singleton; use REQUEST scope se necessário' },
    { regex: /async\s+\w+\s*\([^)]*\)\s*\{(?![^}]*try)/g,            severity: 'MEDIUM',   desc: 'Método async sem try/catch — use ExceptionFilter global ou interceptor' },
    { regex: /\.find\s*\(\s*\{[^}]*\}\s*\)(?!\s*\.\s*(take|skip|limit))/g, severity: 'MEDIUM', desc: 'Repository.find() sem take/skip — pode retornar tabela inteira' },
  ],
  flow: [
    { regex: /@Controller\s*\([^)]*\)(?![^@]*@UseGuards)/g,           severity: 'LOW',      desc: '@Controller sem @UseGuards visível — verifique proteção das rotas' },
    { regex: /ClassSerializerInterceptor(?!\s*,\s*\{)/g,               severity: 'INFO',     desc: 'ClassSerializerInterceptor em uso — confirme @Exclude() nos campos sensíveis do DTO' },
    { regex: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g,                     severity: 'HIGH',     desc: 'Catch vazio — erros silenciados' },
    { regex: /console\.(log|debug)\s*\(/g,                             severity: 'LOW',      desc: 'console.log em NestJS — use Logger do @nestjs/common' },
    { regex: /\/\/\s*TODO|\/\/\s*FIXME/gi,                            severity: 'LOW',      desc: 'Débito técnico marcado' },
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
          findings.push({ severity, label: `NestJS/${label}`, description: desc, file: filePath, line: i + 1 });
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

  if (!deps['class-validator'])
    issues.push({ severity: 'HIGH', label: 'NestJS/Config', description: 'class-validator não instalado — ValidationPipe não consegue validar DTOs.', file: pkgPath });
  if (!deps['@nestjs/throttler'])
    issues.push({ severity: 'MEDIUM', label: 'NestJS/Config', description: '@nestjs/throttler não instalado — sem rate limiting nativo.', file: pkgPath });
  if (!deps['helmet'])
    issues.push({ severity: 'HIGH', label: 'NestJS/Config', description: 'helmet não instalado — headers de segurança HTTP ausentes.', file: pkgPath });

  // main.ts
  const mainTs = [
    path.join(projectRoot, 'src', 'main.ts'),
    path.join(projectRoot, 'src', 'main.js'),
  ].find(fs.existsSync);
  if (mainTs) {
    const main = fs.readFileSync(mainTs, 'utf8');
    if (!(/app\.useGlobalPipes/.test(main)))
      issues.push({ severity: 'HIGH', label: 'NestJS/Config', description: 'useGlobalPipes() não encontrado em main.ts — ValidationPipe não está aplicado globalmente.', file: mainTs });
    if (!(/app\.use\s*\(\s*helmet/.test(main)))
      issues.push({ severity: 'HIGH', label: 'NestJS/Config', description: 'helmet() não aplicado em main.ts — headers de segurança ausentes.', file: mainTs });
    if (!(/enableCors|app\.enableCors/.test(main)))
      issues.push({ severity: 'LOW', label: 'NestJS/Config', description: 'CORS não configurado em main.ts — verifique se necessário para o contexto.', file: mainTs });
  }

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
