'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    // TypeORM raw queries
    { regex: /\.query\s*\(\s*["'`][^"'`]*\+\s*\w/g,                  severity: 'CRITICAL', desc: 'Repository.query() com concatenação — SQL injection, use parâmetros: query("... = $1", [val])' },
    { regex: /createQueryBuilder[^;]*\.where\s*\(\s*`[^`]*\$\{/g,     severity: 'CRITICAL', desc: 'QueryBuilder.where() com template literal — SQL injection direto' },
    { regex: /\.getRawMany\s*\(\s*\)(?![^;]*\.map|[^;]*\.filter)/g,   severity: 'MEDIUM',   desc: 'getRawMany() retorna objetos raw sem tipagem — verifique se campos sensíveis estão expostos' },
    { regex: /getRepository\s*\(\s*\w+\s*\)\s*\.query\s*\(/g,         severity: 'HIGH',     desc: 'getRepository().query() raw — prefira métodos tipados do Repository' },
    // Sequelize
    { regex: /sequelize\.query\s*\(\s*["'`][^"'`]*\+/g,               severity: 'CRITICAL', desc: 'sequelize.query() com concatenação — use replacements ou bind parameters' },
    { regex: /where\s*:\s*\{\s*[^}]*:\s*req\.(body|params|query)\./g, severity: 'HIGH',     desc: 'Condição WHERE com dado do request sem validação visível' },
  ],
  performance: [
    { regex: /find\s*\(\s*\{(?![^}]*take|[^}]*skip|[^}]*limit)[^}]*\}\s*\)/g, severity: 'HIGH', desc: 'Repository.find() sem take/skip — pode retornar tabela inteira' },
    { regex: /\.leftJoinAndSelect[^;]*\.leftJoinAndSelect[^;]*\.leftJoinAndSelect/g, severity: 'MEDIUM', desc: 'Triple leftJoinAndSelect — verifique se todos são necessários, pode impactar performance' },
    { regex: /for\s*\(.*\)\s*\{[^}]*await.*\.(find|findOne|save|update)\s*\(/g, severity: 'HIGH', desc: 'Operação TypeORM dentro de loop — use save(array) ou QueryBuilder em batch' },
    { regex: /\.findOne\s*\(\s*\{(?![^}]*select)[^}]*\}\s*\)/g,       severity: 'LOW',      desc: 'findOne() sem select — retorna todos os campos da entidade' },
  ],
  flow: [
    { regex: /\.save\s*\(\s*\w+\s*\)(?![^;]*catch|[^;]*try)/g,       severity: 'MEDIUM',   desc: 'save() sem try/catch — erros de constraint de DB não tratados' },
    { regex: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g,                     severity: 'HIGH',     desc: 'Catch vazio — erros de DB silenciados' },
    { regex: /transaction\s*\([^)]*\)(?![^}]*rollback|[^}]*catch)/g, severity: 'MEDIUM',   desc: 'Transaction sem rollback visível — verifique tratamento de erros' },
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
          findings.push({ severity, label: `TypeORM/${label}`, description: desc, file: filePath, line: i + 1 });
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

  // ormconfig exposto
  const ormConfig = ['ormconfig.js','ormconfig.json','ormconfig.ts']
    .map(f => path.join(projectRoot, f)).find(fs.existsSync);
  if (ormConfig) {
    const cfg = fs.readFileSync(ormConfig, 'utf8');
    if (/password\s*[:=]\s*["'][^"']{3,}["']/i.test(cfg))
      issues.push({ severity: 'CRITICAL', label: 'TypeORM/Config', description: 'Senha hardcoded em ormconfig — use variáveis de ambiente.', file: ormConfig });
    if (/synchronize\s*:\s*true/.test(cfg))
      issues.push({ severity: 'HIGH', label: 'TypeORM/Config', description: 'synchronize: true — TypeORM altera o schema automaticamente. Nunca em produção, use migrations.', file: ormConfig });
    if (/logging\s*:\s*true/.test(cfg))
      issues.push({ severity: 'LOW', label: 'TypeORM/Config', description: 'logging: true no ormconfig — todas as queries logadas, pode expor dados sensíveis.', file: ormConfig });
  }

  // Sequelize config
  const seqConfig = path.join(projectRoot, 'config', 'config.json');
  if (fs.existsSync(seqConfig)) {
    const cfg = fs.readFileSync(seqConfig, 'utf8');
    if (/"password"\s*:\s*"[^"]{3,}"/i.test(cfg))
      issues.push({ severity: 'CRITICAL', label: 'TypeORM/Config', description: 'Senha hardcoded em config/config.json do Sequelize — use variáveis de ambiente.', file: seqConfig });
  }

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
