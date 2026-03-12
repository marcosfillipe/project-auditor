'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    { regex: /\$queryRaw\s*`[^`]*\$\{/g,                              severity: 'CRITICAL', desc: '$queryRaw com interpolação — SQL injection direto. Use $queryRaw`... ${Prisma.sql`...`}`' },
    { regex: /\$executeRaw\s*`[^`]*\$\{/g,                            severity: 'CRITICAL', desc: '$executeRaw com interpolação — SQL injection. Use Prisma.sql tagged template' },
    { regex: /\$queryRawUnsafe\s*\(/g,                                 severity: 'CRITICAL', desc: '$queryRawUnsafe() — nome já indica: use $queryRaw com Prisma.sql' },
    { regex: /\$executeRawUnsafe\s*\(/g,                               severity: 'CRITICAL', desc: '$executeRawUnsafe() — use $executeRaw com parâmetros seguros' },
  ],
  performance: [
    { regex: /findMany\s*\(\s*\{(?![^}]*take|[^}]*skip|[^}]*cursor)(?=[^}]*\})/g, severity: 'HIGH', desc: 'findMany() sem take/skip/cursor — pode retornar tabela inteira' },
    { regex: /findMany\s*\(\s*\{[^}]*include\s*:\s*\{[^}]*include\s*:\s*\{[^}]*include/g, severity: 'MEDIUM', desc: 'include aninhado em 3+ níveis — pode gerar consulta muito pesada' },
    { regex: /\.findMany\s*\(\s*\{(?![^}]*select)[^}]*\}\s*\)/g,     severity: 'MEDIUM',   desc: 'findMany() sem select — retorna todos os campos, use select para especificar' },
    { regex: /for\s*\(.*\)\s*\{[^}]*await\s+prisma\.\w+\.(findUnique|findFirst|create|update)/g, severity: 'HIGH', desc: 'Query Prisma dentro de loop — padrão N+1, use createMany/updateMany ou Promise.all' },
  ],
  flow: [
    { regex: /prisma\.\$transaction\s*\(\s*\[[^\]]*\]\s*\)/g,        severity: 'INFO',     desc: 'Transação Prisma em array — considere callback para melhor controle de rollback' },
    { regex: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g,                     severity: 'HIGH',     desc: 'Catch vazio após operação Prisma — erros de DB silenciados' },
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
          findings.push({ severity, label: `Prisma/${label}`, description: desc, file: filePath, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

function analyzeProject(projectRoot) {
  const issues = [];

  // schema.prisma
  const schemaPaths = [
    path.join(projectRoot, 'prisma', 'schema.prisma'),
    path.join(projectRoot, 'schema.prisma'),
  ];
  const schemaPath = schemaPaths.find(fs.existsSync);
  if (!schemaPath) return issues;

  const schema = fs.readFileSync(schemaPath, 'utf8');

  // Verifica se DATABASE_URL está hardcoded
  if (/datasource\s+db\s*\{[^}]*url\s*=\s*["'][^"']+["']/g.test(schema))
    issues.push({ severity: 'CRITICAL', label: 'Prisma/Schema', description: 'DATABASE_URL hardcoded no schema.prisma — use env("DATABASE_URL").', file: schemaPath });

  // Verifica ausência de @updatedAt em modelos com timestamps
  if (/createdAt[^@]*DateTime(?![^}]*@updatedAt)/g.test(schema))
    issues.push({ severity: 'LOW', label: 'Prisma/Schema', description: 'Modelo com createdAt sem @updatedAt — considere rastrear atualizações.', file: schemaPath });

  // Verifica se tem índices em FKs
  if (/@@index\s*\(/.test(schema) === false && /@relation/.test(schema))
    issues.push({ severity: 'MEDIUM', label: 'Prisma/Schema', description: 'Relações sem @@index() declarado — queries de JOIN podem ser lentas sem índice nas FKs.', file: schemaPath });

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
