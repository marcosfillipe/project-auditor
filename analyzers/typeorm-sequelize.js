'use strict';

const fs   = require('fs');
const path = require('path');

const SECURITY_PATTERNS = [
  // SQL Injection — TypeORM
  { regex: /\.query\s*\(\s*`[^`]*\${/g,                                     severity: 'CRITICAL', label: 'TypeORM .query() com template literal',   desc: 'Interpolação em .query() — vulnerável a SQL injection. Use parâmetros: .query("SELECT WHERE id = $1", [id]).' },
  { regex: /createQueryBuilder[\s\S]{0,300}\.where\s*\(\s*`[^`]*\${/g,      severity: 'CRITICAL', label: 'QueryBuilder .where() com interpolação',   desc: 'Template literal em .where() — use .where("col = :val", { val }) em vez de interpolação direta.' },
  { regex: /\.andWhere\s*\(\s*`[^`]*\${/g,                                  severity: 'CRITICAL', label: '.andWhere() com template literal',         desc: 'Interpolação em .andWhere() — use parâmetros nomeados: .andWhere("col = :val", { val }).' },
  { regex: /\.orderBy\s*\(\s*\w+\s*,/g,                                     severity: 'MEDIUM',   label: '.orderBy() com variável como coluna',      desc: 'Coluna de ordenação vinda de variável — valide contra lista de colunas permitidas para evitar injection.' },

  // SQL Injection — Sequelize
  { regex: /sequelize\.query\s*\(\s*`[^`]*\${/g,                            severity: 'CRITICAL', label: 'Sequelize.query() com template literal',  desc: 'Interpolação em sequelize.query() — use replacements: sequelize.query(sql, { replacements: { val } }).' },
  { regex: /where\s*:\s*\{\s*\[Op\.like\]\s*:\s*`%\${/g,                   severity: 'HIGH',     label: 'Op.like com interpolação',                desc: 'Op.like com interpolação — pode quebrar query ou permitir injection. Use replacements do Sequelize.' },
  { regex: /literal\s*\(\s*`[^`]*\${/g,                                     severity: 'CRITICAL', label: 'Sequelize.literal() com interpolação',    desc: 'Sequelize.literal() com template literal — altamente perigoso. Nunca use com input do usuário.' },

  // Exposição de dados
  { regex: /attributes\s*:\s*\{[^}]*exclude\s*:\s*\[\s*\]/g,               severity: 'MEDIUM',   label: 'attributes.exclude vazio',                desc: 'exclude vazio não exclui nada — liste explicitamente campos sensíveis: exclude: ["password", "token"].' },
  { regex: /\.findAll\s*\(\s*\)(?!\s*\{)/g,                                 severity: 'HIGH',     label: 'findAll() sem parâmetros',                desc: 'findAll() sem where/limit/attributes retorna toda a tabela — adicione filtros e paginação.' },
  { regex: /include\s*:\s*\[\s*\{[^}]*model\s*:\s*\w+(?![^}]*where|[^}]*limit)[^}]*\}\s*\]/g, severity: 'MEDIUM', label: 'include sem where ou limit', desc: 'include (eager loading) sem filtro ou limit — pode retornar dados em excesso e causar N+1.' },

  // TypeORM — configuração
  { regex: /synchronize\s*:\s*true/g,                                        severity: 'HIGH',     label: 'synchronize:true em TypeORM',            desc: 'synchronize:true sincroniza o schema automaticamente — em produção pode destruir dados. Use migrations.' },
  { regex: /dropSchema\s*:\s*true/g,                                         severity: 'CRITICAL', label: 'dropSchema:true em TypeORM',             desc: 'dropSchema:true APAGA o banco ao conectar — remova imediatamente de qualquer ambiente persistente.' },
  { regex: /logging\s*:\s*true/g,                                            severity: 'LOW',      label: 'logging:true em TypeORM',                desc: 'logging:true expõe todas as queries SQL nos logs — desative em produção ou use logging:["error"].' },
];

const PERFORMANCE_PATTERNS = [
  // TypeORM N+1
  { regex: /for\s*(?:await)?\s*\(.*of\s+\w+\s*\)[\s\S]{0,200}\.(findOne|find|getRepository)\s*\(/g, severity: 'HIGH', label: 'N+1 — TypeORM query em loop',  desc: 'Query TypeORM dentro de loop — use QueryBuilder com JOIN ou findByIds() para busca em batch.' },
  { regex: /getRepository\s*\(\s*\w+\s*\)\.find\s*\(\s*\{(?![^}]*relations|[^}]*select)[^}]*\}/g, severity: 'MEDIUM', label: 'find() sem relations ou select', desc: '.find() sem relations nem select — define relacionamentos e campos explicitamente.' },

  // Sequelize N+1
  { regex: /for\s*(?:const|let|var)\s+\w+\s+of\s+\w+[\s\S]{0,200}\.findOne\s*\(\s*\{/g, severity: 'HIGH', label: 'N+1 — Sequelize findOne em loop',    desc: 'Sequelize.findOne em loop — agrupe em findAll com where: { id: { [Op.in]: ids } }.' },
  { regex: /\.findAll\s*\(\s*\{(?![^}]*limit)[^}]*\}\s*\)/g,               severity: 'HIGH',     label: 'findAll sem limit',                       desc: 'findAll sem limit pode retornar tabela inteira — adicione limit e offset para paginação.' },

  // Geral
  { regex: /eager\s*:\s*true/g,                                              severity: 'MEDIUM',   label: 'Eager loading global',                   desc: 'eager:true carrega sempre a relação — pode causar N+1 e over-fetching. Prefira lazy loading explícito.' },
];

const FLOW_PATTERNS = [
  { regex: /\.save\s*\(\s*\)(?![\s\S]{0,300}try\s*\{|\.catch)/g,           severity: 'MEDIUM',   label: '.save() sem try/catch',                  desc: '.save() pode falhar (unique constraint, FK violation) — envolva em try/catch.' },
  { regex: /transaction\s*\(\s*async[\s\S]{0,500}\)(?![\s\S]{0,100}rollback|catch)/g, severity: 'MEDIUM', label: 'Transaction sem rollback explícito', desc: 'Transação sem rollback visível — o ORM faz rollback automático em erro, mas confirme o comportamento.' },
  { regex: /catch\s*\([^)]+\)\s*\{[\s\S]{0,50}\}/g,                        severity: 'HIGH',     label: 'catch vazio após query ORM',             desc: 'Erro de ORM capturado sem logging — logue o erro para diagnóstico.' },
  { regex: /console\.(log|debug|info)\s*\(/g,                               severity: 'LOW',      label: 'console.log',                            desc: 'Use logger estruturado em vez de console.log.' },
  { regex: /\/\/\s*TODO|\/\/\s*FIXME/gi,                                    severity: 'LOW',      label: 'Dívida técnica',                         desc: 'TODO/FIXME encontrado — registre como issue.' },
];

function makeResult(filePath, line, severity, label, desc) {
  return { file: filePath, line, severity, label, description: desc };
}

function scanPatterns(text, patterns, filePath) {
  const results = [];
  const lines   = text.split('\n');
  for (const { regex, severity, label, desc } of patterns) {
    regex.lastIndex = 0;
    lines.forEach((lineText, idx) => {
      regex.lastIndex = 0;
      if (regex.test(lineText)) {
        results.push(makeResult(filePath, idx + 1, severity, label, desc));
      }
      regex.lastIndex = 0;
    });
  }
  return results;
}

function analyzeFile(filePath) {
  const findings = [];
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch { return findings; }
  findings.push(...scanPatterns(content, SECURITY_PATTERNS,    filePath));
  findings.push(...scanPatterns(content, PERFORMANCE_PATTERNS, filePath));
  findings.push(...scanPatterns(content, FLOW_PATTERNS,        filePath));
  return findings;
}

module.exports = { analyzeFile };
