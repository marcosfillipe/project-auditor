'use strict';

const fs = require('fs');
const path = require('path');

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEVERITY_EMOJI = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: '⚪' };
const SEVERITY_LABEL = { CRITICAL: 'CRÍTICO', HIGH: 'ALTO', MEDIUM: 'MÉDIO', LOW: 'BAIXO', INFO: 'INFO' };

function sortBySeverity(items) {
  return [...items].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
}

function countBySeverity(items) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const item of items) counts[item.severity] = (counts[item.severity] || 0) + 1;
  return counts;
}

function scoreProject(counts) {
  const penalty = (counts.CRITICAL * 25) + (counts.HIGH * 10) + (counts.MEDIUM * 4) + (counts.LOW * 1);
  const score = Math.max(0, 100 - penalty);
  if (score >= 85) return { score, grade: 'A', verdict: '✅ Projeto em bom estado', color: 'green' };
  if (score >= 65) return { score, grade: 'B', verdict: '⚠️ Atenção necessária', color: 'yellow' };
  if (score >= 40) return { score, grade: 'C', verdict: '🔶 Riscos significativos', color: 'orange' };
  return { score, grade: 'D', verdict: '🚨 Projeto com vulnerabilidades críticas', color: 'red' };
}

function timestamp() {
  return new Date().toLocaleString('pt-BR', { timeZone: 'America/Fortaleza', dateStyle: 'full', timeStyle: 'short' });
}

function relPath(filePath, projectRoot) {
  return path.relative(projectRoot, filePath) || filePath;
}

// ─── Section Builders ─────────────────────────────────────────────────────────

function buildSummaryTable(counts, rating) {
  return [
    `## 📊 Resumo Executivo`,
    ``,
    `| Indicador | Valor |`,
    `|-----------|-------|`,
    `| **Score de Saúde** | **${rating.score}/100 (${rating.grade})** |`,
    `| **Veredicto** | ${rating.verdict} |`,
    `| 🔴 Crítico | ${counts.CRITICAL} ocorrência(s) |`,
    `| 🟠 Alto | ${counts.HIGH} ocorrência(s) |`,
    `| 🟡 Médio | ${counts.MEDIUM} ocorrência(s) |`,
    `| 🔵 Baixo | ${counts.LOW} ocorrência(s) |`,
    `| ⚪ Info | ${counts.INFO} ocorrência(s) |`,
    `| **Total de Pontos** | **${Object.values(counts).reduce((a, b) => a + b, 0)}** |`,
    ``,
  ].join('\n');
}

function buildPriorityActions(allFindings) {
  const critical = allFindings.filter(f => f.severity === 'CRITICAL').slice(0, 5);
  const high = allFindings.filter(f => f.severity === 'HIGH').slice(0, 5);

  const lines = [`## 🎯 Ações Prioritárias`, ``];

  if (critical.length) {
    lines.push(`### ⛔ Resolver IMEDIATAMENTE (Críticos)`);
    critical.forEach((f, i) => {
      lines.push(`${i + 1}. **${f.label}** — ${f.description}`);
      if (f.file) lines.push(`   - Arquivo: \`${f.file}\`${f.line ? ` linha ${f.line}` : ''}`);
    });
    lines.push('');
  }

  if (high.length) {
    lines.push(`### ⚠️ Resolver em Breve (Altos)`);
    high.forEach((f, i) => {
      lines.push(`${i + 1}. **${f.label}** — ${f.description}`);
      if (f.file) lines.push(`   - Arquivo: \`${f.file}\`${f.line ? ` linha ${f.line}` : ''}`);
    });
    lines.push('');
  }

  return lines.join('\n');
}

function buildCategorySection(title, emoji, findings, projectRoot) {
  if (!findings.length) {
    return `## ${emoji} ${title}\n\n> ✅ Nenhum problema encontrado nesta categoria.\n\n`;
  }

  const sorted = sortBySeverity(findings);
  const grouped = {};
  for (const f of sorted) {
    if (!grouped[f.label]) grouped[f.label] = [];
    grouped[f.label].push(f);
  }

  const lines = [`## ${emoji} ${title}`, ``];

  for (const [label, items] of Object.entries(grouped)) {
    const sev = items[0].severity;
    lines.push(`### ${SEVERITY_EMOJI[sev]} ${label} \`[${SEVERITY_LABEL[sev]}]\``);
    lines.push('');
    lines.push(`**Total de ocorrências:** ${items.length}`);
    lines.push('');

    for (const item of items.slice(0, 20)) { // cap at 20 per label
      const loc = item.file ? `\`${relPath(item.file, projectRoot)}\`${item.line ? `:${item.line}` : ''}` : '';
      lines.push(`- ${item.description}${loc ? ` — ${loc}` : ''}`);
      if (item.lineContent) lines.push(`  \`\`\`\n  ${item.lineContent}\n  \`\`\``);
    }

    if (items.length > 20) {
      lines.push(`> _(+${items.length - 20} ocorrências adicionais omitidas)_`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function buildChecklist() {
  return [
    `## ✅ Checklist de Correções`,
    ``,
    `Use esta lista para acompanhar o progresso das correções:`,
    ``,
    `### Segurança`,
    `- [ ] Eliminar todas as queries com concatenação de string (SQL Injection)`,
    `- [ ] Substituir secrets hardcoded por variáveis de ambiente`,
    `- [ ] Configurar CORS com origens explícitas (não usar \`*\`)`,
    `- [ ] Adicionar rate limiting nos endpoints de autenticação`,
    `- [ ] Validar e sanitizar todos os inputs de req.body / req.params / req.query`,
    `- [ ] Configurar helmet.js para headers de segurança`,
    `- [ ] Verificar se .env está no .gitignore`,
    `- [ ] Substituir MD5 por bcrypt/argon2 para senhas`,
    ``,
    `### Performance`,
    `- [ ] Resolver queries N+1 (usar joins ou batch loading)`,
    `- [ ] Adicionar LIMIT em todas as queries de listagem`,
    `- [ ] Substituir operações sync (readFileSync) por async`,
    `- [ ] Adicionar timeout em todas as chamadas HTTP externas`,
    `- [ ] Revisar imports wildcard (*) para habilitar tree-shaking`,
    ``,
    `### Fluxo & Qualidade`,
    `- [ ] Cobrir funções async com try/catch`,
    `- [ ] Adicionar handler global de erros no Express`,
    `- [ ] Remover console.log de produção`,
    `- [ ] Resolver todos os TODOs e FIXMEs críticos`,
    `- [ ] Adicionar testes unitários e de integração`,
    `- [ ] Remover rotas /debug ou /internal em produção`,
    ``,
  ].join('\n');
}

function buildRecommendations() {
  return [
    `## 💡 Recomendações Gerais`,
    ``,
    `### Segurança`,
    `- Use **parameterized queries** ou ORM com prepared statements em todas as queries`,
    `- Adote **Zod** ou **Joi** para validação de schema de entrada em todos os endpoints`,
    `- Configure **Content-Security-Policy** via helmet`,
    `- Implemente **JWT com rotação de tokens** e tempo de expiração curto (< 1h)`,
    `- Use **bcrypt** (cost factor ≥ 12) ou **argon2** para armazenar senhas`,
    ``,
    `### Performance`,
    `- Adote **DataLoader** para resolver o problema N+1 em APIs GraphQL`,
    `- Use **Redis** para cache de queries pesadas e sessões`,
    `- Configure **pg-pool** com tamanho de pool adequado para PostgreSQL`,
    `- Considere **índices de banco** nas colunas usadas em WHERE e JOIN frequentes`,
    ``,
    `### Monitoramento`,
    `- Implemente **logging estruturado** (pino, winston) com níveis corretos`,
    `- Configure **health checks** que não exponham dados internos`,
    `- Adote **APM** (Datadog, New Relic, ou similar) para rastrear tempos de resposta`,
    `- Defina **SLOs** (ex: p95 < 200ms para endpoints críticos)`,
    ``,
  ].join('\n');
}

// ─── Main Export ──────────────────────────────────────────────────────────────

function generate({ projectRoot, projectName, securityFindings, performanceFindings, flowFindings, frameworkFindings = [], filesScanned, duration, frameworks = [] }) {
  const allFindings = [...securityFindings, ...performanceFindings, ...flowFindings, ...frameworkFindings];
  const counts = countBySeverity(allFindings);
  const rating = scoreProject(counts);

  const fwLabel = frameworks.filter(f => f !== 'html-css').join(', ') || 'JS/TS genérico';

  const lines = [
    `# 🛡️ Relatório de Auditoria — ${projectName}`,
    ``,
    `> **Gerado em:** ${timestamp()}`,
    `> **Arquivos analisados:** ${filesScanned}`,
    `> **Tempo de análise:** ${duration}ms`,
    `> **Frameworks detectados:** ${fwLabel}`,
    `> **Ferramenta:** Project Auditor Agent v2.0`,
    ``,
    `---`,
    ``,
    buildSummaryTable(counts, rating),
    `---`,
    ``,
    buildPriorityActions(allFindings),
    `---`,
    ``,
    buildCategorySection('Segurança', '🔒', securityFindings, projectRoot),
    `---`,
    ``,
    buildCategorySection('Performance & Gargalos', '⚡', performanceFindings, projectRoot),
    `---`,
    ``,
    buildCategorySection('Fluxo & Qualidade de Código', '🔄', flowFindings, projectRoot),
    `---`,
    ``,
    ...(frameworkFindings.length > 0 ? [
      buildCategorySection('Específicos de Framework', '🧩', frameworkFindings, projectRoot),
      `---`,
      ``,
    ] : []),
    buildChecklist(),
    `---`,
    ``,
    buildRecommendations(),
    `---`,
    ``,
    `_Relatório gerado automaticamente pelo Project Auditor Agent. Revise os resultados com um engenheiro de segurança antes de publicar em produção._`,
  ];

  return lines.join('\n');
}

module.exports = { generate };
