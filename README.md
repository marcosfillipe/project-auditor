# 🛡️ Project Auditor Agent

Agente CLI de auditoria automática para projetos Node.js / React / PostgreSQL.

## Como usar

### 1. Copie a pasta `auditor/` para dentro do seu projeto

```
meu-projeto/
├── src/
├── package.json
├── auditor/          ← cole aqui
│   ├── index.js
│   ├── reporter.js
│   ├── analyzers/
│   └── package.json
```

### 2. Instale as dependências do agente

```bash
cd auditor
npm install
```

### 3. Execute a auditoria

```bash
# De dentro da pasta auditor/ (analisa o projeto pai automaticamente)
node index.js

# Ou passando o caminho explicitamente
node index.js /caminho/para/seu/projeto
```

### 4. Leia o relatório gerado

O relatório será salvo em:
```
seu-projeto/auditor/audit-report-YYYY-MM-DD.md
```

---

## O que é analisado

### 🔒 Segurança
- SQL Injection (concatenação em queries, template literals em SQL)
- XSS (innerHTML, eval, dangerouslySetInnerHTML)
- Secrets hardcoded (passwords, API keys, tokens)
- Exposição de variáveis de ambiente via console/response
- JWT inseguro (algoritmo none, secret vazio, Math.random para tokens)
- CORS com wildcard `*`
- Path traversal (readFile com input do usuário)
- Rate limiting ausente em endpoints críticos
- Dependências vulneráveis (helmet, rate-limit ausentes)
- Gaps no .gitignore

### ⚡ Performance & Gargalos
- Queries N+1 (DB call dentro de loop/forEach/map)
- SELECT sem LIMIT (retorno ilimitado)
- Operações síncronas que bloqueiam o event loop
- Requests HTTP sem timeout
- Loops de alta complexidade (O(n³))
- useEffect sem array de dependências
- Imports wildcard que impedem tree-shaking

### 🔄 Fluxo & Qualidade
- Promises sem .catch() / async sem try-catch
- Inputs de req sem validação
- Blocos catch vazios
- console.log em produção
- TODOs e FIXMEs pendentes
- Funções com mais de 80 linhas
- Ausência de handler global de erros
- Dados sensíveis em localStorage
- Rotas /admin, /debug expostas

---

## Saída de exemplo

```
╔══════════════════════════════════════════════════╗
║        🛡️  PROJECT AUDITOR AGENT v1.0            ║
╚══════════════════════════════════════════════════╝

📁 Projeto:  meu-projeto
📂 Diretório: /home/user/meu-projeto

🔍 Coletando arquivos... 47 arquivo(s) encontrado(s)
🔬 Analisando arquivos...
  [████████████████████] 100%

┌─────────────────────────────────────┐
│  🔒 Segurança:     12               │
│  ⚡ Performance:   8                │
│  🔄 Fluxo:         15               │
│  ─────────────────────────────────  │
│  📊 Total:         35               │
│  🔴 Críticos:      2                │
│  🟠 Altos:         9                │
└─────────────────────────────────────┘

📄 Relatório gerado: auditor/audit-report-2025-01-15.md
```

---

## Integração com CI/CD

O agente retorna **exit code 1** quando encontra vulnerabilidades CRÍTICAS, permitindo bloquear pipelines:

```yaml
# GitHub Actions
- name: Audit project
  run: |
    cd auditor && npm install
    node index.js ..
```

---

## Score de Saúde

| Score | Grade | Significado |
|-------|-------|-------------|
| 85–100 | A | ✅ Projeto em bom estado |
| 65–84 | B | ⚠️ Atenção necessária |
| 40–64 | C | 🔶 Riscos significativos |
| 0–39 | D | 🚨 Vulnerabilidades críticas |

**Penalidades:** CRÍTICO (-25pts) | ALTO (-10pts) | MÉDIO (-4pts) | BAIXO (-1pt)
