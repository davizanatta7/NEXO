# NEXO — Automatização de Gap Analysis em Sistemas de Gestão de Segurança

**Instituição:** Pontifícia Universidade Católica de Minas Gerais (PUC Minas) — Campus Poços de Caldas  
**Curso:** Ciência da Computação — Engenharia de Software & Estágio Obrigatório (2º Semestre de 2026)  
**Autores:** Davi Freire Zanatta & Luiz Alberto Ferreira Gomes  
**Frameworks & Normas:** CIS Controls v8.1 (2024), ABNT NBR ISO/IEC 27001:2022, ABNT NBR ISO/IEC 27002:2022, NIST Cybersecurity Framework (CSF) 2.0 (2024), ISO 31000, CMMC, LGPD (Lei nº 13.709/2018), GDPR (Regulamento UE 2016/679) e ABNT NBR ISO 45001:2018.

---

## 1. Problema de Pesquisa e Objetivo

> *"Como o desenvolvimento de uma aplicação automatizada para o Gap Analysis pode reduzir a ineficiência do processo manual e aumentar a precisão na gestão da conformidade de segurança da informação?"*

O protótipo **NEXO** substitui a auditoria manual baseada em planilhas estáticas e coleta artesanal de evidências por uma arquitetura automatizada *agentless*, composta por:
1. **Conectores de API RESTful Agentless:** Integração assíncrona em JSON com **AWS Audit Manager**, **Microsoft Defender for Cloud (Azure)** e **Serviços de Identidade (Entra ID / Active Directory)** + repositório documental (**Salvaguarda 1.1.2 do CIS Controls v8.1**).
2. **Motor Central de Regras (Core Rule Engine em Python):** Traduz exigências normativas da ISO 27001/27002, NIST CSF 2.0, CIS v8.1, LGPD e GDPR em regras lógicas determinísticas (`0.0%` de falsos positivos).
3. **Banco de Dados Relacional (PostgreSQL):** Esquema relacional (`database/schema.sql`) garantindo integridade entre normativas, regras lógicas e payloads de evidências (`JSONB`).
4. **Interface Gráfica Reativa & Grafo de Risco:** Dashboard interativo (`index.html`, `app.js`, `styles.css`) com visualização do **Grafo de Risco (Risk Graph)**, **Matriz de Riscos 5x5 (ISO 31000 + CVSS)**, **Avaliação de Maturidade CMMC / Grupos de Implementação (IG1, IG2, IG3)** e **Plano de Ação 5W2H**.

---

## 2. Estrutura do Projeto

- [index.html](file:///c:/Users/DavizinP4unelas/Documents/NEXO/index.html) — Interface gráfica principal com as 4 etapas metodológicas, Grafo de Risco SVG, Conectores Agentless, Motor de Regras e Validação em 3 Níveis.
- [data.js](file:///c:/Users/DavizinP4unelas/Documents/NEXO/data.js) — Base de conhecimento normativa (18 Controles CIS v8.1, ISO 27001/27002, NIST CSF 2.0, LGPD, GDPR, Ativos 1.1.2, Riscos e 5W2H).
- [app.js](file:///c:/Users/DavizinP4unelas/Documents/NEXO/app.js) — Lógica reativa, recálculo dinâmico de Gap Analysis por Grupo de Implementação (`IG1`, `IG2`, `IG3`), renderização do Grafo de Risco e exportação JSON/PDF.
- [styles.css](file:///c:/Users/DavizinP4unelas/Documents/NEXO/styles.css) — Estilização executiva do painel e layout otimizado para impressão/PDF.
- [backend/core_engine.py](file:///c:/Users/DavizinP4unelas/Documents/NEXO/backend/core_engine.py) — Motor Central de Regras em Python com ingestão assíncrona (`asyncio`) dos conectores AWS/Azure/IAM e execução da bateria de validação em 3 níveis (Seção 4.3).
- [database/schema.sql](file:///c:/Users/DavizinP4unelas/Documents/NEXO/database/schema.sql) — Esquema relacional PostgreSQL para armazenamento de frameworks, controles, regras e evidências.
- [scripts/cis_audit_collector.py](file:///c:/Users/DavizinP4unelas/Documents/NEXO/scripts/cis_audit_collector.py) — Script auxiliar de descoberta e validação local de ativos e documentação (CIS 1.1.2).

