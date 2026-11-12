// Dados estruturados do Protótipo NEXO - Automatização de Gap Analysis em Sistemas de Gestão de Segurança
// Integrando:
// 1) "Automatização de Gap Analysis em Sistemas de Gestão de Segurança" (Engenharia de Software - Davi Freire Zanatta & Luiz Alberto Ferreira Gomes)
// 2) "Gap Analysis e Segurança da Informação Baseado nos CIS Controls v8.1" (Estágio Obrigatório - PUC Minas Poços de Caldas - 2º Semestre 2026)

const NEXO_DEFAULT_DATA = {
  metadata: {
    projectTitle: "Automatização de Gap Analysis em Sistemas de Gestão de Segurança",
    subTitle: "Gap Analysis e Segurança da Informação Baseado nos CIS Controls v8.1, ISO/IEC 27001:2022, NIST CSF 2.0, LGPD e GDPR",
    institution: "Pontifícia Universidade Católica de Minas Gerais — Campus Poços de Caldas",
    course: "Ciência da Computação — Engenharia de Software & Estágio Obrigatório",
    authors: "Davi Freire Zanatta & Luiz Alberto Ferreira Gomes",
    semester: "2º Semestre – 2026",
    researchQuestion: "Como o desenvolvimento de uma aplicação automatizada para o Gap Analysis pode reduzir a ineficiência do processo manual e aumentar a precisão na gestão da conformidade de segurança da informação?",
    targetIG: "IG2",
    architectureStack: {
      frontend: "React.js / SPA Reativa + Grafo de Risco SVG",
      backend: "Python 3 (FastAPI / Async RESTful Engine) + Conectores Agentless",
      database: "PostgreSQL 16 (Relacional: Normativas <-> Regras <-> Evidências JSON)",
      cloudConnectors: ["AWS Audit Manager API", "Microsoft Defender for Cloud (Azure)", "Active Directory / IAM Graph API"]
    }
  },

  // Questionário de Levantamento As-Is da Empresa
  companyQuestionnaire: {
    companyName: "Nexus Indústria e Serviços S/A",
    sector: "Tecnologia / Software (SaaS)",
    size: "Médio (51 a 250 colaboradores / multi-cloud)",
    assessor: "Davi Freire Zanatta & Luiz Alberto Ferreira Gomes",
    assessmentDate: "2026-11-12",
    targetIg: "IG2",
    answers: {
      1: { score: 68, obs: "Inventário físico automatizado; documentação 1.1.2 em revisão (última versão há 210 dias)." },
      2: { score: 55, obs: "Inventário de software realizado por varredura, mas allowlisting ainda não imposto." },
      3: { score: 42, obs: "Criptografia ativa em bancos de produção; homologação sem KMS e RoPA LGPD em elaboração." },
      4: { score: 58, obs: "Baseline CIS Level 1 aplicado em 88% das VMs Linux; servidores legados pendentes." },
      5: { score: 62, obs: "Contas administrativas segregadas, porém 3 contas de serviço com senhas sem expiração." },
      6: { score: 45, obs: "MFA implementado para e-mail e VPN, mas ausente em 3 contas de administração de domínio." },
      7: { score: 48, obs: "Varredura trimestral manual; processo de correção de patches críticos leva mais de 30 dias." },
      8: { score: 44, obs: "Logs centralizados no Azure Log Analytics, porém com retenção limitada a 30 dias." },
      9: { score: 65, obs: "SPF e DKIM configurados; DMARC em modo monitoramento ('p=none') sem política de rejeição." },
      10: { score: 72, obs: "Microsoft Defender for Endpoint instalado na maioria das máquinas corporativas." },
      11: { score: 58, obs: "Backups diários em nuvem; imutabilidade ativada recentemente, sem teste de restore semestral." },
      12: { score: 52, obs: "Rede segmentada entre escritórios e data center, mas VPC interna sem microssegmentação fina." },
      13: { score: 35, obs: "Monitoramento de rede baseado em NetFlow básico; IDS/IPS não implantado no perímetro interno." },
      14: { score: 50, obs: "Treinamento admissional realizado; sem simulações contínuas de phishing com métricas de clique." },
      15: { score: 38, obs: "Contratos de fornecedores contêm cláusula geral, mas sem auditoria técnica de terceiros ou DPA." },
      16: { score: 40, obs: "Testes unitários e linters ativos; SAST/DAST não bloqueiam o pipeline de deploy em homolog/prod." },
      17: { score: 42, obs: "Plano de Resposta a Incidentes documentado, porém equipe sem simulados de mesa (tabletop exercises)." },
      18: { score: 30, obs: "Último teste de invasão realizado há mais de 18 meses por consultoria externa." }
    }
  },

  // Conectores de API Agentless (Seção 4.1 e 4.2 do documento de Engenharia de Software)
  apiConnectors: [
    {
      id: "CONN-AWS",
      provider: "Amazon Web Services (AWS)",
      service: "AWS Audit Manager & SecurityHub API",
      endpoint: "https://auditmanager.us-east-1.amazonaws.com/v1/assessments",
      mode: "Agentless (REST JSON)",
      status: "Conectado",
      latencyMs: 118,
      evidencesCollected: 42,
      lastSync: "02/11/2026 14:45:10",
      frameworksMapped: ["CIS v8.1", "ISO/IEC 27001:2022", "NIST CSF 2.0", "GDPR"]
    },
    {
      id: "CONN-AZURE",
      provider: "Microsoft Azure",
      service: "Microsoft Defender for Cloud (Regulatory Compliance API)",
      endpoint: "https://management.azure.com/subscriptions/.../regulatoryComplianceStandards",
      mode: "Agentless (REST JSON)",
      status: "Conectado",
      latencyMs: 134,
      evidencesCollected: 38,
      lastSync: "02/11/2026 14:46:02",
      frameworksMapped: ["CIS v8.1", "ISO/IEC 27002:2022", "NIST CSF 2.0", "LGPD"]
    },
    {
      id: "CONN-IAM",
      provider: "Provedor de Identidade Híbrido",
      service: "Entra ID / Active Directory & CMDB Documental (CIS 1.1.2)",
      endpoint: "https://graph.microsoft.com/v1.0/identityGovernance",
      mode: "Agentless (Graph API)",
      status: "Conectado",
      latencyMs: 92,
      evidencesCollected: 29,
      lastSync: "02/11/2026 14:47:30",
      frameworksMapped: ["CIS Control 01 (1.1.2)", "CIS Control 05 & 06", "ISO 27001 A.5.15", "LGPD Art. 46"]
    }
  ],

  // Motor Central de Regras Lógicas (Core Rule Engine - Seção 4.1 Etapa 1 e 3)
  coreRuleEngine: [
    {
      ruleId: "RULE-CIS-1.1.2",
      name: "Auditoria de Ativos de Documentação e Governança",
      sourceConnector: "CONN-IAM",
      logicalExpression: "asset.type == 'DOCUMENTATION' and asset.version_date >= now() - 180d and asset.approved == true",
      frameworks: "CIS v8.1 (1.1.2) | NIST CSF 2.0 (GOVERN) | ISO 27001 A.5.1",
      lastEvaluation: "FALHA PARCIAL (Gap Detectado)",
      falsePositiveRate: "0.0%",
      evidenceSample: "{ \"doc\": \"PGSI_2025.pdf\", \"days_since_review\": 240, \"compliant\": false }"
    },
    {
      ruleId: "RULE-CIS-6.5-MFA",
      name: "Verificação Agentless de MFA em Contas Privilegiadas",
      sourceConnector: "CONN-IAM",
      logicalExpression: "user.role in ['GlobalAdmin', 'DomainAdmin'] implies user.mfa_enrolled == true",
      frameworks: "CIS v8.1 (6.5) | ISO 27001 A.8.5 | NIST CSF 2.0 (PROTECT)",
      lastEvaluation: "NÃO CONFORME (3 contas sem MFA)",
      falsePositiveRate: "0.0%",
      evidenceSample: "{ \"admin_accounts\": 12, \"mfa_enabled\": 9, \"non_compliant_Accounts\": [\"svc_legacy_adm\", \"dba_homolog\", \"backup_op\"] }"
    },
    {
      ruleId: "RULE-CIS-3.11-ENC",
      name: "Validação de Criptografia em Repouso (KMS/TDE) para Dados Pessoais",
      sourceConnector: "CONN-AWS",
      logicalExpression: "storage.contains_pii == true implies (storage.encryption == 'AES-256-KMS' and storage.public_access == false)",
      frameworks: "CIS v8.1 (3.11) | LGPD Art. 46 | GDPR Art. 32 | ISO 27001 A.8.24",
      lastEvaluation: "NÃO CONFORME (Homologação sem TDE)",
      falsePositiveRate: "0.0%",
      evidenceSample: "{ \"resource\": \"rds-erp-homolog\", \"storage_encrypted\": false, \"lgpd_pii\": true }"
    },
    {
      ruleId: "RULE-CIS-8.9-SIEM",
      name: "Retenção Imutável e Centralização de Logs de Auditoria",
      sourceConnector: "CONN-AZURE",
      logicalExpression: "log_vault.immutable == true and log_vault.retention_days >= 90 and siem_forwarding == 'ENABLED'",
      frameworks: "CIS v8.1 (8.9 / 11.2) | ISO 27001 A.8.15 | NIST CSF 2.0 (DETECT)",
      lastEvaluation: "PARCIAL (Retenção 30d < 90d)",
      falsePositiveRate: "0.0%",
      evidenceSample: "{ \"workspace\": \"azure-sec-logs\", \"retention_days\": 30, \"object_lock\": true }"
    },
    {
      ruleId: "RULE-CIS-4.1-HARDENING",
      name: "Conformidade de Baseline CIS Benchmark em Máquinas Virtuais",
      sourceConnector: "CONN-AZURE",
      logicalExpression: "vm.cis_benchmark_level1_score >= 85 and vm.root_ssh_login == 'disabled'",
      frameworks: "CIS v8.1 (4.1) | ISO 27002:2022 (8.9) | NIST CSF 2.0 (PROTECT)",
      lastEvaluation: "CONFORME EM PRODUÇÃO (88%)",
      falsePositiveRate: "0.0%",
      evidenceSample: "{ \"subscription\": \"prod-workloads\", \"compliant_vms\": 44, \"total_vms\": 50 }"
    }
  ],

  // Validação dos Resultados em 3 Níveis Progressivos (Seção 4.3 do documento de Engenharia de Software)
  validationLevels: {
    manualVsAutomatedComparison: {
      manualHoursPerAudit: 160,
      automatedHoursPerAudit: 4.5,
      timeReductionPercent: 97.2,
      manualErrorOrStaleRate: "18.5% (Planilhas estáticas / Erro humano)",
      automatedFalsePositiveRate: "0.0% (Validação determinística via API JSON)",
      manualEvidenceCount: "Amostral (~25 evidências manuais por reunião)",
      automatedEvidenceCount: "100% da infraestrutura (109 evidências contínuas em tempo real)"
    },
    threeTiers: [
      {
        level: "Nível 1 — Validação Técnica (Testes de Software & Performance)",
        focus: "Estabilidade da arquitetura Python + PostgreSQL e consumo assíncrono das APIs RESTful (AWS, Azure, IAM).",
        metric: "Latência média: 114 ms | Taxa de falha de requisição: 0.0% | Integridade relacional PostgreSQL: 100%",
        status: "Aprovado (100%)"
      },
      {
        level: "Nível 2 — Prova de Conceito (Piloto Agentless em Ambiente Controlado)",
        focus: "Exposição do sistema a uma infraestrutura simulada para detectar vulnerabilidades e falhas de configuração sem instalar agentes.",
        metric: "109 ativos/controles auditados de forma agentless | 6 lacunas críticas identificadas automaticamente",
        status: "Validado em Piloto"
      },
      {
        level: "Nível 3 — Validação de Eficácia (Auditoria Automatizada vs. Checklist Manual)",
        focus: "Cruzamento do relatório automático de Gap Analysis com checklist de auditoria manual padrão (ISO 27001 / CIS v8.1).",
        metric: "Precisão sistêmica: 99.4% | Falsos positivos na correlação de evidências: 0 | Redução de tempo: 97.2%",
        status: "Comprovado"
      }
    ]
  },

  projectTimeline: [
    {
      stage: "1. Pesquisa, Mapeamento Normativo & Levantamento As-Is",
      status: "Concluída",
      period: "Set/2026",
      deliverable: "Tradução da ISO 27001, NIST CSF 2.0, LGPD, GDPR e CIS v8.1 (incluindo Ativos de Documentação 1.1.2) em regras lógicas",
      progress: 100
    },
    {
      stage: "2. Modelagem Arquitetural (Python + PostgreSQL + React)",
      status: "Concluída",
      period: "Out/2026",
      deliverable: "Esquema relacional PostgreSQL, Motor Central de Regras (Core) e Conectores Agentless AWS/Azure/IAM",
      progress: 90
    },
    {
      stage: "3. Diagnóstico Automatizado do Gap, Grafo de Risco & Maturidade CMMC",
      status: "Em validação (Piloto PoC)",
      period: "Out/2026 – Nov/2026",
      deliverable: "Grafo de Risco interativo, Matriz ISO 31000/CVSS e Avaliação de Maturidade por Grupos IG",
      progress: 80
    },
    {
      stage: "4. Plano de Ação 5W2H, Automação SOAR/IaC & Validação em 3 Níveis",
      status: "Em execução final",
      period: "Nov/2026 (Até 30/11)",
      deliverable: "Validação de Eficácia (Automatizado vs. Manual), Roteiro 5W2H e Artefatos DevSecOps",
      progress: 70
    }
  ],

  // Etapa 1: Inventário de Ativos (As-Is) - Coletado via API Agentless + CIS v8.1 (1.1.2)
  assets: [
    {
      id: "AST-001",
      name: "Cluster Firewall / Gateway Perimetral & VPC AWS",
      category: "Hardware / Rede",
      cisControl: "CIS 1 / CIS 12",
      nistFunction: "PROTECT",
      ciaImpact: "Disponibilidade",
      owner: "Engenharia de Redes (Conector AWS)",
      criticality: "Crítica",
      status: "Monitorado (Agentless)",
      cvss: 2.4,
      notes: "Security Groups auditados via AWS Audit Manager API; falta automação de backup de regras."
    },
    {
      id: "AST-002",
      name: "Active Directory / Entra ID (Serviço de Identidade Híbrido)",
      category: "Software / Identidade",
      cisControl: "CIS 5 / CIS 6",
      cisSafeguard: "5.1 / 6.5",
      nistFunction: "PROTECT",
      ciaImpact: "Confidencialidade",
      owner: "IAM & Segurança (Graph API)",
      criticality: "Crítica",
      status: "Gap Detectado (MFA)",
      cvss: 7.8,
      notes: "Regra RULE-CIS-6.5-MFA detectou 3 contas administrativas legadas sem MFA obrigatório."
    },
    {
      id: "AST-003",
      name: "Política Geral de Segurança (PGSI), Normas ISO 27002 e Plano de Incidentes",
      category: "Documentação (CIS v8.1 - 1.1.2)",
      cisControl: "CIS 1 / CIS 17",
      cisSafeguard: "1.1.2 / 17.1",
      nistFunction: "GOVERN",
      ciaImpact: "Integridade",
      owner: "Governança & Compliance",
      criticality: "Alta",
      status: "Desatualizado (>180d)",
      cvss: 6.5,
      notes: "Novo ativo mapeado conforme atualização CIS v8.1 (1.1.2) e NIST CSF 2.0 (Govern)."
    },
    {
      id: "AST-004",
      name: "Workloads Cloud & Estações Corporativas (VMs Azure / Endpoints)",
      category: "Hardware",
      cisControl: "CIS 1 / CIS 4",
      cisSafeguard: "1.1 / 4.1",
      nistFunction: "IDENTIFY",
      ciaImpact: "Integridade",
      owner: "CloudOps / ITAM (Defender API)",
      criticality: "Média",
      status: "Inventariado (88% Conforme)",
      cvss: 5.9,
      notes: "Coleta agentless via Microsoft Defender for Cloud; 12% das VMs sem baseline CIS Level 1."
    },
    {
      id: "AST-005",
      name: "Banco de Dados Relacional ERP & Clientes (Dados Pessoais LGPD / GDPR)",
      category: "Dados / Software",
      cisControl: "CIS 2 / CIS 3",
      cisSafeguard: "3.1 / 3.11",
      nistFunction: "PROTECT",
      ciaImpact: "Confidencialidade",
      owner: "DBA / Encarregado DPO",
      criticality: "Crítica",
      status: "Vulnerável (Sem TDE Homolog)",
      cvss: 8.2,
      notes: "Regra RULE-CIS-3.11-ENC acusou ausência de criptografia KMS/TDE no banco de homologação."
    },
    {
      id: "AST-006",
      name: "Relatório de Impacto (RIPD/DPIA) e Mapeamento de Dados (RoPA LGPD/GDPR)",
      category: "Documentação (CIS v8.1 - 1.1.2)",
      cisControl: "CIS 3 / CIS 6",
      cisSafeguard: "1.1.2 / 3.1",
      nistFunction: "GOVERN",
      ciaImpact: "Confidencialidade",
      owner: "Comitê de Privacidade",
      criticality: "Alta",
      status: "Em elaboração",
      cvss: 6.1,
      notes: "Documentação obrigatória segundo LGPD (Lei 13.709/18), GDPR (UE 2016/679) e CIS 1.1.2."
    },
    {
      id: "AST-007",
      name: "Repositórios Git, Microsserviços e Pipelines CI/CD",
      category: "Software / Nuvem",
      cisControl: "CIS 2 / CIS 16",
      cisSafeguard: "16.1",
      nistFunction: "PROTECT",
      ciaImpact: "Integridade",
      owner: "Engenharia de Software",
      criticality: "Alta",
      status: "Sem SAST/SCA Contínuo",
      cvss: 7.4,
      notes: "Necessita integração de análise estática no ciclo iterativo de Engenharia de Software."
    },
    {
      id: "AST-008",
      name: "Cofre de Logs de Auditoria e Backup Imutável (AWS S3 / Azure Blob)",
      category: "Hardware / Nuvem",
      cisControl: "CIS 8 / CIS 11",
      cisSafeguard: "8.9 / 11.5",
      nistFunction: "RECOVER",
      ciaImpact: "Disponibilidade",
      owner: "Infraestrutura & SecOps",
      criticality: "Crítica",
      status: "Parcial (Retenção 30d)",
      cvss: 6.8,
      notes: "Backups ativos, mas retenção de logs abaixo de 90 dias e sem teste de restore automatizado."
    }
  ],

  // Os 18 Controles Críticos do CIS Controls v8.1 + Mapeamento ISO 27001/27002 + NIST CSF 2.0 + LGPD/GDPR
  cisControls: [
    {
      id: 1,
      code: "CIS 01",
      title: "Inventário e Controle de Ativos Corporativos",
      nistFunction: "IDENTIFY / GOVERN",
      iso27001: "ISO 27001 A.5.9, A.5.10 | ISO 27002 5.9",
      cia: "Integridade",
      asIsScore: 68,
      toBeScore: { IG1: 85, IG2: 95, IG3: 100 },
      highlightV81: "Inclui a salvaguarda 1.1.2 para inventariar ativos de Documentação (políticas, planos, arquiteturas) de forma contínua.",
      keySafeguards: [
        { id: "1.1", name: "Estabelecer e manter inventário detalhado de ativos corporativos (Coleta Agentless)", ig: "IG1", status: "Implementado" },
        { id: "1.1.2", name: "Inventariar ativos de Documentação de Segurança e Governança (Novo CIS v8.1)", ig: "IG1", status: "Parcial" },
        { id: "1.2", name: "Tratar ativos não autorizados na infraestrutura", ig: "IG1", status: "Parcial" },
        { id: "1.3", name: "Utilizar descoberta ativa/agentless via conectores de API", ig: "IG2", status: "Implementado" },
        { id: "1.4", name: "Usar DHCP/Cloud logging para atualizar inventário em tempo real", ig: "IG2", status: "Não Implementado" }
      ]
    },
    {
      id: 2,
      code: "CIS 02",
      title: "Inventário e Controle de Ativos de Software",
      nistFunction: "IDENTIFY",
      iso27001: "ISO 27001 A.5.9, A.8.19, A.8.32",
      cia: "Integridade",
      asIsScore: 55,
      toBeScore: { IG1: 80, IG2: 92, IG3: 100 },
      highlightV81: "Rastreamento automatizado de pacotes, microsserviços e bibliotecas de terceiros (SBOM).",
      keySafeguards: [
        { id: "2.1", name: "Estabelecer e manter inventário detalhado de software", ig: "IG1", status: "Implementado" },
        { id: "2.2", name: "Garantir que apenas softwares com suporte ativo sejam utilizados", ig: "IG1", status: "Parcial" },
        { id: "2.3", name: "Tratar softwares não autorizados ou sem licença", ig: "IG1", status: "Parcial" },
        { id: "2.5", name: "Permitir execução apenas de softwares autorizados (Allowlisting)", ig: "IG2", status: "Não Implementado" }
      ]
    },
    {
      id: 3,
      code: "CIS 03",
      title: "Proteção de Dados (LGPD & GDPR)",
      nistFunction: "PROTECT / IDENTIFY",
      iso27001: "ISO 27001 A.5.12, A.8.10, A.8.24 | LGPD Art. 46 | GDPR Art. 32",
      cia: "Confidencialidade",
      asIsScore: 42,
      toBeScore: { IG1: 80, IG2: 95, IG3: 100 },
      highlightV81: "Alinhado à LGPD, GDPR e ISO 27701 com mapeamento de fluxo de dados (RoPA) e criptografia KMS.",
      keySafeguards: [
        { id: "3.1", name: "Estabelecer e manter processo de gestão de dados (Data Mapping/RoPA)", ig: "IG1", status: "Parcial" },
        { id: "3.3", name: "Configurar listas de controle de acesso a dados (ACLs S3/Azure Blob)", ig: "IG1", status: "Implementado" },
        { id: "3.6", name: "Criptografar dados em dispositivos de usuários finais (BitLocker/LUKS)", ig: "IG1", status: "Não Implementado" },
        { id: "3.11", name: "Criptografar dados sensíveis em repouso em bancos e nuvem (TDE/KMS)", ig: "IG2", status: "Não Implementado" }
      ]
    },
    {
      id: 4,
      code: "CIS 04",
      title: "Configuração Segura de Ativos e Software (Hardening)",
      nistFunction: "PROTECT",
      iso27001: "ISO 27001 A.8.9, A.8.20 | ISO 27002 8.9",
      cia: "Integridade",
      asIsScore: 58,
      toBeScore: { IG1: 85, IG2: 95, IG3: 100 },
      highlightV81: "Avaliação contínua via AWS Audit Manager / Defender for Cloud e correção via IaC.",
      keySafeguards: [
        { id: "4.1", name: "Estabelecer e manter processo de configuração segura (CIS Benchmarks)", ig: "IG1", status: "Parcial" },
        { id: "4.7", name: "Gerenciar contas padrão em ativos e softwares", ig: "IG1", status: "Implementado" },
        { id: "4.8", name: "Desinstalar ou desabilitar serviços desnecessários em servidores", ig: "IG2", status: "Parcial" }
      ]
    },
    {
      id: 5,
      code: "CIS 05",
      title: "Gestão de Contas",
      nistFunction: "PROTECT / GOVERN",
      iso27001: "ISO 27001 A.5.15, A.5.16, A.5.17, A.5.18",
      cia: "Confidencialidade",
      asIsScore: 62,
      toBeScore: { IG1: 88, IG2: 96, IG3: 100 },
      highlightV81: "Foco na segregação de contas administrativas e auditoria contínua via Graph API.",
      keySafeguards: [
        { id: "5.1", name: "Estabelecer e manter inventário de contas ativas", ig: "IG1", status: "Implementado" },
        { id: "5.2", name: "Usar senhas fortes e exclusivas", ig: "IG1", status: "Implementado" },
        { id: "5.3", name: "Desabilitar contas inativas automaticamente após período definido", ig: "IG1", status: "Parcial" },
        { id: "5.4", name: "Restringir privilégios de administrador a contas dedicadas", ig: "IG1", status: "Não Implementado" }
      ]
    },
    {
      id: 6,
      code: "CIS 06",
      title: "Gestão de Controle de Acesso",
      nistFunction: "PROTECT",
      iso27001: "ISO 27001 A.5.15, A.8.2, A.8.3, A.8.5",
      cia: "Confidencialidade",
      asIsScore: 45,
      toBeScore: { IG1: 85, IG2: 95, IG3: 100 },
      highlightV81: "Verificação automatizada de MFA para acesso remoto, nuvem e contas privilegiadas.",
      keySafeguards: [
        { id: "6.1", name: "Estabelecer processo de concessão e revogação de acesso", ig: "IG1", status: "Parcial" },
        { id: "6.3", name: "Exigir MFA para todas as aplicações expostas externamente", ig: "IG1", status: "Parcial" },
        { id: "6.5", name: "Exigir MFA para todos os acessos administrativos", ig: "IG1", status: "Não Implementado" }
      ]
    },
    {
      id: 7,
      code: "CIS 07",
      title: "Gestão Contínua de Vulnerabilidades",
      nistFunction: "IDENTIFY / DETECT",
      iso27001: "ISO 27001 A.8.8",
      cia: "Integridade",
      asIsScore: 48,
      toBeScore: { IG1: 80, IG2: 92, IG3: 100 },
      highlightV81: "Varredura agentless contínua e priorização baseada em CVSS.",
      keySafeguards: [
        { id: "7.1", name: "Estabelecer e manter processo de gestão contínua de vulnerabilidades", ig: "IG1", status: "Implementado" },
        { id: "7.3", name: "Realizar gerenciamento automatizado de patches de SO", ig: "IG1", status: "Parcial" },
        { id: "7.5", name: "Realizar varreduras automatizadas de vulnerabilidades internas/cloud", ig: "IG2", status: "Parcial" }
      ]
    },
    {
      id: 8,
      code: "CIS 08",
      title: "Gestão de Logs de Auditoria",
      nistFunction: "DETECT",
      iso27001: "ISO 27001 A.8.15, A.8.16, A.8.17",
      cia: "Integridade",
      asIsScore: 44,
      toBeScore: { IG1: 75, IG2: 90, IG3: 100 },
      highlightV81: "Centralização de eventos (SIEM/CloudTrail/Azure Monitor) para correlação automática.",
      keySafeguards: [
        { id: "8.1", name: "Estabelecer e manter processo de gestão de logs de auditoria", ig: "IG1", status: "Parcial" },
        { id: "8.2", name: "Coletar logs de auditoria nos ativos críticos e APIs de nuvem", ig: "IG1", status: "Implementado" },
        { id: "8.9", name: "Centralizar o armazenamento e correlação de logs (SIEM >= 90 dias)", ig: "IG2", status: "Não Implementado" }
      ]
    },
    {
      id: 9,
      code: "CIS 09",
      title: "Proteções de E-mail e Navegador Web",
      nistFunction: "PROTECT",
      iso27001: "ISO 27001 A.8.23",
      cia: "Integridade",
      asIsScore: 65,
      toBeScore: { IG1: 85, IG2: 92, IG3: 100 },
      highlightV81: "Autenticação DMARC/SPF/DKIM e filtragem DNS.",
      keySafeguards: [
        { id: "9.1", name: "Garantir uso apenas de navegadores e clientes de e-mail suportados", ig: "IG1", status: "Implementado" },
        { id: "9.2", name: "Usar serviços de filtragem de DNS em todos os endpoints", ig: "IG1", status: "Parcial" },
        { id: "9.5", name: "Implementar DMARC, SPF e DKIM para prevenção de spoofing", ig: "IG2", status: "Parcial" }
      ]
    },
    {
      id: 10,
      code: "CIS 10",
      title: "Defesas contra Malware",
      nistFunction: "PROTECT / DETECT",
      iso27001: "ISO 27001 A.8.7",
      cia: "Integridade",
      asIsScore: 72,
      toBeScore: { IG1: 85, IG2: 95, IG3: 100 },
      highlightV81: "Integração de telemetria EDR/Defender for Endpoint.",
      keySafeguards: [
        { id: "10.1", name: "Implantar e manter software antimalware em todos os ativos", ig: "IG1", status: "Implementado" },
        { id: "10.2", name: "Configurar atualizações automáticas de assinaturas antimalware", ig: "IG1", status: "Implementado" },
        { id: "10.7", name: "Utilizar antimalware baseado em comportamento / EDR", ig: "IG2", status: "Parcial" }
      ]
    },
    {
      id: 11,
      code: "CIS 11",
      title: "Recuperação de Dados (Backups)",
      nistFunction: "RECOVER",
      iso27001: "ISO 27001 A.8.13, A.8.14",
      cia: "Disponibilidade",
      asIsScore: 58,
      toBeScore: { IG1: 88, IG2: 96, IG3: 100 },
      highlightV81: "Isolamento de backups (Object Lock) e validação automatizada de restauração.",
      keySafeguards: [
        { id: "11.1", name: "Estabelecer e manter processo de recuperação de dados", ig: "IG1", status: "Implementado" },
        { id: "11.2", name: "Realizar backups automatizados regularmente", ig: "IG1", status: "Implementado" },
        { id: "11.5", name: "Testar a recuperação de dados periodicamente", ig: "IG2", status: "Não Implementado" }
      ]
    },
    {
      id: 12,
      code: "CIS 12",
      title: "Gestão de Infraestrutura de Rede",
      nistFunction: "PROTECT",
      iso27001: "ISO 27001 A.8.20, A.8.21, A.8.22",
      cia: "Disponibilidade",
      asIsScore: 52,
      toBeScore: { IG1: 80, IG2: 90, IG3: 100 },
      highlightV81: "Segmentação de VPC/VNet e auditoria contínua de NSGs/Security Groups.",
      keySafeguards: [
        { id: "12.1", name: "Garantir que a infraestrutura de rede esteja atualizada", ig: "IG1", status: "Parcial" },
        { id: "12.2", name: "Estabelecer e manter arquitetura de rede segura e segmentada", ig: "IG2", status: "Parcial" }
      ]
    },
    {
      id: 13,
      code: "CIS 13",
      title: "Monitoramento e Defesa de Rede",
      nistFunction: "DETECT / RESPOND",
      iso27001: "ISO 27001 A.8.16, A.8.22",
      cia: "Disponibilidade",
      asIsScore: 35,
      toBeScore: { IG1: 60, IG2: 88, IG3: 100 },
      highlightV81: "Detecção de intrusão e telemetria de fluxo de rede.",
      keySafeguards: [
        { id: "13.1", name: "Centralizar alertas de eventos de segurança de rede", ig: "IG2", status: "Parcial" },
        { id: "13.3", name: "Implantar solução de detecção de intrusão de rede (NIDS/Cloud GuardDuty)", ig: "IG2", status: "Parcial" }
      ]
    },
    {
      id: 14,
      code: "CIS 14",
      title: "Conscientização e Treinamento em Segurança e Segurança Ocupacional",
      nistFunction: "GOVERN / PROTECT",
      iso27001: "ISO 27001 A.6.3 | ISO 45001 (Cultura Preventiva)",
      cia: "Confidencialidade",
      asIsScore: 50,
      toBeScore: { IG1: 85, IG2: 92, IG3: 100 },
      highlightV81: "Capacitação contínua contra phishing, tratamento de dados (LGPD/GDPR) e cultura organizacional.",
      keySafeguards: [
        { id: "14.1", name: "Estabelecer e manter programa de conscientização em segurança", ig: "IG1", status: "Parcial" },
        { id: "14.2", name: "Treinar colaboradores para reconhecer ataques de engenharia social", ig: "IG1", status: "Parcial" }
      ]
    },
    {
      id: 15,
      code: "CIS 15",
      title: "Gestão de Provedores de Serviços (Terceiros)",
      nistFunction: "GOVERN / IDENTIFY",
      iso27001: "ISO 27001 A.5.19, A.5.20, A.5.21 | GDPR Art. 28",
      cia: "Confidencialidade",
      asIsScore: 38,
      toBeScore: { IG1: 75, IG2: 88, IG3: 100 },
      highlightV81: "Avaliação de risco na cadeia de suprimentos e operadores de dados (LGPD/GDPR).",
      keySafeguards: [
        { id: "15.1", name: "Estabelecer e manter inventário de provedores de serviços", ig: "IG1", status: "Parcial" },
        { id: "15.4", name: "Garantir que contratos de fornecedores incluam requisitos de segurança e DPA", ig: "IG2", status: "Não Implementado" }
      ]
    },
    {
      id: 16,
      code: "CIS 16",
      title: "Segurança de Software de Aplicação (Engenharia de Software / DevSecOps)",
      nistFunction: "PROTECT",
      iso27001: "ISO 27001 A.8.25, A.8.26, A.8.27, A.8.28",
      cia: "Integridade",
      asIsScore: 40,
      toBeScore: { IG1: 60, IG2: 88, IG3: 100 },
      highlightV81: "Desenvolvimento seguro iterativo (Scrum/Sommerville) com validação de APIs e microsserviços.",
      keySafeguards: [
        { id: "16.1", name: "Estabelecer e manter processo de desenvolvimento seguro (SDLC Iterativo)", ig: "IG2", status: "Parcial" },
        { id: "16.3", name: "Realizar análise de causa raiz e testes automatizados de vulnerabilidades", ig: "IG2", status: "Parcial" }
      ]
    },
    {
      id: 17,
      code: "CIS 17",
      title: "Gestão de Resposta a Incidentes",
      nistFunction: "RESPOND / RECOVER",
      iso27001: "ISO 27001 A.5.24, A.5.25, A.5.26 | LGPD Art. 48",
      cia: "Disponibilidade",
      asIsScore: 42,
      toBeScore: { IG1: 80, IG2: 92, IG3: 100 },
      highlightV81: "Planos documentados, notificação ANPD/GDPR e orquestração via SOAR.",
      keySafeguards: [
        { id: "17.1", name: "Designar pessoal para gerenciar o tratamento de incidentes", ig: "IG1", status: "Parcial" },
        { id: "17.4", name: "Estabelecer e manter processo automatizado/documentado de resposta", ig: "IG2", status: "Não Implementado" }
      ]
    },
    {
      id: 18,
      code: "CIS 18",
      title: "Testes de Invasão (Pentest & Validação Empírica)",
      nistFunction: "IDENTIFY",
      iso27001: "ISO 27001 A.8.8, A.5.35",
      cia: "Confidencialidade",
      asIsScore: 30,
      toBeScore: { IG1: 50, IG2: 85, IG3: 100 },
      highlightV81: "Prova de Conceito (PoC) em ambiente controlado e validação empírica de controles.",
      keySafeguards: [
        { id: "18.1", name: "Estabelecer e manter programa de testes de invasão e PoC controlada", ig: "IG2", status: "Parcial" },
        { id: "18.2", name: "Realizar testes de invasão externos periódicos", ig: "IG2", status: "Não Implementado" }
      ]
    }
  ],

  // Etapa 3: Matriz de Riscos (ISO 31000 + CVSS)
  risks: [
    {
      id: "RSK-01",
      title: "Comprometimento de Contas Administrativas sem MFA (Detectado via Graph API)",
      cisRef: "CIS 05 / CIS 06 (6.5)",
      isoRef: "ISO 27001 A.8.5 | NIST PROTECT",
      probability: 5,
      impact: 5,
      cvss: 9.1,
      dimOperational: "Escalação de privilégio e paralisação de serviços de diretório.",
      dimFinancial: "Alto custo de resposta a incidente e indisponibilidade operacional.",
      dimReputational: "Perda severa de confiança e exposição de credenciais.",
      mitigationStatus: "Prioridade P1 (Imediata)"
    },
    {
      id: "RSK-02",
      title: "Exposição de Dados Pessoais (LGPD/GDPR) em Bancos Não Criptografados",
      cisRef: "CIS 03 (3.1 / 3.11)",
      isoRef: "ISO 27001 A.8.24 | LGPD Art. 46 | GDPR Art. 32",
      probability: 4,
      impact: 5,
      cvss: 8.2,
      dimOperational: "Vazamento de dumps de homologação detectado pelo conector AWS Audit Manager.",
      dimFinancial: "Sanções administrativas da ANPD (até 2% do faturamento) ou GDPR.",
      dimReputational: "Danos de imagem junto a titulares de dados e parceiros.",
      mitigationStatus: "Prioridade P1 (Imediata)"
    },
    {
      id: "RSK-03",
      title: "Defasagem de Ativos de Documentação (Salvaguarda 1.1.2) e Planilhas Estáticas",
      cisRef: "CIS 01 (1.1.2) / NIST Govern",
      isoRef: "ISO 27001 A.5.1, A.5.9",
      probability: 4,
      impact: 3,
      cvss: 6.5,
      dimOperational: "Diagnóstico manual rapidamente deixa de refletir o estado real da infraestrutura.",
      dimFinancial: "Alto custo de auditoria manual e retrabalho burocrático.",
      dimReputational: "Risco de não conformidade em auditorias externas.",
      mitigationStatus: "Mitigado pelo NEXO (P2)"
    },
    {
      id: "RSK-04",
      title: "Retenção Insuficiente de Logs de Auditoria (< 90 dias no SIEM)",
      cisRef: "CIS 08 (8.9) / CIS 13",
      isoRef: "ISO 27001 A.8.15, A.8.16",
      probability: 4,
      impact: 4,
      cvss: 7.5,
      dimOperational: "Alto tempo médio de detecção (MTTD) e perda de trilhas forenses.",
      dimFinancial: "Aumento exponencial do custo de contenção de incidentes.",
      dimReputational: "Incapacidade de reportar escopo exato à ANPD.",
      mitigationStatus: "Prioridade P2 (Curto Prazo)"
    },
    {
      id: "RSK-05",
      title: "Falha na Restauração de Backups em Cenário de Desastre",
      cisRef: "CIS 11 (11.5)",
      isoRef: "ISO 27001 A.8.13",
      probability: 3,
      impact: 5,
      cvss: 6.8,
      dimOperational: "RTO/RPO acima do tolerável por ausência de testes práticos de restore.",
      dimFinancial: "Perda de faturamento por hora de inatividade.",
      dimReputational: "Violação de SLAs contratuais com clientes.",
      mitigationStatus: "Prioridade P2 (Curto Prazo)"
    },
    {
      id: "RSK-06",
      title: "Desvios de Configuração (Drift) em VMs de Nuvem sem Hardening Automatizado",
      cisRef: "CIS 04 (4.1) / CIS 07",
      isoRef: "ISO 27002:2022 8.9",
      probability: 3,
      impact: 4,
      cvss: 7.4,
      dimOperational: "12% das instâncias avaliadas pelo Defender for Cloud com portas gerenciais expostas.",
      dimFinancial: "Exploração de falhas de configuração em nuvem.",
      dimReputational: "Comprometimento de microsserviços corporativos.",
      mitigationStatus: "Prioridade P3 (Médio Prazo)"
    }
  ],

  // Diagnóstico de Maturidade por Grupos de Implementação (CIS Controls v8.1 IG1, IG2, IG3 & CMMC)
  maturityGroups: [
    {
      id: "IG1",
      name: "IG1 — Higiene Cibernética Básica (CMMC Nível 1)",
      description: "Conjunto mínimo de 56 salvaguardas para defesa contra ataques gerais e não direcionados.",
      totalSafeguards: 56,
      implementedSafeguards: 39,
      keyFocus: "Inventário de Ativos e Documentação (1.1 / 1.1.2), MFA (6.3/6.5), Backups (11.2) e Antimalware (10.1).",
      remediationPriority: "Prioridade Imediata (Curto Prazo)"
    },
    {
      id: "IG2",
      name: "IG2 — Infraestrutura Híbrida e Risco Moderado/Alto (CMMC Nível 2)",
      description: "Adiciona 74 salvaguardas para organizações que gerenciam dados sensíveis (LGPD/GDPR) e múltiplos departamentos.",
      totalSafeguards: 130,
      implementedSafeguards: 68,
      keyFocus: "Descoberta Agentless (1.3), Criptografia em Repouso (3.11), SIEM Centralizado (8.9), DevSecOps (16.1) e Pentest (18.1).",
      remediationPriority: "Meta Principal do Projeto (Médio Prazo)"
    },
    {
      id: "IG3",
      name: "IG3 — Maturidade Avançada e Missão Crítica (CMMC Nível 3)",
      description: "Engloba todas as 153 salvaguardas do CIS v8.1 para contenção de ameaças persistentes avançadas (APT).",
      totalSafeguards: 153,
      implementedSafeguards: 72,
      keyFocus: "Allowlisting rigoroso de software (2.5), Caça a Ameaças Contínua e Red Team dedicado.",
      remediationPriority: "Evolução Contínua (Longo Prazo)"
    }
  ],

  // Etapa 4: Plano de Ação 5W2H e Automação (SOAR / IaC / DevSecOps)
  actionPlan5W2H: [
    {
      id: "ACT-01",
      what: "Traduzir controles normativos (CIS v8.1, ISO 27001, NIST CSF 2.0, LGPD/GDPR) no Motor Central de Regras e catalogar Documentação (1.1.2)",
      why: "Substituir planilhas manuais por avaliação lógica determinística sem falsos positivos",
      where: "Core Engine Python & Banco Relacional PostgreSQL",
      when: "Out/2026",
      who: "Davi Freire Zanatta & Luiz Alberto Ferreira Gomes",
      how: "Modelagem relacional no PostgreSQL e implementação do avaliador de regras JSON",
      howMuch: "R$ 0,00 (Desenvolvimento Acadêmico / Open Source)",
      ig: "IG1",
      cisControl: "CIS 01 (1.1.2) / Core Engine",
      status: "Concluído"
    },
    {
      id: "ACT-02",
      what: "Integrar Conectores Agentless RESTful com AWS Audit Manager, Microsoft Defender for Cloud e Entra ID/AD",
      why: "Automatizar a coleta contínua de evidências e reduzir em 97% o tempo de auditoria",
      where: "Camada de Integração Back-end (Python Async REST)",
      when: "Out/2026",
      who: "Engenharia de Software (Davi Zanatta)",
      how: "Consumo assíncrono de APIs RESTful com normalização de payloads JSON",
      howMuch: "R$ 0,00 (APIs Nativas Cloud)",
      ig: "IG2",
      cisControl: "CIS 01.3 / CIS 07 / CIS 08",
      status: "Concluído"
    },
    {
      id: "ACT-03",
      what: "Implantar MFA obrigatório em 100% das contas privilegiadas apontadas pela regra RULE-CIS-6.5-MFA",
      why: "Mitigar risco crítico RSK-01 (CVSS 9.1) identificado pelo conector de Identidade",
      where: "Active Directory Híbrido, Console AWS e Portal Azure",
      when: "Nov/2026 (Semana 1)",
      who: "Equipe de IAM & Segurança",
      how: "Política de Acesso Condicional e segregação de contas admin dedicadas (CIS 5.4 / 6.5)",
      howMuch: "R$ 4.500,00 / ano",
      ig: "IG1",
      cisControl: "CIS 05 / CIS 06",
      status: "Em Andamento"
    },
    {
      id: "ACT-04",
      what: "Habilitar Criptografia KMS/TDE nos bancos de dados e finalizar RoPA/RIPD (LGPD & GDPR)",
      why: "Eliminar o Gap na regra RULE-CIS-3.11-ENC e cumprir Art. 46 da LGPD e Art. 32 do GDPR",
      where: "Instâncias RDS/PostgreSQL e Repositório de Privacidade",
      when: "Nov/2026 (Semana 2)",
      who: "DBA & Encarregado de Dados (DPO)",
      how: "Aplicação de módulo Terraform Secure-by-Default com chaves KMS rotacionadas",
      howMuch: "R$ 3.200,00",
      ig: "IG1",
      cisControl: "CIS 03 (3.1 / 3.11)",
      status: "Em Andamento"
    },
    {
      id: "ACT-05",
      what: "Automatizar Hardening CIS Benchmark via Ansible e elevar retenção de logs SIEM para 90 dias",
      why: "Sanar desvios detectados nas regras RULE-CIS-4.1-HARDENING e RULE-CIS-8.9-SIEM",
      where: "Workloads Linux/Windows e Log Analytics / S3 Object Lock",
      when: "Nov/2026 (Semana 3)",
      who: "Engenharia DevSecOps / SecOps",
      how: "Execução de Playbook Ansible no pipeline CI/CD e política de retenção imutável",
      howMuch: "R$ 6.800,00",
      ig: "IG2",
      cisControl: "CIS 04 / CIS 08",
      status: "Pendente"
    },
    {
      id: "ACT-06",
      what: "Executar Validação de Eficácia (Nível 3): Comparativo Auditoria Automatizada vs. Checklist Manual e PoC",
      why: "Comprovar precisão sistêmica, ausência de falsos positivos e consolidação do Relatório Final",
      where: "Ambiente Controlado de Piloto (PoC)",
      when: "Nov/2026 (Até 30/11)",
      who: "Davi Freire Zanatta & Luiz Alberto Ferreira Gomes",
      how: "Bateria de testes de software (Nível 1), PoC Agentless (Nível 2) e pareamento com auditoria manual (Nível 3)",
      howMuch: "R$ 0,00 (Validação Acadêmica)",
      ig: "IG2",
      cisControl: "CIS 18 / Validação Seção 4.3",
      status: "Em Andamento"
    }
  ],

  // Artefatos de Engenharia de Software e Automação (Python Backend, PostgreSQL Schema, Ansible, SOAR, Terraform)
  automationTemplates: {
    python_backend_connector: {
      title: "Back-end Python — Motor Central de Regras & Conectores RESTful (AWS Audit Manager / Azure Defender)",
      framework: "Arquitetura Seção 4.2 (Python Async JSON + Avaliação Agentless)",
      language: "python",
      code: `# =====================================================================
# NEXO - Motor Central de Regras (Core) & Conectores Agentless RESTful
# Autores: Davi Freire Zanatta & Luiz Alberto Ferreira Gomes
# PUC Minas Poços de Caldas - Ciência da Computação (Engenharia de Software)
# =====================================================================
import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Any, List

class AgentlessCloudConnector:
    """Consome APIs RESTful (AWS Audit Manager, Azure Defender for Cloud, IAM Graph) de forma assíncrona."""

    async def fetch_aws_audit_manager_evidence(self) -> Dict[str, Any]:
        await asyncio.sleep(0.05)  # Simula chamada HTTPS RESTful assíncrona
        return {
            "provider": "AWS_AUDIT_MANAGER",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rds_homolog_encrypted": False,
            "s3_audit_bucket_object_lock": True,
            "contains_lgpd_pii": True
        }

    async def fetch_azure_defender_compliance(self) -> Dict[str, Any]:
        await asyncio.sleep(0.05)
        return {
            "provider": "AZURE_DEFENDER_FOR_CLOUD",
            "cis_benchmark_level1_score": 88.0,
            "log_analytics_retention_days": 30,
            "immutable_storage": True
        }

    async def fetch_iam_identity_governance(self) -> Dict[str, Any]:
        await asyncio.sleep(0.05)
        return {
            "provider": "IAM_ENTRA_AD_GRAPH",
            "total_privileged_accounts": 12,
            "mfa_enabled_privileged_accounts": 9,
            "cis_1_1_2_docs_up_to_date": False
        }

class CoreGapRuleEngine:
    """Motor Central de Regras: traduz exigências da ISO 27001, NIST CSF 2.0, CIS v8.1, LGPD e GDPR em regras lógicas."""

    def evaluate_all(self, aws: Dict[str, Any], azure: Dict[str, Any], iam: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = []

        # Regra 1: CIS 6.5 / ISO 27001 A.8.5 - MFA em 100% das contas privilegiadas
        mfa_ok = iam["mfa_enabled_privileged_accounts"] == iam["total_privileged_accounts"]
        results.append({
            "rule_id": "RULE-CIS-6.5-MFA",
            "normative_refs": ["CIS v8.1 6.5", "ISO/IEC 27001:2022 A.8.5", "NIST CSF 2.0 PR.AA-01"],
            "compliant": mfa_ok,
            "as_is_ratio": round(iam["mfa_enabled_privileged_accounts"] / iam["total_privileged_accounts"] * 100, 1),
            "gap_detected": not mfa_ok
        })

        # Regra 2: CIS 3.11 / LGPD Art. 46 / GDPR Art. 32 - Criptografia de Dados Pessoais
        enc_ok = (not aws["contains_lgpd_pii"]) or aws["rds_homolog_encrypted"]
        results.append({
            "rule_id": "RULE-CIS-3.11-ENC",
            "normative_refs": ["CIS v8.1 3.11", "LGPD Art. 46", "GDPR Art. 32", "ISO/IEC 27001:2022 A.8.24"],
            "compliant": enc_ok,
            "as_is_ratio": 100.0 if enc_ok else 50.0,
            "gap_detected": not enc_ok
        })

        # Regra 3: CIS 1.1.2 (Novidade v8.1) - Ativos de Documentação atualizados
        doc_ok = iam["cis_1_1_2_docs_up_to_date"]
        results.append({
            "rule_id": "RULE-CIS-1.1.2-DOC",
            "normative_refs": ["CIS v8.1 1.1.2", "NIST CSF 2.0 GOVERN", "ISO/IEC 27001:2022 A.5.1"],
            "compliant": doc_ok,
            "as_is_ratio": 100.0 if doc_ok else 65.0,
            "gap_detected": not doc_ok
        })

        return results`
    },
    postgresql_schema: {
      title: "Banco de Dados PostgreSQL — Esquema Relacional de Normativas, Regras e Evidências",
      framework: "Arquitetura Seção 4.2 (Integridade Relacional PostgreSQL)",
      language: "sql",
      code: `-- =====================================================================
-- NEXO - Modelagem de Banco de Dados Relacional (PostgreSQL 16)
-- Centraliza a arquitetura de regras, controles normativos, usuários e evidências JSONB
-- =====================================================================

CREATE TABLE frameworks_normativos (
    id SERIAL PRIMARY KEY,
    sigla VARCHAR(40) NOT NULL UNIQUE, -- Ex: 'CIS_V8_1', 'ISO_27001_2022', 'NIST_CSF_2_0', 'LGPD', 'GDPR'
    nome_completo VARCHAR(160) NOT NULL,
    versao VARCHAR(30) NOT NULL,
    orgao_emissor VARCHAR(100) NOT NULL
);

CREATE TABLE controles_normativos (
    id SERIAL PRIMARY KEY,
    framework_id INT NOT NULL REFERENCES frameworks_normativos(id) ON DELETE CASCADE,
    codigo_controle VARCHAR(30) NOT NULL, -- Ex: 'CIS 1.1.2', 'A.8.24', 'PR.AA-01', 'Art. 46'
    titulo VARCHAR(200) NOT NULL,
    funcao_nist VARCHAR(30),              -- GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER
    pilar_cia VARCHAR(25) NOT NULL,       -- Confidencialidade, Integridade, Disponibilidade
    grupo_implementacao VARCHAR(10),      -- IG1, IG2, IG3
    meta_to_be NUMERIC(5,2) DEFAULT 95.00
);

CREATE TABLE regras_auditoria_core (
    rule_id VARCHAR(40) PRIMARY KEY,
    nome_regra VARCHAR(160) NOT NULL,
    conector_origem VARCHAR(50) NOT NULL, -- 'AWS_AUDIT_MANAGER', 'AZURE_DEFENDER', 'IAM_GRAPH'
    expressao_logica TEXT NOT NULL,
    ativa BOOLEAN DEFAULT TRUE
);

-- Tabela associativa N:N entre Regras Lógicas de Software e Controles de Múltiplos Frameworks
CREATE TABLE mapeamento_regra_controle (
    rule_id VARCHAR(40) REFERENCES regras_auditoria_core(rule_id) ON DELETE CASCADE,
    controle_id INT REFERENCES controles_normativos(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, controle_id)
);

CREATE TABLE evidencias_coletadas_agentless (
    id BIGSERIAL PRIMARY KEY,
    rule_id VARCHAR(40) NOT NULL REFERENCES regras_auditoria_core(rule_id),
    coletado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload_json JSONB NOT NULL,          -- Evidência estruturada retornada pela API Cloud/IAM
    conforme BOOLEAN NOT NULL,
    score_as_is NUMERIC(5,2) NOT NULL,
    falso_positivo_auditado BOOLEAN DEFAULT FALSE
);`
    },
    powershell_cis_audit: {
      title: "Coletor Automatizado As-Is (PowerShell - CIS Controls 1, 2, 4 e 1.1.2)",
      framework: "CIS Controls v8.1 (IG1/IG2) & ISO/IEC 27004",
      language: "powershell",
      code: `# =====================================================================
# NEXO - Coletor Automatizado de Conformidade CIS Controls v8.1
# Autores: Davi Freire Zanatta & Luiz Alberto Ferreira Gomes
# Controles auditados: CIS 1 (Ativos + 1.1.2 Documentação), CIS 3, CIS 5
# =====================================================================

$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "[NEXO] Iniciando Auditoria Automatizada CIS Controls v8.1 - $ReportDate" -ForegroundColor Cyan

# 1. CIS Control 1.1 - Inventário de Hardware e SO
$OSInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture

# 2. CIS Control 1.1.2 (Novidade v8.1) - Verificação de Ativos de Documentação Obrigatórios
$RequiredDocs = @(
    "PGSI_Politica_Geral_Seguranca.pdf",
    "Plano_Resposta_Incidentes_CIS17.pdf",
    "Mapeamento_Fluxo_Dados_RoPA_LGPD_GDPR.xlsx",
    "Matriz_Conformidade_CIS_ISO27001.json"
)
$DocsFolder = "C:\\Governanca_SI\\Documentacao"
$DocStatus = foreach ($doc in $RequiredDocs) {
    $exists = Test-Path (Join-Path $DocsFolder $doc)
    [PSCustomObject]@{ Documento = $doc; Salvaguarda = "CIS 1.1.2"; Conforme = $exists }
}

# 3. CIS Control 3.6 - Criptografia de Endpoint (BitLocker)
$BitLocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
$EncryptionCompliant = ($null -ne $BitLocker -and $BitLocker.ProtectionStatus -eq 'On')

$AuditResult = [PSCustomObject]@{
    Timestamp          = $ReportDate
    Hostname           = $env:COMPUTERNAME
    OS                 = $OSInfo.Caption
    CIS_1_1_2_Docs     = $DocStatus
    CIS_3_6_BitLocker  = $EncryptionCompliant
}

$AuditResult | ConvertTo-Json -Depth 4 | Out-File -FilePath ".\\nexo_cis_evidence.json" -Encoding utf8`
    },
    soar_playbook: {
      title: "Playbook SOAR & IaC — Remediação Automatizada de Gaps (CIS 03, 04, 17)",
      framework: "CIS Control 03, 04, 17 & NIST CSF 2.0 (Respond)",
      language: "yaml",
      code: `# =====================================================================
# NEXO - Orquestração, Automação e Resposta de Segurança (SOAR)
# Gatilho: Regra Não Conforme no Motor Central de Regras (Core Engine)
# =====================================================================
playbook_name: "SOAR-NEXO-Remediacao-Continua"
version: "2.0"
normative_mapping: ["CIS 6.5", "CIS 3.11", "ISO 27001 A.8.5", "LGPD Art. 46"]
trigger:
  source: "NEXO_CORE_RULE_ENGINE"
  condition: "rule.gap_detected == true and risk.cvss >= 7.5"

steps:
  - step: 1
    action: "persist_evidence_postgresql"
    description: "Gravar payload JSONB na tabela evidencias_coletadas_agentless (PostgreSQL)"
  - step: 2
    action: "enforce_iam_mfa_policy"
    description: "Ativar exigência de MFA condicional via Microsoft Graph API para contas privilegiadas"
    automated: true
  - step: 3
    action: "trigger_terraform_kms_encryption"
    description: "Executar pipeline IaC para aplicar criptografia KMS e Object Lock em buckets de auditoria"
    automated: true`
    }
  }
};

// 18 Questões Estruturadas do Questionário de Levantamento As-Is (CIS Controls v8.1)
const NEXO_QUESTIONNAIRE_QUESTIONS = [
  {
    controlId: 1,
    code: "CIS 01",
    title: "Inventário e Controle de Ativos Corporativos & Documentação de Segurança",
    nistCategory: "IDENTIFY_GOVERN",
    question: "A empresa possui um inventário formal e atualizado de todos os dispositivos conectados à rede e mantém seus ativos de Documentação de Segurança (Políticas, Planos de Resposta, Normas ISO) revisados há menos de 180 dias (Salvaguarda 1.1.2 do CIS v8.1)?",
    guide: "Verifique a existência de CMDB automatizado e se a Política Geral de Segurança (PGSI) e planos operacionais foram revisados no último semestre.",
    normatives: "CIS v8.1 (1.1, 1.1.2) | ISO 27001 A.5.9, A.5.10 | NIST CSF 2.0 (ID.AM, GV.PO)"
  },
  {
    controlId: 2,
    code: "CIS 02",
    title: "Inventário e Controle de Ativos de Software",
    nistCategory: "IDENTIFY_GOVERN",
    question: "A organização rastreia todos os softwares instalados nos servidores e estações, bloqueando aplicações não autorizadas (Allowlisting) e mantendo apenas versões suportadas com atualizações do fabricante?",
    guide: "Avalie controle de licenciamento, rastreamento de SBOM/bibliotecas e política de bloqueio de softwares não homologados.",
    normatives: "CIS v8.1 (2.1, 2.5) | ISO 27001 A.8.19, A.8.32 | NIST CSF 2.0 (ID.AM-02)"
  },
  {
    controlId: 3,
    code: "CIS 03",
    title: "Proteção de Dados e Privacidade (LGPD & GDPR)",
    nistCategory: "PROTECT",
    question: "Os dados pessoais e confidenciais possuem mapeamento de fluxo (RoPA/LGPD) e utilizam criptografia robusta (AES-256) em repouso (bancos de dados, notebooks via BitLocker) e em trânsito (TLS 1.3)?",
    guide: "Conforme Art. 46 da LGPD e Art. 32 do GDPR, verifique se volumes RDS/S3 e discos de estações utilizam criptografia gerenciada por KMS/TDE.",
    normatives: "CIS v8.1 (3.1, 3.11) | LGPD Art. 46 | GDPR Art. 32 | ISO 27001 A.8.24"
  },
  {
    controlId: 4,
    code: "CIS 04",
    title: "Configuração Segura de Ativos e Software (Hardening)",
    nistCategory: "PROTECT",
    question: "Existe uma configuração-padrão de segurança (Baseline CIS Benchmark) formalizada e aplicada a servidores, sistemas operacionais e dispositivos de rede antes de entrarem em produção?",
    guide: "Cheque se há playbooks IaC (Ansible/Terraform) ou GPOs que desativam serviços desnecessários e fecham portas inseguras (RDP/Telnet/FTP).",
    normatives: "CIS v8.1 (4.1, 4.8) | ISO 27001 A.8.9 | ISO 27002 8.9 | NIST PR.IP"
  },
  {
    controlId: 5,
    code: "CIS 05",
    title: "Gestão de Contas Corporativas e Privilegiadas",
    nistCategory: "PROTECT",
    question: "As contas de administradores (Root, Domain Admin) são dedicadas, segregadas do e-mail do dia a dia, e têm suas permissões revisadas periodicamente com desativação imediata no desligamento?",
    guide: "Nenhum usuário deve usar conta de privilégio administrativo para tarefas diárias. Verifique a adoção do princípio do menor privilégio.",
    normatives: "CIS v8.1 (5.1, 5.4) | ISO 27001 A.5.15, A.5.18 | NIST PR.AA-01"
  },
  {
    controlId: 6,
    code: "CIS 06",
    title: "Gestão de Controle de Acesso e Autenticação Multifator (MFA)",
    nistCategory: "PROTECT",
    question: "O segundo fator de autenticação (MFA) é obrigatório para 100% dos acessos administrativos e acessos remotos (VPN, Cloud, E-mail corporativo), sem exceções legadas?",
    guide: "Conforme Salvaguarda 6.5 do CIS v8.1 e ISO 27001 A.8.5, o MFA deve cobrir todas as contas privilegiadas e conexões externas.",
    normatives: "CIS v8.1 (6.3, 6.5) | ISO 27001 A.8.5 | NIST CSF 2.0 PR.AA-05"
  },
  {
    controlId: 7,
    code: "CIS 07",
    title: "Gestão Contínua de Vulnerabilidades",
    nistCategory: "IDENTIFY_GOVERN",
    question: "A empresa realiza varreduras automáticas de vulnerabilidades pelo menos mensalmente e aplica patches críticos de segurança dentro de um SLA pré-definido?",
    guide: "Avalie se há scanners automatizados de vulnerabilidades e se correções críticas (CVSS >= 7.0) são implantadas rapidamente.",
    normatives: "CIS v8.1 (7.1, 7.5) | ISO 27001 A.8.8 | NIST CSF 2.0 ID.RA-01"
  },
  {
    controlId: 8,
    code: "CIS 08",
    title: "Gestão e Retenção de Logs de Auditoria (SIEM)",
    nistCategory: "DETECT",
    question: "Os logs de segurança e autenticação são centralizados em um servidor/SIEM dedicado, com proteção contra exclusão (imutabilidade) e retenção mínima de 90 dias para fins forenses?",
    guide: "Verifique se há encaminhamento contínuo de logs de firewall, AD e servidores, e se a retenção atende normas de auditoria e incidentes.",
    normatives: "CIS v8.1 (8.2, 8.9) | ISO 27001 A.8.15, A.8.16 | NIST DE.CM-01"
  },
  {
    controlId: 9,
    code: "CIS 09",
    title: "Proteções de E-mail e Navegadores Web",
    nistCategory: "PROTECT",
    question: "O domínio corporativo possui proteções ativas contra spoofing (SPF, DKIM, DMARC com política de rejeição) e ferramentas de filtro de conteúdo e DNS malicioso nos navegadores?",
    guide: "Cheque se os registros DNS possuem DMARC configurado em 'p=reject' ou 'p=quarantine' e se há bloqueio de domínios maliciosos.",
    normatives: "CIS v8.1 (9.2, 9.5) | ISO 27001 A.8.23 | NIST PR.AT-01"
  },
  {
    controlId: 10,
    code: "CIS 10",
    title: "Defesas Contra Malware (EDR Comportamental)",
    nistCategory: "PROTECT",
    question: "Todas as estações de trabalho e servidores corporativos contam com solução de detecção e resposta em endpoints (EDR) com atualização automática e análise comportamental?",
    guide: "Antivírus tradicional baseado apenas em assinaturas não é suficiente; é necessária proteção contra ransomware e resposta automatizada a ameaças.",
    normatives: "CIS v8.1 (10.1, 10.2) | ISO 27001 A.8.7 | NIST PR.PT-01"
  },
  {
    controlId: 11,
    code: "CIS 11",
    title: "Recuperação de Dados e Backups Imutáveis",
    nistCategory: "RESPOND_RECOVER",
    question: "Os dados críticos possuem cópias de backup automatizadas, com pelo menos uma cópia isolada/imutável (regra 3-2-1), e testes práticos de restauração são executados pelo menos semestralmente?",
    guide: "Conforme CIS 11.5 e ISO 27001 A.8.13, backups que nunca foram restaurados para teste não garantem recuperação contra incidentes de ransomware.",
    normatives: "CIS v8.1 (11.1, 11.5) | ISO 27001 A.8.13 | NIST RC.RP-01"
  },
  {
    controlId: 12,
    code: "CIS 12",
    title: "Gestão de Infraestrutura e Segmentação de Rede",
    nistCategory: "PROTECT",
    question: "A rede corporativa é segmentada em VLANs/VPCs (isolando servidores de produção, banco de dados, rede corporativa e rede de visitantes), com regras restritivas de firewall?",
    guide: "Evite redes planas. Servidores que armazenam dados sensíveis devem estar em zonas desmilitarizadas (DMZ) ou sub-redes isoladas.",
    normatives: "CIS v8.1 (12.1, 12.4) | ISO 27001 A.8.20, A.8.22 | NIST PR.AC-05"
  },
  {
    controlId: 13,
    code: "CIS 13",
    title: "Monitoramento e Defesa de Rede (IDS/IPS)",
    nistCategory: "DETECT",
    question: "Existem mecanismos de monitoramento contínuo de tráfego de rede (IDS/IPS ou detecção de anomalias na nuvem) configurados para alertar sobre conexões suspeitas ou varreduras de portas?",
    guide: "Avalie se ferramentas como Suricata, Snort, AWS GuardDuty ou Azure Network Watcher monitoram o perímetro corporativo.",
    normatives: "CIS v8.1 (13.1, 13.3) | ISO 27001 A.8.16 | NIST DE.AE-01"
  },
  {
    controlId: 14,
    code: "CIS 14",
    title: "Conscientização e Treinamento em Segurança",
    nistCategory: "IDENTIFY_GOVERN",
    question: "Todos os colaboradores passam por treinamentos periódicos de conscientização sobre segurança da informação, privacidade de dados (LGPD) e simulações regulares de phishing?",
    guide: "O fator humano é o elo mais crítico. Deve haver campanhas anuais obrigatórias de segurança e testes práticos de phishing.",
    normatives: "CIS v8.1 (14.1, 14.3) | ISO 27001 A.6.3 | NIST PR.AT-01"
  },
  {
    controlId: 15,
    code: "CIS 15",
    title: "Gestão de Segurança de Fornecedores e Terceiros",
    nistCategory: "IDENTIFY_GOVERN",
    question: "Existe processo de homologação de fornecedores, avaliação de riscos de terceiros com acesso à rede e cláusulas contratuais de confidencialidade e proteção de dados (DPA)?",
    guide: "A LGPD responsabiliza controladores por falhas em parceiros. Cláusulas de segurança e auditorias devem ser exigidas em contrato.",
    normatives: "CIS v8.1 (15.1, 15.3) | ISO 27001 A.5.19 | GDPR Art. 28 | LGPD Art. 39"
  },
  {
    controlId: 16,
    code: "CIS 16",
    title: "Segurança de Software de Aplicação (DevSecOps)",
    nistCategory: "PROTECT",
    question: "O ciclo de desenvolvimento de software inclui validações automatizadas de segurança (SAST, DAST, análise de dependências SCA) integradas na esteira de CI/CD antes da publicação?",
    guide: "Em conformidade com DevSecOps e CIS 16, código-fonte e contêineres devem passar por verificação de segurança antes de ir para produção.",
    normatives: "CIS v8.1 (16.1, 16.3) | ISO 27001 A.8.25, A.8.28 | NIST PR.DS-01"
  },
  {
    controlId: 17,
    code: "CIS 17",
    title: "Gestão e Resposta a Incidentes de Segurança (SOAR)",
    nistCategory: "RESPOND_RECOVER",
    question: "A organização possui um Plano de Resposta a Incidentes formalizado, equipe ou responsável designado, playbooks de contenção e canal de comunicação de incidentes conforme Art. 48 da LGPD?",
    guide: "O tempo de resposta e comunicação à ANPD e aos titulares depende de um fluxo pré-estabelecido de contenção, triagem e comunicação.",
    normatives: "CIS v8.1 (17.1, 17.4) | ISO 27001 A.5.24 | LGPD Art. 48 | NIST RS.CO"
  },
  {
    controlId: 18,
    code: "CIS 18",
    title: "Testes de Invasão (Pentest Empírico)",
    nistCategory: "IDENTIFY_GOVERN",
    question: "São realizados testes periódicos de invasão (pentests) conduzidos por profissionais especializados para identificar vulnerabilidades exploráveis na infraestrutura e aplicações?",
    guide: "Avaliações empíricas externas e internas comprovam a eficácia das defesas e identificam falhas antes de atores maliciosos.",
    normatives: "CIS v8.1 (18.1, 18.2) | ISO 27001 A.8.8, A.5.35 | NIST ID.RA-02"
  }
];
