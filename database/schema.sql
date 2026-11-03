-- =====================================================================
-- NEXO — Automatização de Gap Analysis em Sistemas de Gestão de Segurança
-- Autores: Davi Freire Zanatta & Luiz Alberto Ferreira Gomes
-- PUC Minas (Campus Poços de Caldas) — Ciência da Computação — 2º Semestre 2026
-- Seção 4.2.2: Banco de Dados Relacional PostgreSQL
-- =====================================================================

CREATE TABLE IF NOT EXISTS usuarios_auditores (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(120) NOT NULL,
    email VARCHAR(160) NOT NULL UNIQUE,
    papel VARCHAR(50) NOT NULL DEFAULT 'AUDITOR_SI',
    mfa_habilitado BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS frameworks_normativos (
    id SERIAL PRIMARY KEY,
    sigla VARCHAR(40) NOT NULL UNIQUE,
    nome_completo VARCHAR(200) NOT NULL,
    versao VARCHAR(30) NOT NULL,
    ano_publicacao INT NOT NULL
);

CREATE TABLE IF NOT EXISTS controles_normativos (
    id SERIAL PRIMARY KEY,
    framework_id INT NOT NULL REFERENCES frameworks_normativos(id) ON DELETE CASCADE,
    codigo_controle VARCHAR(40) NOT NULL,
    titulo VARCHAR(220) NOT NULL,
    funcao_nist VARCHAR(30) NOT NULL,     -- GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER
    pilar_cia VARCHAR(30) NOT NULL,       -- Confidencialidade, Integridade, Disponibilidade
    grupo_ig VARCHAR(10) DEFAULT 'IG2',   -- IG1, IG2, IG3
    meta_to_be NUMERIC(5,2) NOT NULL DEFAULT 95.00
);

CREATE TABLE IF NOT EXISTS ativos_infraestrutura (
    asset_id VARCHAR(30) PRIMARY KEY,
    nome VARCHAR(180) NOT NULL,
    categoria VARCHAR(80) NOT NULL,       -- Inclui 'Documentação (CIS v8.1 - 1.1.2)'
    conector_origem VARCHAR(60) NOT NULL, -- 'AWS_AUDIT_MANAGER', 'AZURE_DEFENDER', 'IAM_GRAPH'
    criticidade VARCHAR(20) NOT NULL,
    cvss_base NUMERIC(3,1) NOT NULL DEFAULT 5.0,
    atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS regras_auditoria_core (
    rule_id VARCHAR(50) PRIMARY KEY,
    nome_regra VARCHAR(180) NOT NULL,
    conector_api VARCHAR(60) NOT NULL,
    expressao_logica TEXT NOT NULL,
    ativa BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS mapeamento_regra_controle (
    rule_id VARCHAR(50) REFERENCES regras_auditoria_core(rule_id) ON DELETE CASCADE,
    controle_id INT REFERENCES controles_normativos(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, controle_id)
);

CREATE TABLE IF NOT EXISTS evidencias_coletadas_agentless (
    id BIGSERIAL PRIMARY KEY,
    rule_id VARCHAR(50) NOT NULL REFERENCES regras_auditoria_core(rule_id),
    asset_id VARCHAR(30) REFERENCES ativos_infraestrutura(asset_id),
    coletado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload_json JSONB NOT NULL,
    conforme BOOLEAN NOT NULL,
    score_as_is NUMERIC(5,2) NOT NULL,
    falso_positivo BOOLEAN NOT NULL DEFAULT FALSE
);

-- Carga Inicial dos Frameworks Normativos Citados na Pesquisa
INSERT INTO frameworks_normativos (sigla, nome_completo, versao, ano_publicacao) VALUES
('CIS_CONTROLS', 'CIS Critical Security Controls', 'v8.1', 2024),
('ISO_27001', 'ABNT NBR ISO/IEC 27001 - Sistemas de Gestão da Segurança da Informação', '2022', 2022),
('ISO_27002', 'ABNT NBR ISO/IEC 27002 - Controles de Segurança da Informação', '2022', 2022),
('NIST_CSF', 'The NIST Cybersecurity Framework', '2.0', 2024),
('LGPD', 'Lei Geral de Proteção de Dados Pessoais (Lei nº 13.709/2018)', '2018', 2018),
('GDPR', 'General Data Protection Regulation (Regulamento UE 2016/679)', '2016', 2016),
('ISO_45001', 'ABNT NBR ISO 45001 - Sistemas de Gestão de Saúde e Segurança Ocupacional', '2018', 2018)
ON CONFLICT (sigla) DO NOTHING;

