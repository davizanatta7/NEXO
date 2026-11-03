#!/usr/bin/env python3
"""
NEXO - Coletor Automatizado de Evidências (As-Is) & Diagnóstico CIS Controls v8.1
Projeto de Estágio Obrigatório - PUC Minas (Campus Poços de Caldas)
Aluno: Davi Freire Zanatta | Curso: Ciência da Computação (2º Semestre de 2026)

Este script exemplifica a Etapa 1 (Avaliação As-Is) e Etapa 4 (Automação de Coleta - ISO/IEC 27004),
verificando informações do host, presença de ativos de Documentação (Salvaguarda 1.1.2 introduzida
no CIS Controls v8.1) e gerando um relatório JSON de evidências.
"""

import datetime
import json
import os
import platform
import socket
from pathlib import Path


REQUIRED_DOCUMENTATION_ASSETS_1_1_2 = [
    {"id": "DOC-01", "name": "Política Geral de Segurança da Informação (PGSI)", "cis": "1.1.2 / NIST GOVERN"},
    {"id": "DOC-02", "name": "Plano de Resposta a Incidentes (PRI)", "cis": "1.1.2 / 17.4"},
    {"id": "DOC-03", "name": "Mapeamento de Fluxo de Dados (RoPA - LGPD / ISO 27701)", "cis": "1.1.2 / 3.1"},
    {"id": "DOC-04", "name": "Matriz de Conformidade CIS Controls v8.1 x ISO/IEC 27001:2022", "cis": "1.1.2"},
]


def collect_host_inventory():
    """Coleta informações básicas de Hardware e Sistema Operacional (CIS Control 1 & 2)."""
    return {
        "hostname": socket.gethostname(),
        "os_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python_runtime": platform.python_version(),
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def audit_documentation_assets(workspace_dir: Path):
    """
    Verifica a existência de artefatos do projeto e simula a auditoria
    da Salvaguarda 1.1.2 (Ativos de Documentação - novidade do CIS Controls v8.1).
    """
    prototype_files = ["index.html", "data.js", "app.js", "styles.css"]
    existing_files = [f for f in prototype_files if (workspace_dir / f).exists()]

    return {
        "cis_safeguard": "1.1.2 (Documentação como Ativo - CIS Controls v8.1)",
        "nist_csf_2_0_function": "GOVERN (GV)",
        "cataloged_Governance_docs": REQUIRED_DOCUMENTATION_ASSETS_1_1_2,
        "workspace_artifacts_found": existing_files,
        "compliance_ratio": round(len(existing_files) / len(prototype_files) * 100, 1),
    }


def main():
    workspace = Path(__file__).resolve().parent.parent
    report = {
        "project": "NEXO - Gap Analysis e Segurança da Informação Baseado nos CIS Controls v8.1",
        "author": "Davi Freire Zanatta (PUC Minas Poços de Caldas)",
        "host_inventory_cis_01_02": collect_host_inventory(),
        "documentation_audit_cis_1_1_2": audit_documentation_assets(workspace),
    }

    output_path = workspace / "nexo_evidence_report.json"
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[NEXO] Auditoria As-Is concluída com sucesso!")
    print(f"[NEXO] Evidência salva em: {output_path}")


if __name__ == "__main__":
    main()

