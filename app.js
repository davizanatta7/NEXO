// Lógica Interativa do Protótipo NEXO v2.1 - Automatização de Gap Analysis em Sistemas de Gestão de Segurança
const STORAGE_KEY = "NEXO_PROTOTYPE_STATE_V81_CIS_CMMC";

let appState = loadState();

function loadState() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      if (parsed.apiConnectors && parsed.coreRuleEngine && parsed.maturityGroups) {
        return parsed;
      }
    }
  } catch (e) {
    console.warn("Usando estado padrão em memória:", e);
  }
  return JSON.parse(JSON.stringify(NEXO_DEFAULT_DATA));
}

function saveState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(appState));
  } catch (e) {
    console.warn("Não foi possível persistir no localStorage:", e);
  }
}

function resetPrototypeData() {
  localStorage.removeItem(STORAGE_KEY);
  appState = JSON.parse(JSON.stringify(NEXO_DEFAULT_DATA));
  document.getElementById("globalIgSelector").value = appState.metadata.targetIG;
  renderAll();
}

function switchTab(tabId) {
  document.querySelectorAll(".nav-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
  });
  document.querySelectorAll(".tab-section").forEach((sec) => {
    sec.classList.toggle("active", sec.id === tabId);
  });
}

function syncTargetIgSelectors(ig) {
  ["globalIgSelector", "qTargetIg"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = ig;
  });
}

function changeTargetIG(newIG) {
  appState.metadata.targetIG = newIG;
  syncTargetIgSelectors(newIG);
  saveState();
  renderAll();
}

function changeNistWidgetIG(newIG) {
  appState.metadata.nistTargetIG = newIG;
  saveState();
  renderOverviewTab();
}

function changeCiaWidgetIG(newIG) {
  appState.metadata.ciaTargetIG = newIG;
  saveState();
  renderOverviewTab();
}

function recalculateControlScore(control) {
  if (!control.keySafeguards || control.keySafeguards.length === 0) return control.asIsScore;
  let totalPoints = 0;
  control.keySafeguards.forEach((sg) => {
    if (sg.status === "Implementado") totalPoints += 100;
    else if (sg.status === "Parcial") totalPoints += 50;
  });
  control.asIsScore = Math.round(totalPoints / control.keySafeguards.length);
  return control.asIsScore;
}

function computeMetrics() {
  const ig = appState.metadata.targetIG;
  const controls = appState.cisControls;

  let sumAsIs = 0;
  let sumToBe = 0;
  controls.forEach((c) => {
    sumAsIs += c.asIsScore;
    sumToBe += c.toBeScore[ig];
  });

  const avgAsIs = Math.round(sumAsIs / controls.length);
  const avgToBe = Math.round(sumToBe / controls.length);
  const avgGap = Math.max(0, avgToBe - avgAsIs);

  let cmmcLevel = "Nível 1 (Foundational)";
  if (avgAsIs >= 80) cmmcLevel = "Nível 3 (Expert)";
  else if (avgAsIs >= 50) cmmcLevel = "Nível 2 (Advanced)";

  const docAssets = appState.assets.filter((a) => a.category.includes("1.1.2")).length;
  const totalEvidences = appState.apiConnectors.reduce((acc, c) => acc + c.evidencesCollected, 0);

  return {
    ig,
    avgAsIs,
    avgToBe,
    avgGap,
    cmmcLevel,
    totalAssets: appState.assets.length,
    docAssets,
    totalEvidences,
    timeReduction: appState.validationLevels.manualVsAutomatedComparison.timeReductionPercent
  };
}

function renderGlobalKPIs() {
  const m = computeMetrics();
  const container = document.getElementById("globalKpiContainer");

  container.innerHTML = `
    <div class="kpi-card">
      <div class="kpi-label">Aderência Atual (As-Is)</div>
      <div class="kpi-value" style="color: var(--accent-blue);">${m.avgAsIs}%</div>
      <div class="kpi-sub">18 Controles CIS v8.1 &bull; ${m.cmmcLevel}</div>
    </div>
    <div class="kpi-card kpi-emerald">
      <div class="kpi-label">Estado Desejado (To-Be: ${m.ig})</div>
      <div class="kpi-value" style="color: var(--accent-emerald);">${m.avgToBe}%</div>
      <div class="kpi-sub">ISO 27001/27002 &bull; NIST 2.0 &bull; LGPD/GDPR</div>
    </div>
    <div class="kpi-card kpi-rose">
      <div class="kpi-label">Distanciamento Médio (O Gap)</div>
      <div class="kpi-value" style="color: var(--accent-rose);">-${m.avgGap}%</div>
      <div class="kpi-sub">Monitorado pelo Motor Central de Regras</div>
    </div>
    <div class="kpi-card kpi-amber">
      <div class="kpi-label">Coleta Agentless &amp; Ativos</div>
      <div class="kpi-value" style="color: var(--accent-amber);">
        ${m.totalEvidences} <span style="font-size:0.84rem; font-weight:600;">Evidências JSON</span>
      </div>
      <div class="kpi-sub">${m.totalAssets} Ativos (${m.docAssets} Docs CIS 1.1.2)</div>
    </div>
    <div class="kpi-card kpi-purple">
      <div class="kpi-label">Eficiência vs. Auditoria Manual</div>
      <div class="kpi-value" style="color: var(--accent-purple);">-${m.timeReduction}%</div>
      <div class="kpi-sub">160h (Planilhas) &rarr; 4.5h (Automatizado / 0% FP)</div>
    </div>
  `;
}

// Renderiza o Grafo de Risco SVG (Seção 4.2 item 3)
function renderRiskGraphSVG() {
  const container = document.getElementById("riskGraphSvgContainer");
  if (!container) return;

  container.innerHTML = `
    <svg viewBox="0 0 1120 310" style="width:100%; min-width:860px; height:auto; background:#090e1a; border-radius:10px; border:1px solid var(--border-color);">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569" />
        </marker>
        <marker id="arrow-alert" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e" />
        </marker>
      </defs>

      <!-- Títulos das Camadas do Grafo -->
      <text x="115" y="28" fill="#94a3b8" font-size="11" font-weight="700" text-anchor="middle">1. CONECTORES API AGENTLESS</text>
      <text x="395" y="28" fill="#94a3b8" font-size="11" font-weight="700" text-anchor="middle">2. MOTOR CENTRAL DE REGRAS (PYTHON)</text>
      <text x="695" y="28" fill="#94a3b8" font-size="11" font-weight="700" text-anchor="middle">3. NORMATIVAS (POSTGRESQL)</text>
      <text x="980" y="28" fill="#94a3b8" font-size="11" font-weight="700" text-anchor="middle">4. GRAFO DE RISCO ATIVO</text>

      <!-- Arestas (Linhas de Conexão) -->
      <line x1="210" y1="75" x2="290" y2="75" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)" />
      <line x1="210" y1="155" x2="290" y2="155" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)" />
      <line x1="210" y1="235" x2="290" y2="215" stroke="#38bdf8" stroke-width="2" marker-end="url(#arrow)" />
      <line x1="210" y1="235" x2="290" y2="268" stroke="#a855f7" stroke-width="2" marker-end="url(#arrow)" />

      <line x1="500" y1="75" x2="590" y2="75" stroke="#f43f5e" stroke-width="2" marker-end="url(#arrow-alert)" />
      <line x1="500" y1="155" x2="590" y2="155" stroke="#f59e0b" stroke-width="2" marker-end="url(#arrow)" />
      <line x1="500" y1="215" x2="590" y2="215" stroke="#f43f5e" stroke-width="2" marker-end="url(#arrow-alert)" />
      <line x1="500" y1="268" x2="590" y2="268" stroke="#a855f7" stroke-width="2" marker-end="url(#arrow)" />

      <line x1="800" y1="75" x2="875" y2="75" stroke="#f43f5e" stroke-width="2" marker-end="url(#arrow-alert)" />
      <line x1="800" y1="155" x2="875" y2="155" stroke="#f59e0b" stroke-width="2" marker-end="url(#arrow)" />
      <line x1="800" y1="215" x2="875" y2="215" stroke="#f43f5e" stroke-width="2" marker-end="url(#arrow-alert)" />
      <line x1="800" y1="268" x2="875" y2="268" stroke="#a855f7" stroke-width="2" marker-end="url(#arrow)" />

      <!-- Coluna 1: Conectores Agentless -->
      <rect x="20" y="50" width="190" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" />
      <text x="115" y="72" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">AWS Audit Manager API</text>
      <text x="115" y="88" fill="#38bdf8" font-size="10" text-anchor="middle">42 Evidências JSON (118ms)</text>

      <rect x="20" y="130" width="190" height="50" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="1.5" />
      <text x="115" y="152" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">Azure Defender for Cloud</text>
      <text x="115" y="168" fill="#38bdf8" font-size="10" text-anchor="middle">38 Evidências JSON (134ms)</text>

      <rect x="20" y="210" width="190" height="55" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="1.5" />
      <text x="115" y="232" fill="#f8fafc" font-size="12" font-weight="700" text-anchor="middle">IAM Graph &amp; Repositório</text>
      <text x="115" y="249" fill="#c084fc" font-size="10" text-anchor="middle">AD + Ativos Documentação 1.1.2</text>

      <!-- Coluna 2: Regras Lógicas (Core Engine) -->
      <rect x="290" y="52" width="210" height="46" rx="8" fill="#1e293b" stroke="#f43f5e" stroke-width="1.5" />
      <text x="395" y="72" fill="#fda4af" font-size="11" font-weight="700" text-anchor="middle">RULE-CIS-3.11-ENC (KMS/TDE)</text>
      <text x="395" y="87" fill="#94a3b8" font-size="10" text-anchor="middle">storage.encrypted == false</text>

      <rect x="290" y="132" width="210" height="46" rx="8" fill="#1e293b" stroke="#f59e0b" stroke-width="1.5" />
      <text x="395" y="152" fill="#fcd34d" font-size="11" font-weight="700" text-anchor="middle">RULE-CIS-8.9-SIEM (Logs)</text>
      <text x="395" y="167" fill="#94a3b8" font-size="10" text-anchor="middle">retention_days: 30 &lt; 90</text>

      <rect x="290" y="192" width="210" height="44" rx="8" fill="#1e293b" stroke="#f43f5e" stroke-width="1.5" />
      <text x="395" y="211" fill="#fda4af" font-size="11" font-weight="700" text-anchor="middle">RULE-CIS-6.5-MFA (Admin)</text>
      <text x="395" y="226" fill="#94a3b8" font-size="10" text-anchor="middle">3 Contas Admin sem MFA</text>

      <rect x="290" y="246" width="210" height="44" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="1.5" />
      <text x="395" y="265" fill="#e9d5ff" font-size="11" font-weight="700" text-anchor="middle">RULE-CIS-1.1.2 (Docs v8.1)</text>
      <text x="395" y="280" fill="#94a3b8" font-size="10" text-anchor="middle">PGSI &amp; RoPA &gt; 180 dias</text>

      <!-- Coluna 3: Controles Normativos -->
      <rect x="590" y="52" width="210" height="46" rx="8" fill="#0f172a" stroke="#64748b" />
      <text x="695" y="72" fill="#f8fafc" font-size="11" font-weight="700" text-anchor="middle">CIS 03 (3.11) &bull; ISO 27001 A.8.24</text>
      <text x="695" y="87" fill="#38bdf8" font-size="10" text-anchor="middle">LGPD Art. 46 &bull; GDPR Art. 32</text>

      <rect x="590" y="132" width="210" height="46" rx="8" fill="#0f172a" stroke="#64748b" />
      <text x="695" y="152" fill="#f8fafc" font-size="11" font-weight="700" text-anchor="middle">CIS 08 (8.9) &bull; ISO 27001 A.8.15</text>
      <text x="695" y="167" fill="#38bdf8" font-size="10" text-anchor="middle">NIST CSF 2.0 (DETECT)</text>

      <rect x="590" y="192" width="210" height="44" rx="8" fill="#0f172a" stroke="#64748b" />
      <text x="695" y="211" fill="#f8fafc" font-size="11" font-weight="700" text-anchor="middle">CIS 06 (6.5) &bull; ISO 27001 A.8.5</text>
      <text x="695" y="226" fill="#38bdf8" font-size="10" text-anchor="middle">NIST CSF 2.0 (PROTECT)</text>

      <rect x="590" y="246" width="210" height="44" rx="8" fill="#0f172a" stroke="#64748b" />
      <text x="695" y="265" fill="#f8fafc" font-size="11" font-weight="700" text-anchor="middle">CIS 01 (1.1.2) &bull; ISO 27001 A.5.1</text>
      <text x="695" y="280" fill="#c084fc" font-size="10" text-anchor="middle">NIST CSF 2.0 (GOVERN)</text>

      <!-- Coluna 4: Riscos Quantificados -->
      <rect x="875" y="52" width="225" height="46" rx="8" fill="rgba(244,63,94,0.18)" stroke="#f43f5e" stroke-width="1.5" />
      <text x="987" y="72" fill="#fda4af" font-size="11" font-weight="700" text-anchor="middle">RSK-02: Vazamento PII (CVSS 8.2)</text>
      <text x="987" y="87" fill="#f8fafc" font-size="10" text-anchor="middle">Sanção LGPD/GDPR &bull; Prioridade P1</text>

      <rect x="875" y="132" width="225" height="46" rx="8" fill="rgba(245,158,11,0.18)" stroke="#f59e0b" stroke-width="1.5" />
      <text x="987" y="152" fill="#fcd34d" font-size="11" font-weight="700" text-anchor="middle">RSK-04: Cegueira SIEM (CVSS 7.5)</text>
      <text x="987" y="167" fill="#f8fafc" font-size="10" text-anchor="middle">Aumento MTTD &bull; Prioridade P2</text>

      <rect x="875" y="192" width="225" height="44" rx="8" fill="rgba(244,63,94,0.22)" stroke="#f43f5e" stroke-width="1.5" />
      <text x="987" y="211" fill="#fda4af" font-size="11" font-weight="700" text-anchor="middle">RSK-01: Takeover Admin (CVSS 9.1)</text>
      <text x="987" y="226" fill="#f8fafc" font-size="10" text-anchor="middle">Risco Extremo (5x5=25) &bull; P1</text>

      <rect x="875" y="246" width="225" height="44" rx="8" fill="rgba(168,85,247,0.18)" stroke="#a855f7" stroke-width="1.5" />
      <text x="987" y="265" fill="#e9d5ff" font-size="11" font-weight="700" text-anchor="middle">RSK-03: Defasagem Doc (CVSS 6.5)</text>
      <text x="987" y="280" fill="#f8fafc" font-size="10" text-anchor="middle">Gap Governança &bull; Mitigado NEXO</text>
    </svg>
  `;
}

// ABA 0: Visão Geral
function renderOverviewTab() {
  const ig = appState.metadata.targetIG;
  const nistIg = appState.metadata.nistTargetIG || ig;
  const ciaIg = appState.metadata.ciaTargetIG || ig;
  syncTargetIgSelectors(ig);

  const nistSel = document.getElementById("nistWidgetIgSelector");
  if (nistSel) nistSel.value = nistIg;
  const ciaSel = document.getElementById("ciaWidgetIgSelector");
  if (ciaSel) ciaSel.value = ciaIg;

  // Bloco exclusivo de impressão/PDF: explicação detalhada das porcentagens
  const printMethodEl = document.getElementById("printPercentageMethodology");
  if (printMethodEl) {
    const m = computeMetrics();
    printMethodEl.innerHTML = `
      <div class="card-header" style="margin-bottom:0.5rem;">
        <div>
          <div class="card-title">&#128202; Metodologia e Interpretação Detalhada das Porcentagens</div>
          <div class="card-subtitle">Critérios de cálculo de aderência (As-Is), meta normativa (To-Be) e lacuna (Gap)</div>
        </div>
      </div>
      <div style="font-size:0.8rem; line-height:1.5; color:#1e293b;">
        <p style="margin-bottom:0.45rem;">
          <strong>1. Como as porcentagens são calculadas:</strong> Cada um dos 18 Controles Críticos do <strong>CIS Controls v8.1</strong> recebe uma pontuação de aderência atual (<strong>As-Is</strong>) entre <strong>0%</strong> e <strong>100%</strong>, calculada pela média das salvaguardas implementadas (<em>Implementado = 100%</em>, <em>Parcial = 50%</em>, <em>Não Implementado = 0%</em>) ou declaradas no Questionário (<em>0%, 25%, 50%, 75%, 100%</em>). As porcentagens exibidas nos agrupamentos (Funções NIST CSF 2.0 e Pilares da Tríade CIA) correspondem à <strong>média aritmética</strong> dos controles pertencentes a cada categoria.
        </p>
        <p style="margin-bottom:0.45rem;">
          <strong>2. Estado Atual vs. Meta e Gap (${m.ig}):</strong> Atualmente a organização apresenta aderência média global de <strong>${m.avgAsIs}%</strong> (As-Is) frente à meta de <strong>${m.avgToBe}%</strong> (To-Be para <strong>${m.ig}</strong>), resultando em uma lacuna média (<strong>Gap = To-Be &minus; As-Is</strong>) de <strong>${m.avgGap} pontos percentuais (-${m.avgGap}%)</strong>.
        </p>
        <p style="margin:0;">
          <strong>3. Faixas de Classificação das Porcentagens:</strong>
          &bull; <strong>0% a 49% (Gap Crítico):</strong> Controle ausente ou incipiente, gerando exposição imediata a incidentes ou sanções (ex.: LGPD/GDPR).
          &bull; <strong>50% a 84% (Parcial / Em Evolução):</strong> Controle existente em parte do ambiente, porém sem cobertura total ou automação contínua.
          &bull; <strong>85% a 100% (Implementado / Conforme):</strong> Controle consolidado, auditável e alinhado ao nível de maturidade esperado.
        </p>
      </div>
    `;
  }

  const nistDescriptions = {
    GOVERN: "Define políticas, papéis, gestão documental (CIS 1.1.2) e governança de terceiros/conscientização.",
    IDENTIFY: "Mapeia ativos físicos/software, vulnerabilidades e testes de invasão para conhecer a superfície de exposição.",
    PROTECT: "Aplica salvaguardas preventivas como criptografia (LGPD), hardening, MFA (CIS 6.5), EDR, rede e DevSecOps.",
    DETECT: "Centraliza logs de auditoria (SIEM) e monitora tráfego de rede (IDS/IPS) para identificação rápida de anomalias.",
    RESPOND: "Estrutura planos de resposta a incidentes, playbooks SOAR e contenção conforme prazos regulatórios (LGPD Art. 48).",
    RECOVER: "Garante continuidade operacional e restauração segura por meio de backups imutáveis e testes periódicos de restore."
  };

  const nistFunctions = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"];
  const nistContainer = document.getElementById("nistComparisonContainer");

  let nistHtml = "";
  nistFunctions.forEach((fn) => {
    const matched = appState.cisControls.filter((c) => c.nistFunction.includes(fn));
    const asIs = Math.round(matched.reduce((a, c) => a + c.asIsScore, 0) / (matched.length || 1));
    const toBe = Math.round(matched.reduce((a, c) => a + c.toBeScore[nistIg], 0) / (matched.length || 1));
    const gap = Math.max(0, toBe - asIs);
    const controlsBreakdown = matched.map((c) => `${c.code} (${c.asIsScore}% / Meta ${c.toBeScore[nistIg]}%)`).join(", ");

    nistHtml += `
      <div class="progress-row">
        <div class="progress-header">
          <span><strong>${fn}</strong> ${fn === "GOVERN" ? '<span class="badge badge-purple">NIST CSF 2.0 &bull; CIS v8.1</span>' : ""}</span>
          <span>As-Is: <strong>${asIs}%</strong> &bull; Meta (${nistIg}): <strong>${toBe}%</strong> &bull; <span style="color:var(--accent-rose)">Gap: -${gap}%</span></span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" style="width:${asIs}%; background: linear-gradient(90deg, #0284c7, #38bdf8);"></div>
          <div class="progress-marker" style="left:${toBe}%;" title="Meta To-Be (${toBe}%)"></div>
        </div>
        <div class="print-only print-detail-note">
          <strong>O que significa (${asIs}% atual vs. ${toBe}% meta):</strong> ${nistDescriptions[fn] || ""}
          O índice de <strong>${asIs}%</strong> é a média de ${matched.length} controle(s): <em>${controlsBreakdown}</em>. A lacuna de <strong>-${gap}%</strong> indica o esforço necessário para atingir o padrão ${nistIg}.
        </div>
      </div>
    `;
  });
  nistContainer.innerHTML = nistHtml;

  // Tríade CIA + Comparativo Manual vs Automatizado
  const pillarDescriptions = {
    Confidencialidade: "Mede a eficácia na proteção contra acesso não autorizado a dados sensíveis e credenciais (MFA, criptografia LGPD/GDPR, gestão de contas e terceiros).",
    Integridade: "Avalia a confiabilidade e exatidão dos ativos, configurações e registros (inventário, hardening, patches, SIEM, proteção web/EDR e DevSecOps).",
    Disponibilidade: "Reflete a resiliência operacional e continuidade dos serviços diante de falhas ou ataques (backups imutáveis, segmentação de rede, IDS/IPS e resposta a incidentes)."
  };
  const pillars = ["Confidencialidade", "Integridade", "Disponibilidade"];
  const ciaContainer = document.getElementById("ciaAndCmmcContainer");
  let ciaHtml = `<div style="margin-bottom:1rem;">`;

  pillars.forEach((pillar) => {
    const controls = appState.cisControls.filter((c) => c.cia === pillar);
    const score = Math.round(controls.reduce((a, c) => a + c.asIsScore, 0) / (controls.length || 1));
    const target = Math.round(controls.reduce((a, c) => a + c.toBeScore[ciaIg], 0) / (controls.length || 1));
    const pillarGap = Math.max(0, target - score);
    const controlsBreakdown = controls.map((c) => `${c.code} (${c.asIsScore}%)`).join(", ");
    const color =
      pillar === "Confidencialidade" ? "#38bdf8" : pillar === "Integridade" ? "#10b981" : "#f59e0b";

    ciaHtml += `
      <div class="progress-row">
        <div class="progress-header">
          <span><strong>${pillar}</strong> (${controls.length} Controles CIS)</span>
          <span>Atual: <strong>${score}%</strong> / Meta (${ciaIg}): <strong>${target}%</strong></span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" style="width:${score}%; background:${color};"></div>
          <div class="progress-marker" style="left:${target}%;"></div>
        </div>
        <div class="print-only print-detail-note">
          <strong>Detalhamento (${score}% atual / Gap de -${pillarGap}%):</strong> ${pillarDescriptions[pillar]}
          Composto por ${controls.length} controles: <em>${controlsBreakdown}</em>.
        </div>
      </div>
    `;
  });

  const cmp = appState.validationLevels.manualVsAutomatedComparison;
  ciaHtml += `
    </div>
    <div style="background:rgba(15,23,42,0.65); border:1px solid var(--border-color); border-radius:8px; padding:0.9rem; font-size:0.81rem;">
      <div style="font-weight:700; margin-bottom:0.4rem; color:var(--accent-emerald);">
        &#9889; Impacto da Automatização vs. Auditoria Manual em Planilhas:
      </div>
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; color:var(--text-secondary);">
        <div>&bull; <strong>Tempo Manual:</strong> ${cmp.manualHoursPerAudit}h por ciclo</div>
        <div>&bull; <strong>Tempo Automatizado:</strong> <strong style="color:#fff">${cmp.automatedHoursPerAudit}h (-${cmp.timeReductionPercent}%)</strong></div>
        <div>&bull; <strong>Inconsistência Manual:</strong> ${cmp.manualErrorOrStaleRate}</div>
        <div>&bull; <strong>Falsos Positivos NEXO:</strong> <strong style="color:var(--accent-emerald)">${cmp.automatedFalsePositiveRate}</strong></div>
      </div>
    </div>
  `;
  ciaContainer.innerHTML = ciaHtml;

  renderRiskGraphSVG();
}

// ABA 1: Conectores Agentless + Inventário de Ativos
function renderConnectorsAndAssets() {
  const connContainer = document.getElementById("connectorsCardsContainer");
  if (connContainer) {
    connContainer.innerHTML = appState.apiConnectors
      .map(
        (c) => `
        <div class="card" style="background:rgba(15,23,42,0.65); margin-bottom:0;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.45rem;">
            <span class="badge badge-emerald">&bull; ${c.status}</span>
            <span style="font-size:0.74rem; color:var(--text-secondary);">Latência: <strong>${c.latencyMs} ms</strong></span>
          </div>
          <div style="font-weight:700; font-size:0.95rem; color:#fff;">${c.provider}</div>
          <div style="font-size:0.8rem; color:var(--accent-blue); margin-bottom:0.4rem;">${c.service}</div>
          <div style="font-size:0.73rem; color:var(--text-secondary); word-break:break-all; margin-bottom:0.5rem;">
            <code>${c.endpoint}</code>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.76rem; border-top:1px solid rgba(255,255,255,0.07); padding-top:0.45rem;">
            <span>Evidências JSON: <strong>${c.evidencesCollected}</strong></span>
            <span>Sync: ${c.lastSync}</span>
          </div>
        </div>
      `
      )
      .join("");
  }
  renderAssetsTable();
}

function renderAssetsTable() {
  const search = (document.getElementById("assetSearchInput")?.value || "").toLowerCase();
  const catFilter = document.getElementById("assetCategoryFilter")?.value || "ALL";
  const tbody = document.querySelector("#assetsTable tbody");

  const filtered = appState.assets.filter((a) => {
    const matchText =
      a.name.toLowerCase().includes(search) ||
      a.owner.toLowerCase().includes(search) ||
      a.cisControl.toLowerCase().includes(search) ||
      a.notes.toLowerCase().includes(search);
    const matchCat = catFilter === "ALL" || a.category.includes(catFilter);
    return matchText && matchCat;
  });

  tbody.innerHTML = filtered
    .map((a) => {
      const isDocV81 = a.category.includes("1.1.2");
      const cvssClass = a.cvss >= 7.0 ? "badge-rose" : a.cvss >= 4.0 ? "badge-amber" : "badge-emerald";
      return `
        <tr>
          <td><code>${a.id}</code></td>
          <td><strong>${a.name}</strong><br/><span style="font-size:0.74rem; color:var(--text-secondary);">Fonte: ${a.owner}</span></td>
          <td>
            <span class="badge ${isDocV81 ? "badge-purple" : "badge-blue"}">${a.category}</span>
          </td>
          <td><strong>${a.cisControl}</strong><br/><span style="font-size:0.73rem; color:var(--text-secondary);">NIST: ${a.nistFunction}</span></td>
          <td>${a.ciaImpact}</td>
          <td>${a.criticality}</td>
          <td><span class="badge ${cvssClass}">CVSS ${a.cvss.toFixed(1)}</span></td>
          <td><strong>${a.status}</strong></td>
          <td style="max-width:290px; color:var(--text-secondary);">${a.notes}</td>
        </tr>
      `;
    })
    .join("");
}

function runSimulatedDiscovery() {
  const nowStr = new Date().toLocaleTimeString("pt-BR");
  appState.apiConnectors.forEach((c) => {
    c.evidencesCollected += 2;
    c.lastSync = `02/11/2026 ${nowStr}`;
  });

  const alreadyScanned = appState.assets.some((a) => a.id === "AST-009");
  if (!alreadyScanned) {
    appState.assets.unshift(
      {
        id: "AST-009",
        name: "Plano de Continuidade de Negócios (PCN) & Diretrizes ISO 45001 / ISO 27002",
        category: "Documentação (CIS v8.1 - 1.1.2)",
        cisControl: "CIS 1 (1.1.2) / CIS 11",
        nistFunction: "GOVERN / RECOVER",
        ciaImpact: "Disponibilidade",
        owner: "Conector Governança & Compliance",
        criticality: "Alta",
        status: "Auditado via API",
        cvss: 4.8,
        notes: "Ativo documental validado pelo Motor Central de Regras (Salvaguarda 1.1.2)."
      },
      {
        id: "AST-010",
        name: "Bucket S3 / Blob Storage de Homologação sem Bloqueio Público Total",
        category: "Hardware / Nuvem",
        cisControl: "CIS 3 (3.3) / CIS 12",
        nistFunction: "PROTECT",
        ciaImpact: "Confidencialidade",
        owner: "AWS Audit Manager API (Agentless)",
        criticality: "Alta",
        status: "Não Conforme (Gap)",
        cvss: 8.4,
        notes: "Descoberto de forma agentless sem instalação de agente local na conta AWS."
      }
    );
  }
  saveState();
  renderAll();
  switchTab("tab-stage1");
}

// ABA 2: Motor Central de Regras + Matriz de Conformidade
function renderCoreRulesAndCompliance() {
  const rulesTbody = document.querySelector("#coreRulesTable tbody");
  if (rulesTbody) {
    rulesTbody.innerHTML = appState.coreRuleEngine
      .map((r) => {
        const isOk = r.lastEvaluation.includes("CONFORME EM PRODUÇÃO");
        const badge = isOk ? "badge-emerald" : "badge-rose";
        return `
          <tr>
            <td><code>${r.ruleId}</code></td>
            <td>
              <strong>${r.name}</strong><br/>
              <code style="font-size:0.74rem; color:var(--accent-blue);">${r.logicalExpression}</code>
            </td>
            <td><span class="badge badge-blue">${r.sourceConnector}</span></td>
            <td style="font-size:0.78rem;">${r.frameworks}</td>
            <td><code style="font-size:0.72rem; color:var(--text-secondary);">${r.evidenceSample}</code></td>
            <td>
              <span class="badge ${badge}">${r.lastEvaluation}</span><br/>
              <span style="font-size:0.7rem; color:var(--accent-emerald);">Falsos Positivos: ${r.falsePositiveRate}</span>
            </td>
          </tr>
        `;
      })
      .join("");
  }
  renderComplianceMatrix();
}

function renderComplianceMatrix() {
  const fnFilter = document.getElementById("cisFunctionFilter")?.value || "ALL";
  const ig = appState.metadata.targetIG;
  const container = document.getElementById("complianceMatrixContainer");

  const filteredControls = appState.cisControls.filter(
    (c) => fnFilter === "ALL" || c.nistFunction.includes(fnFilter)
  );

  container.innerHTML = filteredControls
    .map((c) => {
      const target = c.toBeScore[ig];
      const gap = Math.max(0, target - c.asIsScore);
      const gapBadge = gap > 35 ? "badge-rose" : gap > 15 ? "badge-amber" : "badge-emerald";

      const safeguardsRows = c.keySafeguards
        .map(
          (sg, idx) => `
          <tr>
            <td style="width:90px;"><code>${sg.id}</code></td>
            <td>
              <strong>${sg.name}</strong>
              ${sg.id === "1.1.2" ? '<span class="badge badge-purple" style="margin-left:6px;">Novidade CIS v8.1</span>' : ""}
            </td>
            <td style="width:90px;"><span class="badge badge-blue">${sg.ig}</span></td>
            <td style="width:210px;">
              <select class="select-field" style="width:100%; padding:0.3rem 0.5rem;" onchange="updateSafeguardStatus(${c.id}, ${idx}, this.value)">
                <option value="Implementado" ${sg.status === "Implementado" ? "selected" : ""}>Implementado (100%)</option>
                <option value="Parcial" ${sg.status === "Parcial" ? "selected" : ""}>Parcialmente Impl. (50%)</option>
                <option value="Não Implementado" ${sg.status === "Não Implementado" ? "selected" : ""}>Não Implementado (0%)</option>
              </select>
            </td>
          </tr>
        `
        )
        .join("");

      return `
        <div class="card" style="background:rgba(15,23,42,0.55); margin-bottom:1rem;">
          <div class="card-header" style="margin-bottom:0.65rem;">
            <div>
              <div class="card-title">
                <span class="badge badge-blue">${c.code}</span>
                ${c.title}
              </div>
              <div class="card-subtitle" style="margin-top:0.2rem;">
                <strong>NIST CSF 2.0:</strong> ${c.nistFunction} &bull;
                <strong>Normativas:</strong> ${c.iso27001} &bull;
                <strong>Pilar CIA:</strong> ${c.cia}
              </div>
            </div>
            <div style="text-align:right;">
              <span class="badge ${gapBadge}">As-Is: ${c.asIsScore}% | Meta (${ig}): ${target}% | Gap: -${gap}%</span>
            </div>
          </div>
          <div style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.65rem;">
            &#128161; <em>Diretriz v8.1:</em> ${c.highlightV81}
          </div>
          <div class="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Salvaguarda</th>
                  <th>Requisito Técnico / Processual (To-Be)</th>
                  <th>Grupo IG</th>
                  <th>Status Avaliado (Interativo)</th>
                </tr>
              </thead>
              <tbody>${safeguardsRows}</tbody>
            </table>
          </div>
        </div>
      `;
    })
    .join("");
}

function updateSafeguardStatus(controlId, safeguardIdx, newStatus) {
  const control = appState.cisControls.find((c) => c.id === controlId);
  if (!control) return;
  control.keySafeguards[safeguardIdx].status = newStatus;
  recalculateControlScore(control);
  saveState();
  renderAll();
}

// ABA 3: Diagnóstico de Gap, Matriz 5x5 ISO 31000 e SERVQUAL
function renderGapAndRisksTab() {
  const ig = appState.metadata.targetIG;
  document.getElementById("stage3IgLabel").textContent = ig;

  const gapContainer = document.getElementById("gapBarsContainer");
  gapContainer.innerHTML = appState.cisControls
    .map((c) => {
      const target = c.toBeScore[ig];
      const gap = Math.max(0, target - c.asIsScore);
      const fillColor =
        gap > 40 ? "var(--accent-rose)" : gap > 20 ? "var(--accent-amber)" : "var(--accent-emerald)";

      return `
        <div class="progress-row">
          <div class="progress-header">
            <span><strong>${c.code} — ${c.title}</strong> <span style="color:var(--text-secondary);">(${c.iso27001})</span></span>
            <span>
              As-Is: <strong>${c.asIsScore}%</strong> |
              To-Be (${ig}): <strong>${target}%</strong> |
              <strong style="color:${fillColor}">Gap: -${gap}%</strong>
            </span>
          </div>
          <div class="progress-track">
            <div class="progress-fill" style="width:${c.asIsScore}%; background:${fillColor};"></div>
            <div class="progress-marker" style="left:${target}%;" title="Meta To-Be: ${target}%"></div>
          </div>
        </div>
      `;
    })
    .join("");

  // Matriz 5x5 de Riscos
  const matrixContainer = document.getElementById("riskMatrix5x5Container");
  let gridHtml = `<div class="risk-matrix-grid">`;

  for (let prob = 5; prob >= 1; prob--) {
    gridHtml += `<div class="risk-axis-label">P=${prob}</div>`;
    for (let imp = 1; imp <= 5; imp++) {
      const score = prob * imp;
      const cellClass =
        score >= 16
          ? "risk-extreme"
          : score >= 10
          ? "risk-high"
          : score >= 5
          ? "risk-med"
          : "risk-low";

      const matchingRisks = appState.risks.filter(
        (r) => r.probability === prob && r.impact === imp
      );
      const badges = matchingRisks.map((r) => `<span>${r.id}</span>`).join(", ");

      gridHtml += `
        <div class="risk-cell ${cellClass}" title="Probabilidade ${prob} x Impacto ${imp} = Score ${score}">
          <div>${score}</div>
          <div style="font-size:0.68rem;">${badges || "-"}</div>
        </div>
      `;
    }
  }

  gridHtml += `<div></div>`;
  for (let imp = 1; imp <= 5; imp++) {
    gridHtml += `<div class="risk-axis-label">I=${imp}</div>`;
  }
  gridHtml += `</div>`;
  matrixContainer.innerHTML = gridHtml;

  // Avaliação de Maturidade CMMC & Grupos de Implementação (IG1, IG2, IG3)
  const maturityContainer = document.getElementById("maturityGroupsContainer");
  if (maturityContainer && appState.maturityGroups) {
    maturityContainer.innerHTML = appState.maturityGroups
      .map((mg) => {
        const pct = Math.round((mg.implementedSafeguards / mg.totalSafeguards) * 100);
        const gapSafeguards = mg.totalSafeguards - mg.implementedSafeguards;
        return `
          <div style="border-bottom:1px solid rgba(148,163,184,0.14); padding-bottom:0.75rem; margin-bottom:0.75rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
              <strong style="font-size:0.86rem; color:var(--accent-blue);">${mg.name}</strong>
              <span class="badge badge-purple">${mg.implementedSafeguards} / ${mg.totalSafeguards} Salvaguardas (${pct}%)</span>
            </div>
            <p style="font-size:0.78rem; color:var(--text-secondary); margin:0.2rem 0;">${mg.description}</p>
            <div class="progress-track" style="height:8px; margin:0.4rem 0;">
              <div class="progress-fill" style="width:${pct}%; background:linear-gradient(90deg, #0284c7, #10b981);"></div>
            </div>
            <div style="font-size:0.75rem; color:var(--text-primary); display:flex; justify-content:space-between; flex-wrap:wrap; gap:0.4rem;">
              <span><strong>Foco Técnico:</strong> ${mg.keyFocus}</span>
              <span class="badge badge-rose">Faltam ${gapSafeguards} salvaguardas</span>
            </div>
          </div>
        `;
      })
      .join("");
  }

  // Tabela de Riscos
  const risksTbody = document.querySelector("#risksDetailTable tbody");
  risksTbody.innerHTML = appState.risks
    .map((r) => {
      const score = r.probability * r.impact;
      const badge = score >= 16 ? "badge-rose" : score >= 10 ? "badge-amber" : "badge-blue";
      return `
        <tr>
          <td><code>${r.id}</code></td>
          <td><strong>${r.title}</strong></td>
          <td>${r.cisRef}<br/><span style="font-size:0.73rem; color:var(--text-secondary);">${r.isoRef}</span></td>
          <td><span class="badge ${badge}">${r.probability} x ${r.impact} = ${score}</span></td>
          <td><strong>${r.cvss.toFixed(1)}</strong></td>
          <td>${r.dimOperational}</td>
          <td>${r.dimFinancial}</td>
          <td>${r.dimReputational}</td>
          <td><span class="badge ${badge}">${r.mitigationStatus}</span></td>
        </tr>
      `;
    })
    .join("");
}

// ABA 4: Validação em 3 Níveis + Plano 5W2H + Código da Arquitetura
function renderActionPlanAndAutomation() {
  // 1. Validação em 3 Níveis Progressivos (Seção 4.3)
  const valContainer = document.getElementById("validationTiersContainer");
  if (valContainer) {
    valContainer.innerHTML = `
      <div class="grid-3" style="margin-bottom:0;">
        ${appState.validationLevels.threeTiers
          .map(
            (t) => `
          <div style="background:rgba(15,23,42,0.65); border:1px solid var(--border-color); border-radius:8px; padding:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
              <span class="badge badge-emerald">${t.status}</span>
            </div>
            <div style="font-weight:700; font-size:0.9rem; color:var(--accent-blue); margin-bottom:0.35rem;">${t.level}</div>
            <p style="font-size:0.79rem; color:var(--text-secondary); margin-bottom:0.55rem;">${t.focus}</p>
            <div style="font-size:0.76rem; color:#fff; background:#090d16; padding:0.45rem 0.6rem; border-radius:6px; border:1px solid rgba(255,255,255,0.06);">
              ${t.metric}
            </div>
          </div>
        `
          )
          .join("")}
      </div>
    `;
  }

  // 2. Tabela 5W2H
  const tbody = document.querySelector("#actionPlanTable tbody");
  tbody.innerHTML = appState.actionPlan5W2H
    .map((act, idx) => {
      const statusBadge =
        act.status === "Concluído"
          ? "badge-emerald"
          : act.status === "Em Andamento"
          ? "badge-blue"
          : "badge-amber";

      return `
        <tr>
          <td>
            <code>${act.id}</code><br/>
            <span class="badge badge-purple">${act.ig}</span>
          </td>
          <td><strong>${act.what}</strong><br/><span style="font-size:0.73rem; color:var(--accent-blue);">${act.cisControl}</span></td>
          <td>${act.why}</td>
          <td>${act.where}</td>
          <td>${act.when}</td>
          <td>${act.who}</td>
          <td>${act.how}</td>
          <td><strong>${act.howMuch}</strong></td>
          <td>
            <select class="select-field" style="padding:0.25rem 0.45rem; font-size:0.76rem;" onchange="updateActionStatus(${idx}, this.value)">
              <option value="Pendente" ${act.status === "Pendente" ? "selected" : ""}>Pendente</option>
              <option value="Em Andamento" ${act.status === "Em Andamento" ? "selected" : ""}>Em Andamento</option>
              <option value="Concluído" ${act.status === "Concluído" ? "selected" : ""}>Concluído</option>
            </select>
            <div style="margin-top:4px;"><span class="badge ${statusBadge}">${act.status}</span></div>
          </td>
        </tr>
      `;
    })
    .join("");

  renderAutomationTemplate();
}

function runValidationSuite() {
  const nowStr = new Date().toLocaleTimeString("pt-BR");
  appState.validationLevels.threeTiers[0].status = `Aprovado (${nowStr})`;
  appState.validationLevels.threeTiers[1].status = `PoC Validada (${nowStr})`;
  appState.validationLevels.threeTiers[2].status = `0% Falsos Positivos (${nowStr})`;
  saveState();
  renderActionPlanAndAutomation();
}

function updateActionStatus(idx, newStatus) {
  appState.actionPlan5W2H[idx].status = newStatus;
  saveState();
  renderActionPlanAndAutomation();
}

function renderAutomationTemplate() {
  const key = document.getElementById("automationTemplateSelector")?.value || "python_backend_connector";
  const tpl = appState.automationTemplates[key];
  if (!tpl) return;

  document.getElementById("automationMetaBar").innerHTML = `
    <strong>Artefato:</strong> ${tpl.title} &bull; <strong>Enquadramento Arquitetural:</strong> <span class="badge badge-blue">${tpl.framework}</span>
  `;
  document.getElementById("automationCodeViewer").textContent = tpl.code;
}

function copyAutomationCode() {
  const code = document.getElementById("automationCodeViewer").textContent;
  navigator.clipboard?.writeText(code);
}

// Modais
function openAssetModal() {
  document.getElementById("assetModal").classList.add("open");
}

function closeAssetModal() {
  document.getElementById("assetModal").classList.remove("open");
}

function saveNewAsset(e) {
  e.preventDefault();
  const nextNum = appState.assets.length + 1;
  const newAsset = {
    id: `AST-0${nextNum < 10 ? "0" + nextNum : nextNum}`,
    name: document.getElementById("newAssetName").value,
    category: document.getElementById("newAssetCategory").value,
    cisControl: document.getElementById("newAssetCis").value,
    nistFunction: document.getElementById("newAssetCategory").value.includes("1.1.2") ? "GOVERN" : "IDENTIFY",
    ciaImpact: document.getElementById("newAssetCia").value,
    owner: document.getElementById("newAssetOwner").value,
    criticality: "Alta",
    status: "Inventariado",
    cvss: parseFloat(document.getElementById("newAssetCvss").value) || 5.0,
    notes: document.getElementById("newAssetNotes").value
  };
  appState.assets.unshift(newAsset);
  saveState();
  closeAssetModal();
  renderAll();
}

function openActionModal() {
  document.getElementById("actionModal").classList.add("open");
}

function closeActionModal() {
  document.getElementById("actionModal").classList.remove("open");
}

function saveNewAction(e) {
  e.preventDefault();
  const nextNum = appState.actionPlan5W2H.length + 1;
  appState.actionPlan5W2H.push({
    id: `ACT-0${nextNum}`,
    what: document.getElementById("actWhat").value,
    why: document.getElementById("actWhy").value,
    where: document.getElementById("actWhere").value,
    when: document.getElementById("actWhen").value,
    who: document.getElementById("actWho").value,
    how: document.getElementById("actHow").value,
    howMuch: document.getElementById("actHowMuch").value,
    ig: document.getElementById("actIg").value,
    cisControl: "CIS Controls v8.1",
    status: "Pendente"
  });
  saveState();
  closeActionModal();
  renderActionPlanAndAutomation();
}

function exportDiagnosticJSON() {
  const metrics = computeMetrics();
  const payload = {
    exportedAt: new Date().toISOString(),
    summaryMetrics: metrics,
    projectData: appState
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `NEXO_Gap_Analysis_CIS_v8.1_${metrics.ig}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function showNexoToast(htmlContent) {
  const toast = document.getElementById("nexoToast");
  if (!toast) return;
  toast.innerHTML = htmlContent;
  toast.style.display = "block";
  clearTimeout(window._nexoToastTimer);
  window._nexoToastTimer = setTimeout(() => {
    toast.style.display = "none";
  }, 5000);
}

// ============================================================================
// SEÇÃO DO QUESTIONÁRIO AS-IS (LEVANTAMENTO DA EMPRESA)
// ============================================================================
let qCurrentFilter = "ALL";

function initQuestionnaireState() {
  if (!appState.companyQuestionnaire) {
    appState.companyQuestionnaire = JSON.parse(JSON.stringify(NEXO_DEFAULT_DATA.companyQuestionnaire || {}));
  }
  if (!appState.companyQuestionnaire.answers) {
    appState.companyQuestionnaire.answers = {};
  }
  // Se ainda não houver respostas salvas para algum controle, sincroniza com o asIsScore atual
  appState.cisControls.forEach((ctrl) => {
    if (!appState.companyQuestionnaire.answers[ctrl.id]) {
      appState.companyQuestionnaire.answers[ctrl.id] = {
        score: ctrl.asIsScore,
        obs: ""
      };
    }
  });
}

function saveQuestionnaireMeta() {
  initQuestionnaireState();
  const q = appState.companyQuestionnaire;
  const nameInput = document.getElementById("qCompanyName");
  const sectorInput = document.getElementById("qCompanySector");
  const sizeInput = document.getElementById("qCompanySize");
  const assessorInput = document.getElementById("qAssessorName");
  const dateInput = document.getElementById("qAssessmentDate");

  if (nameInput) q.companyName = nameInput.value;
  if (sectorInput) q.sector = sectorInput.value;
  if (sizeInput) q.size = sizeInput.value;
  if (assessorInput) q.assessor = assessorInput.value;
  if (dateInput) q.assessmentDate = dateInput.value;

  saveState();
}

function changeQuestionnaireTargetIg(ig) {
  initQuestionnaireState();
  appState.companyQuestionnaire.targetIg = ig;
  changeTargetIG(ig);
  renderQuestionnaireTab();
}

function filterQuestionnaire(category) {
  qCurrentFilter = category;
  document.querySelectorAll("#qFilterButtonGroup button").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-qfilter") === category);
  });
  renderQuestionnaireItems();
}

function renderQuestionnaireTab() {
  initQuestionnaireState();
  const q = appState.companyQuestionnaire;

  // Atualizar campos do formulário cadastral
  const nameInput = document.getElementById("qCompanyName");
  const sectorInput = document.getElementById("qCompanySector");
  const sizeInput = document.getElementById("qCompanySize");
  const assessorInput = document.getElementById("qAssessorName");
  const dateInput = document.getElementById("qAssessmentDate");
  const igInput = document.getElementById("qTargetIg");

  if (nameInput && !nameInput.matches(":focus")) nameInput.value = q.companyName || "";
  if (sectorInput) sectorInput.value = q.sector || "Tecnologia / Software (SaaS)";
  if (sizeInput) sizeInput.value = q.size || "Médio (51 a 250 colaboradores / multi-cloud)";
  if (assessorInput && !assessorInput.matches(":focus")) assessorInput.value = q.assessor || "";
  if (dateInput) dateInput.value = q.assessmentDate || new Date().toISOString().split("T")[0];
  if (igInput) igInput.value = appState.metadata.targetIG;

  // Calcular métricas ao vivo do questionário
  let totalScore = 0;
  let answeredCount = 0;

  appState.cisControls.forEach((c) => {
    const ans = q.answers[c.id];
    const score = ans ? ans.score : 0;
    totalScore += score;
    if (ans && ans.score > 0) answeredCount++;
  });

  const avgScore = Math.round(totalScore / appState.cisControls.length);
  const targetMetrics = computeMetrics();
  const gap = Math.max(0, targetMetrics.avgToBe - avgScore);

  // Nível CMMC estimado
  let cmmcLevel = "Nível 1 (Básico / Higiene)";
  let cmmcColor = "var(--accent-amber)";
  if (avgScore >= 85) {
    cmmcLevel = "Nível 3 (Avançado / Contínuo)";
    cmmcColor = "var(--accent-emerald)";
  } else if (avgScore >= 60) {
    cmmcLevel = "Nível 2 (Gerenciado / Documentado)";
    cmmcColor = "var(--accent-blue)";
  } else if (avgScore < 40) {
    cmmcLevel = "Nível 1 Incompleto (Risco Alto)";
    cmmcColor = "var(--accent-rose)";
  }

  const liveScoreEl = document.getElementById("qLiveScoreVal");
  const liveTargetEl = document.getElementById("qLiveTargetVal");
  const liveGapEl = document.getElementById("qLiveGapVal");
  const liveCmmcEl = document.getElementById("qLiveCmmcVal");
  const answeredCountEl = document.getElementById("qAnsweredCount");

  if (liveScoreEl) liveScoreEl.textContent = `${avgScore}%`;
  if (liveTargetEl) liveTargetEl.textContent = `${targetMetrics.avgToBe}%`;
  if (liveGapEl) liveGapEl.textContent = `${gap}%`;
  if (liveCmmcEl) {
    liveCmmcEl.textContent = cmmcLevel;
    liveCmmcEl.style.color = cmmcColor;
  }
  if (answeredCountEl) answeredCountEl.textContent = answeredCount;

  renderQuestionnaireItems();
}

function renderQuestionnaireItems() {
  const container = document.getElementById("questionnaireItemsContainer");
  if (!container) return;

  const q = appState.companyQuestionnaire;
  const questionsList = (typeof NEXO_QUESTIONNAIRE_QUESTIONS !== "undefined") ? NEXO_QUESTIONNAIRE_QUESTIONS : [];

  const filtered = questionsList.filter((item) => {
    if (qCurrentFilter === "ALL") return true;
    return item.nistCategory === qCurrentFilter;
  });

  container.innerHTML = filtered.map((item) => {
    const ctrl = appState.cisControls.find((c) => c.id === item.controlId) || {};
    const ans = q.answers[item.controlId] || { score: ctrl.asIsScore || 0, obs: "" };
    const currentScore = ans.score;

    let scoreColor = "var(--accent-rose)";
    let scoreBadge = "Gap Crítico";
    if (currentScore >= 85) { scoreColor = "var(--accent-emerald)"; scoreBadge = "Implementado"; }
    else if (currentScore >= 50) { scoreColor = "var(--accent-blue)"; scoreBadge = "Parcial"; }
    else if (currentScore >= 25) { scoreColor = "var(--accent-amber)"; scoreBadge = "Inicial / Em Andamento"; }

    const isV81Highlight = item.controlId === 1;

    return `
      <div class="q-card" id="qcard-${item.controlId}">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 0.6rem;">
          <div style="display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;">
            <span class="badge badge-blue" style="font-size: 0.82rem; padding: 0.3rem 0.6rem; font-weight: 800;">${item.code}</span>
            <strong style="color: #fff; font-size: 1rem;">${item.title}</strong>
            ${isV81Highlight ? '<span class="badge badge-purple">Salvaguarda 1.1.2 Docs (Novidade CIS v8.1)</span>' : ''}
            <span class="badge" style="background: rgba(15,23,42,0.8); border: 1px solid var(--border-color); font-size: 0.72rem; color: var(--text-secondary);">${ctrl.nistFunction || 'PROTECT'}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 0.6rem;">
            <span class="badge" style="background: rgba(15,23,42,0.9); border: 1px solid ${scoreColor}; color: ${scoreColor}; font-weight: 700;">
              ${scoreBadge} (${currentScore}%)
            </span>
          </div>
        </div>

        <div style="background: rgba(15, 23, 42, 0.45); border-left: 3px solid var(--accent-purple); padding: 0.65rem 0.9rem; border-radius: 4px; margin-bottom: 0.8rem;">
          <div style="font-size: 0.88rem; color: #f1f5f9; font-weight: 600; line-height: 1.45;">
            ❓ ${item.question}
          </div>
          <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.3rem;">
            💡 <em>${item.guide}</em>
          </div>
        </div>

        <div style="font-size: 0.73rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
          <strong>Normas Mapeadas:</strong> <code style="color: var(--accent-blue);">${item.normatives}</code>
        </div>

        <!-- Seletor de Opções (0%, 25%, 50%, 75%, 100%) -->
        <div class="q-options-grid">
          <button type="button" class="q-option-btn ${currentScore === 0 ? 'selected-0' : ''}" onclick="selectQuestionnaireOption(${item.controlId}, 0)">
            <span style="font-weight: 700; color: #f43f5e;">❌ 0% — Inexistente</span>
            <span>Não implementado / Sem controle formal</span>
          </button>
          <button type="button" class="q-option-btn ${currentScore === 25 ? 'selected-25' : ''}" onclick="selectQuestionnaireOption(${item.controlId}, 25)">
            <span style="font-weight: 700; color: #f59e0b;">⚠️ 25% — Inicial</span>
            <span>Planilhas manuais ou não padronizado</span>
          </button>
          <button type="button" class="q-option-btn ${currentScore === 50 ? 'selected-50' : ''}" onclick="selectQuestionnaireOption(${item.controlId}, 50)">
            <span style="font-weight: 700; color: #38bdf8;">🔄 50% — Parcial</span>
            <span>Implementado em parte dos ativos</span>
          </button>
          <button type="button" class="q-option-btn ${currentScore === 75 ? 'selected-75' : ''}" onclick="selectQuestionnaireOption(${item.controlId}, 75)">
            <span style="font-weight: 700; color: #2dd4bf;">📈 75% — Majoritário</span>
            <span>Ativo na maior parte da infraestrutura</span>
          </button>
          <button type="button" class="q-option-btn ${currentScore === 100 ? 'selected-100' : ''}" onclick="selectQuestionnaireOption(${item.controlId}, 100)">
            <span style="font-weight: 700; color: #10b981;">✅ 100% — Conforme</span>
            <span>Totalmente implementado e automatizado</span>
          </button>
        </div>

        <!-- Barra de Progresso do Controle -->
        <div class="q-progress-bar-container">
          <div class="q-progress-bar-fill" style="width: ${currentScore}%; background: ${scoreColor};"></div>
        </div>

        <!-- Campo de Evidências / Observações -->
        <div style="margin-top: 0.75rem;">
          <input type="text" class="input-field" style="width: 100%; font-size: 0.78rem; padding: 0.4rem 0.7rem;" 
            placeholder="Evidência / Justificativa da empresa (ex: link de política, print, ferramenta utilizada, chamado)" 
            value="${escapeHtml(ans.obs || '')}" 
            onchange="updateQuestionnaireObs(${item.controlId}, this.value)" />
        </div>
      </div>
    `;
  }).join("");
}

function escapeHtml(str) {
  return String(str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function selectQuestionnaireOption(controlId, score) {
  initQuestionnaireState();
  if (!appState.companyQuestionnaire.answers[controlId]) {
    appState.companyQuestionnaire.answers[controlId] = { score: 0, obs: "" };
  }
  appState.companyQuestionnaire.answers[controlId].score = score;
  saveState();
  renderQuestionnaireTab();
}

function updateQuestionnaireObs(controlId, obsText) {
  initQuestionnaireState();
  if (!appState.companyQuestionnaire.answers[controlId]) {
    appState.companyQuestionnaire.answers[controlId] = { score: 0, obs: "" };
  }
  appState.companyQuestionnaire.answers[controlId].obs = obsText;
  saveState();
}

function applyQuestionnaireToDiagnosis() {
  initQuestionnaireState();
  const q = appState.companyQuestionnaire;
  saveQuestionnaireMeta();

  let updatedCount = 0;
  appState.cisControls.forEach((ctrl) => {
    const ans = q.answers[ctrl.id];
    if (ans && typeof ans.score === "number") {
      ctrl.asIsScore = ans.score;
      if (ans.score >= 85) {
        ctrl.status = `Implementado (${ans.score}%)`;
      } else if (ans.score >= 50) {
        ctrl.status = `Parcial (${ans.score}%)`;
      } else {
        ctrl.status = `Gap Crítico (${ans.score}%)`;
      }

      // Sincronizar salvaguardas
      if (Array.isArray(ctrl.keySafeguards)) {
        ctrl.keySafeguards.forEach((sg, idx) => {
          if (ans.score >= 85) sg.status = "Implementado";
          else if (ans.score >= 50) sg.status = idx === 0 ? "Implementado" : "Parcial";
          else if (ans.score >= 25) sg.status = idx === 0 ? "Parcial" : "Não Implementado";
          else sg.status = "Não Implementado";
        });
      }
      updatedCount++;
    }
  });

  saveState();
  renderAll();

  const metrics = computeMetrics();
  showNexoToast(`
    <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
      <span style="font-size:1.3rem;">⚡</span>
      <strong style="color:var(--accent-emerald); font-size:0.95rem;">Respostas Aplicadas ao Diagnóstico!</strong>
    </div>
    <div style="font-size:0.82rem; color:var(--text-primary); margin-bottom:0.35rem;">
      <strong>Empresa:</strong> ${q.companyName || "Organização Avaliada"}
    </div>
    <div style="font-size:0.75rem; color:var(--text-secondary); line-height:1.4;">
      • Aderência Média As-Is: <strong style="color:var(--accent-blue);">${metrics.avgAsIs}%</strong><br/>
      • Meta To-Be: <strong>${metrics.ig}</strong> (${metrics.avgToBe}%) | Gap Calculado: <strong style="color:var(--accent-rose);">${metrics.avgGap}%</strong><br/>
      • <strong>${updatedCount}</strong> controles CIS v8.1 e salvaguardas atualizados.
    </div>
  `);

  switchTab("tab-overview");
}

function fillRealisticQuestionnaireExample() {
  initQuestionnaireState();
  const q = appState.companyQuestionnaire;
  q.companyName = "TechCloud Logística & Pagamentos S/A";
  q.sector = "Tecnologia / Software (SaaS)";
  q.size = "Médio (51 a 250 colaboradores / multi-cloud)";
  q.assessor = "Davi Freire Zanatta & Luiz Alberto Ferreira Gomes (SecOps)";
  q.assessmentDate = "2026-11-12";
  q.targetIg = "IG2";

  const realisticValues = {
    1: { score: 50, obs: "Inventário físico em planilha e Active Directory; documentação 1.1.2 desatualizada há 190 dias." },
    2: { score: 50, obs: "Softwares rastreados por inventário do Windows Defender; sem allowlisting formal." },
    3: { score: 25, obs: "Banco de produção criptografado; banco de homologação sem KMS/TDE e sem RoPA LGPD." },
    4: { score: 50, obs: "GPOs aplicadas em estações; servidores Linux em nuvem sem baseline CIS Benchmark 4.1." },
    5: { score: 50, obs: "Contas de administrador compartilhadas entre analistas de infraestrutura." },
    6: { score: 25, obs: "MFA obrigatório apenas em e-mail e VPN; 4 contas de Domain Admin sem MFA imposto (CIS 6.5)." },
    7: { score: 50, obs: "Varredura de vulnerabilidades executada semestralmente; patches críticos atrasados." },
    8: { score: 25, obs: "Logs dispersos nos servidores locais com retenção de apenas 15 dias; sem SIEM centralizado." },
    9: { score: 75, obs: "SPF e DKIM ativos; DMARC em modo monitoramento (p=none); DNS com filtro Cloudflare." },
    10: { score: 75, obs: "Microsoft Defender for Endpoint com proteção em tempo real em 90% das máquinas." },
    11: { score: 50, obs: "Backup diário automatizado em storage externo; testes de restauração não realizados em 2026." },
    12: { score: 50, obs: "VPC com regras de firewall na nuvem, porém rede interna de escritório plana." },
    13: { score: 25, obs: "Sem IDS/IPS ativo no tráfego interno; apenas firewall de borda." },
    14: { score: 50, obs: "Treinamento admissional realizado; sem testes contínuos de phishing." },
    15: { score: 25, obs: "Contratos de fornecedores de cloud sem análise de DPA ou auditoria de conformidade LGPD." },
    16: { score: 50, obs: "Linters e testes automatizados no GitHub Actions; SAST/DAST não bloqueiam o pipeline." },
    17: { score: 25, obs: "Plano de Resposta a Incidentes básico em PDF; sem equipe formal de CSIRT e sem playbook SOAR." },
    18: { score: 0, obs: "Nenhum teste de invasão (pentest) executado nos últimos 24 meses." }
  };

  q.answers = realisticValues;
  saveState();
  renderQuestionnaireTab();

  showNexoToast(`
    <div style="display:flex; align-items:center; gap:0.5rem;">
      <span style="font-size:1.25rem;">✨</span>
      <div>
        <strong style="color:var(--accent-purple);">Exemplo Realista Preenchido!</strong><br/>
        <span style="font-size:0.75rem; color:var(--text-secondary);">Clique em <strong>'⚡ Aplicar Respostas'</strong> para gerar a Gap Analysis.</span>
      </div>
    </div>
  `);
}

function resetQuestionnaire() {
  if (!confirm("Deseja realmente zerar todas as respostas do questionário?")) return;
  initQuestionnaireState();
  appState.cisControls.forEach((c) => {
    appState.companyQuestionnaire.answers[c.id] = { score: 0, obs: "" };
  });
  saveState();
  renderQuestionnaireTab();
  showNexoToast(`
    <div style="display:flex; align-items:center; gap:0.5rem;">
      <span style="font-size:1.2rem;">🔄</span>
      <strong style="color:var(--accent-blue);">Questionário Zerado com Sucesso.</strong>
    </div>
  `);
}

function exportQuestionnaireJSON() {
  initQuestionnaireState();
  saveQuestionnaireMeta();
  const q = appState.companyQuestionnaire;
  const metrics = computeMetrics();

  const payload = {
    documentType: "NEXO_COMPANY_QUESTIONNAIRE_AS_IS",
    exportedAt: new Date().toISOString(),
    organization: {
      companyName: q.companyName,
      sector: q.sector,
      size: q.size,
      assessor: q.assessor,
      assessmentDate: q.assessmentDate,
      targetIg: appState.metadata.targetIG
    },
    summaryScore: {
      averageScoreAsIs: metrics.avgAsIs,
      targetScoreToBe: metrics.avgToBe,
      gapAverage: metrics.avgGap
    },
    answers: q.answers,
    controlsSummary: appState.cisControls.map((c) => ({
      id: c.id,
      code: c.code,
      title: c.title,
      declaredScore: q.answers[c.id]?.score || 0,
      evidenceObs: q.answers[c.id]?.obs || ""
    }))
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safeName = (q.companyName || "Empresa").replace(/[^a-zA-Z0-9]/g, "_");
  a.download = `NEXO_Questionario_${safeName}_${appState.metadata.targetIG}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function importQuestionnaireJSON(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const parsed = JSON.parse(e.target.result);
      initQuestionnaireState();
      const q = appState.companyQuestionnaire;

      if (parsed.organization) {
        if (parsed.organization.companyName) q.companyName = parsed.organization.companyName;
        if (parsed.organization.sector) q.sector = parsed.organization.sector;
        if (parsed.organization.size) q.size = parsed.organization.size;
        if (parsed.organization.assessor) q.assessor = parsed.organization.assessor;
        if (parsed.organization.assessmentDate) q.assessmentDate = parsed.organization.assessmentDate;
        if (parsed.organization.targetIg) {
          appState.metadata.targetIG = parsed.organization.targetIg;
          document.getElementById("globalIgSelector").value = parsed.organization.targetIg;
        }
      }

      if (parsed.answers) {
        q.answers = parsed.answers;
      } else if (Array.isArray(parsed.controlsSummary)) {
        parsed.controlsSummary.forEach((item) => {
          if (item.id) {
            q.answers[item.id] = {
              score: item.declaredScore || 0,
              obs: item.evidenceObs || ""
            };
          }
        });
      }

      saveState();
      renderQuestionnaireTab();

      showNexoToast(`
        <div style="display:flex; align-items:center; gap:0.5rem;">
          <span style="font-size:1.3rem;">📂</span>
          <div>
            <strong style="color:var(--accent-emerald);">Respostas do Questionário Carregadas!</strong><br/>
            <span style="font-size:0.75rem; color:var(--text-secondary);">Arquivo: ${file.name}</span>
          </div>
        </div>
      `);
    } catch (err) {
      alert("Erro ao importar questionário JSON: " + err.message);
    }
    event.target.value = "";
  };
  reader.readAsText(file);
}

// ============================================================================
// IMPORTAÇÃO / EXPORTAÇÃO GLOBAL DE DIAGNÓSTICO
// ============================================================================
function processJsonData(parsed, sourceFileName = "Arquivo JSON") {
  try {
    let updatedControls = 0;
    let scenarioTitle = parsed.scenarioName || parsed.project || sourceFileName;

    if (parsed.projectData) {
      appState = parsed.projectData;
      scenarioTitle = appState.metadata?.projectTitle || scenarioTitle;
    } else {
      // 1. Meta Target IG
      const rawIg = parsed.targetIG || parsed.target_ig;
      if (rawIg) {
        const ig = rawIg.toString().toUpperCase();
        if (["IG1", "IG2", "IG3"].includes(ig)) {
          appState.metadata.targetIG = ig;
          const selector = document.getElementById("globalIgSelector");
          if (selector) selector.value = ig;
        }
      }

      // 2. Pontuações de Controles CIS (cisControlsScores, cis_controls, controls_gap_analysis)
      const ctrlList = parsed.cisControlsScores || parsed.cis_controls || parsed.controls_gap_analysis;
      if (Array.isArray(ctrlList)) {
        ctrlList.forEach((sc) => {
          const ctrl = appState.cisControls.find((c) => c.id === sc.id || c.code === sc.code);
          const score = typeof sc.asIsScore === "number" ? sc.asIsScore :
                        typeof sc.as_is_score === "number" ? sc.as_is_score :
                        typeof sc.score === "number" ? sc.score : null;
          if (ctrl && score !== null) {
            ctrl.asIsScore = score;
            if (sc.status) {
              ctrl.status = sc.status;
            } else {
              ctrl.status = score >= 85 ? `Implementado (${score}%)` : score >= 50 ? `Parcial (${score}%)` : `Gap Crítico (${score}%)`;
            }
            if (Array.isArray(ctrl.keySafeguards)) {
              ctrl.keySafeguards.forEach((sg) => {
                if (score >= 85) sg.status = "Implementado";
                else if (score >= 50) sg.status = "Parcial";
                else sg.status = "Não Implementado";
              });
            }
            // Sincronizar resposta no questionário também
            initQuestionnaireState();
            if (!appState.companyQuestionnaire.answers[ctrl.id]) {
              appState.companyQuestionnaire.answers[ctrl.id] = { score, obs: "" };
            } else {
              appState.companyQuestionnaire.answers[ctrl.id].score = score;
            }
            updatedControls++;
          }
        });
      }

      // 3. Avaliações de Regras Agentless (Ex: nexo_evidence_report.json)
      if (Array.isArray(parsed.rule_evaluations)) {
        parsed.rule_evaluations.forEach((r) => {
          const rId = r.rule_id || "";
          const score = Math.round(r.as_is_score ?? 0);
          let targetId = null;
          if (rId.includes("1.1.2")) targetId = 1;
          else if (rId.includes("6.5")) targetId = 6;
          else if (rId.includes("3.11")) targetId = 3;
          else if (rId.includes("4.1")) targetId = 4;

          if (targetId) {
            const ctrl = appState.cisControls.find((c) => c.id === targetId);
            if (ctrl) {
              ctrl.asIsScore = score;
              ctrl.status = score >= 80 ? `Conforme (${score}%)` : `Gap Detectado (${score}%)`;
              updatedControls++;
            }
          }
        });
      }

      // 4. Conectores de API
      if (Array.isArray(parsed.apiConnectors)) {
        parsed.apiConnectors.forEach((inc, i) => {
          if (appState.apiConnectors[i]) {
            Object.assign(appState.apiConnectors[i], inc);
          }
        });
      }

      // 5. Ativos Corporativos
      if (Array.isArray(parsed.assets) && parsed.assets.length > 0) {
        appState.assets = parsed.assets;
      }

      // 6. Matriz de Riscos
      if (Array.isArray(parsed.risks) && parsed.risks.length > 0) {
        appState.riskMatrix = parsed.risks;
      }

      // 7. Ações 5W2H
      if (Array.isArray(parsed.actions5W2H) && parsed.actions5W2H.length > 0) {
        appState.actionPlan5W2H = parsed.actions5W2H;
      }
    }

    saveState();
    renderAll();

    const metrics = computeMetrics();
    showNexoToast(`
      <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
        <span style="font-size:1.25rem;">✅</span>
        <strong style="color:var(--accent-emerald); font-size:0.95rem;">Cenário JSON Carregado!</strong>
      </div>
      <div style="font-size:0.83rem; color:var(--text-primary); margin-bottom:0.35rem;">
        <strong>Identificação:</strong> ${scenarioTitle}
      </div>
      <div style="font-size:0.75rem; color:var(--text-secondary); line-height:1.4;">
        • Aderência Média As-Is: <strong style="color:var(--accent-blue);">${metrics.avgAsIs}%</strong><br/>
        • Meta To-Be: <strong>${metrics.ig}</strong> (${metrics.avgToBe}%) | Gap Médio: <strong>${metrics.avgGap}%</strong><br/>
        • Controles Atualizados: <strong>${updatedControls}</strong> | Total de Ativos: <strong>${appState.assets.length}</strong>
      </div>
    `);
  } catch (err) {
    alert("Erro ao processar dados do JSON: " + err.message);
  }
}

function importDiagnosticJSON(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const parsed = JSON.parse(e.target.result);
      processJsonData(parsed, file.name);
    } catch (err) {
      alert("Erro ao ler arquivo JSON: " + err.message);
    }
    event.target.value = "";
  };
  reader.readAsText(file);
}

function loadQuickScenario(key) {
  if (!key) return;

  if (key === "padrao") {
    resetPrototypeData();
    showNexoToast(`
      <div style="display:flex; align-items:center; gap:0.5rem;">
        <span style="font-size:1.2rem;">🔄</span>
        <strong style="color:var(--accent-blue);">Estado Inicial da PoC Restaurado!</strong>
      </div>
    `);
    const sel = document.getElementById("quickScenarioSelect");
    if (sel) sel.value = "";
    return;
  }

  const s1Scores = [
    { id: 1, code: "CIS 01", asIsScore: 45, status: "Gap Documentação 1.1.2 (45%)" },
    { id: 2, code: "CIS 02", asIsScore: 40, status: "Sem Allowlisting (40%)" },
    { id: 3, code: "CIS 03", asIsScore: 28, status: "Sem Criptografia KMS/LGPD (28%)" },
    { id: 4, code: "CIS 04", asIsScore: 35, status: "Sem Baseline CIS Benchmark (35%)" },
    { id: 5, code: "CIS 05", asIsScore: 48, status: "Contas Admin Compartilhadas (48%)" },
    { id: 6, code: "CIS 06", asIsScore: 30, status: "Ausência de MFA Admin (30%)" },
    { id: 7, code: "CIS 07", asIsScore: 35, status: "Patches Manuais Atrasados (35%)" },
    { id: 8, code: "CIS 08", asIsScore: 25, status: "Logs Descentralizados 15d (25%)" },
    { id: 9, code: "CIS 09", asIsScore: 55, status: "DMARC em Modo None (55%)" },
    { id: 10, code: "CIS 10", asIsScore: 60, status: "Antivírus Básico sem EDR (60%)" },
    { id: 11, code: "CIS 11", asIsScore: 42, status: "Backup sem Imutabilidade/Teste (42%)" },
    { id: 12, code: "CIS 12", asIsScore: 40, status: "Rede Plana sem VLAN Restrita (40%)" },
    { id: 13, code: "CIS 13", asIsScore: 25, status: "Sem IDS/IPS Ativo (25%)" },
    { id: 14, code: "CIS 14", asIsScore: 35, status: "Sem Treinamento de Phishing (35%)" },
    { id: 15, code: "CIS 15", asIsScore: 30, status: "Fornecedores sem Cláusula LGPD (30%)" },
    { id: 16, code: "CIS 16", asIsScore: 25, status: "Pipelines sem SAST/DAST (25%)" },
    { id: 17, code: "CIS 17", asIsScore: 30, status: "Sem Playbook SOAR / PRI Defasado (30%)" },
    { id: 18, code: "CIS 18", asIsScore: 20, status: "Pentest Não Executado (20%)" }
  ];

  const s2Scores = [
    { id: 1, code: "CIS 01", asIsScore: 96, status: "Implementado - Docs 1.1.2 Versionados (96%)" },
    { id: 2, code: "CIS 02", asIsScore: 92, status: "Implementado - SBOM & Inventário (92%)" },
    { id: 3, code: "CIS 03", asIsScore: 95, status: "Implementado - KMS/TDE & RoPA LGPD (95%)" },
    { id: 4, code: "CIS 04", asIsScore: 94, status: "Implementado - Hardening IaC Ansible (94%)" },
    { id: 5, code: "CIS 05", asIsScore: 96, status: "Implementado - Contas Admin Dedicadas (96%)" },
    { id: 6, code: "CIS 06", asIsScore: 98, status: "Implementado - MFA 100% Obrigatório (98%)" },
    { id: 7, code: "CIS 07", asIsScore: 90, status: "Implementado - Scan Contínuo Agentless (90%)" },
    { id: 8, code: "CIS 08", asIsScore: 92, status: "Implementado - SIEM 90 Dias Imutável (92%)" },
    { id: 9, code: "CIS 09", asIsScore: 92, status: "Implementado - DMARC Reject & DNS Filter (92%)" },
    { id: 10, code: "CIS 10", asIsScore: 95, status: "Implementado - EDR Comportamental Ativo (95%)" },
    { id: 11, code: "CIS 11", asIsScore: 96, status: "Implementado - Object Lock & Restore Testado (96%)" },
    { id: 12, code: "CIS 12", asIsScore: 90, status: "Implementado - Microssegmentação VPC/VLAN (90%)" },
    { id: 13, code: "CIS 13", asIsScore: 88, status: "Implementado - NIDS & GuardDuty Ativos (88%)" },
    { id: 14, code: "CIS 14", asIsScore: 92, status: "Implementado - Programa Contínuo LGPD/SI (92%)" },
    { id: 15, code: "CIS 15", asIsScore: 86, status: "Implementado - Contratos DPA Auditados (86%)" },
    { id: 16, code: "CIS 16", asIsScore: 88, status: "Implementado - SAST/DAST Integrado (88%)" },
    { id: 17, code: "CIS 17", asIsScore: 92, status: "Implementado - SOAR Automatizado (92%)" },
    { id: 18, code: "CIS 18", asIsScore: 85, status: "Implementado - Pentest Validado (85%)" }
  ];

  if (key === "exemplo_1") {
    processJsonData({
      scenarioName: "Cenário 1 — Diagnóstico Inicial (As-Is Crítico / Pré-Remediação 5W2H)",
      targetIG: "IG2",
      cisControlsScores: s1Scores
    }, "exemplo_1_cenario_critico_as_is.json");
  } else if (key === "exemplo_2") {
    processJsonData({
      scenarioName: "Cenário 2 — Diagnóstico Evoluído (Pós-Plano 5W2H & Automação DevSecOps)",
      targetIG: "IG2",
      cisControlsScores: s2Scores
    }, "exemplo_2_cenario_evoluido_pos_5w2h.json");
  } else if (key === "relatorio") {
    processJsonData({
      scenarioName: "Relatório de Evidências da Validação em 3 Níveis (Seção 4.3)",
      targetIG: "IG2",
      rule_evaluations: [
        { rule_id: "RULE-CIS-1.1.2-DOCS", as_is_score: 66.7 },
        { rule_id: "RULE-CIS-6.5-MFA", as_is_score: 75.0 },
        { rule_id: "RULE-CIS-3.11-LGPD-GDPR", as_is_score: 60.0 },
        { rule_id: "RULE-CIS-4.1-HARDENING", as_is_score: 87.5 }
      ]
    }, "nexo_evidence_report.json");
  }

  const sel = document.getElementById("quickScenarioSelect");
  if (sel) sel.value = "";
}

function setupDragAndDrop() {
  const overlay = document.getElementById("dropZoneOverlay");
  let dragCounter = 0;

  window.addEventListener("dragenter", (e) => {
    e.preventDefault();
    dragCounter++;
    if (overlay) overlay.style.display = "flex";
  });

  window.addEventListener("dragover", (e) => {
    e.preventDefault();
  });

  window.addEventListener("dragleave", (e) => {
    e.preventDefault();
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      if (overlay) overlay.style.display = "none";
    }
  });

  window.addEventListener("drop", (e) => {
    e.preventDefault();
    dragCounter = 0;
    if (overlay) overlay.style.display = "none";

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      const file = files[0];
      if (file.name.endsWith(".json")) {
        const reader = new FileReader();
        reader.onload = (ev) => {
          try {
            const parsed = JSON.parse(ev.target.result);
            processJsonData(parsed, file.name);
          } catch (err) {
            alert("Erro ao ler JSON arrastado: " + err.message);
          }
        };
        reader.readAsText(file);
      } else {
        alert("Por favor, solte um arquivo com extensão .json");
      }
    }
  });
}

function renderAll() {
  renderGlobalKPIs();
  renderOverviewTab();
  renderQuestionnaireTab();
  renderConnectorsAndAssets();
  renderCoreRulesAndCompliance();
  renderGapAndRisksTab();
  renderActionPlanAndAutomation();
}

window.addEventListener("DOMContentLoaded", () => {
  document.getElementById("globalIgSelector").value = appState.metadata.targetIG;
  renderAll();
  setupDragAndDrop();
});
