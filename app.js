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

function changeTargetIG(newIG) {
  appState.metadata.targetIG = newIG;
  saveState();
  renderAll();
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
  document.getElementById("overviewIgBadge").textContent = `Alvo: ${ig}`;

  const nistFunctions = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"];
  const nistContainer = document.getElementById("nistComparisonContainer");

  let nistHtml = "";
  nistFunctions.forEach((fn) => {
    const matched = appState.cisControls.filter((c) => c.nistFunction.includes(fn));
    const asIs = Math.round(matched.reduce((a, c) => a + c.asIsScore, 0) / (matched.length || 1));
    const toBe = Math.round(matched.reduce((a, c) => a + c.toBeScore[ig], 0) / (matched.length || 1));
    const gap = Math.max(0, toBe - asIs);

    nistHtml += `
      <div class="progress-row">
        <div class="progress-header">
          <span><strong>${fn}</strong> ${fn === "GOVERN" ? '<span class="badge badge-purple">NIST CSF 2.0 &bull; CIS v8.1</span>' : ""}</span>
          <span>As-Is: <strong>${asIs}%</strong> &bull; Meta (${ig}): <strong>${toBe}%</strong> &bull; <span style="color:var(--accent-rose)">Gap: -${gap}%</span></span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" style="width:${asIs}%; background: linear-gradient(90deg, #0284c7, #38bdf8);"></div>
          <div class="progress-marker" style="left:${toBe}%;" title="Meta To-Be (${toBe}%)"></div>
        </div>
      </div>
    `;
  });
  nistContainer.innerHTML = nistHtml;

  // Tríade CIA + Comparativo Manual vs Automatizado
  const pillars = ["Confidencialidade", "Integridade", "Disponibilidade"];
  const ciaContainer = document.getElementById("ciaAndCmmcContainer");
  let ciaHtml = `<div style="margin-bottom:1rem;">`;

  pillars.forEach((pillar) => {
    const controls = appState.cisControls.filter((c) => c.cia === pillar);
    const score = Math.round(controls.reduce((a, c) => a + c.asIsScore, 0) / (controls.length || 1));
    const target = Math.round(controls.reduce((a, c) => a + c.toBeScore[ig], 0) / (controls.length || 1));
    const color =
      pillar === "Confidencialidade" ? "#38bdf8" : pillar === "Integridade" ? "#10b981" : "#f59e0b";

    ciaHtml += `
      <div class="progress-row">
        <div class="progress-header">
          <span><strong>${pillar}</strong> (${controls.length} Controles CIS)</span>
          <span>Atual: <strong>${score}%</strong> / Meta: <strong>${target}%</strong></span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" style="width:${score}%; background:${color};"></div>
          <div class="progress-marker" style="left:${target}%;"></div>
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

  // Tabela do Cronograma
  const tbody = document.querySelector("#timelineTable tbody");
  tbody.innerHTML = appState.projectTimeline
    .map((item) => {
      const badgeClass =
        item.status === "Concluída"
          ? "badge-emerald"
          : item.status.includes("validação")
          ? "badge-blue"
          : "badge-amber";
      return `
        <tr>
          <td><strong>${item.stage}</strong></td>
          <td><span class="badge ${badgeClass}">${item.status}</span></td>
          <td>${item.period}</td>
          <td>${item.deliverable}</td>
          <td style="min-width:140px;">
            <div class="progress-track" style="height:8px;">
              <div class="progress-fill" style="width:${item.progress}%; background:var(--accent-emerald);"></div>
            </div>
            <span style="font-size:0.74rem; color:var(--text-secondary);">${item.progress}%</span>
          </td>
        </tr>
      `;
    })
    .join("");
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

function importDiagnosticJSON(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const parsed = JSON.parse(e.target.result);
      if (parsed.projectData) {
        appState = parsed.projectData;
      } else {
        if (parsed.targetIG) appState.metadata.targetIG = parsed.targetIG;
        if (Array.isArray(parsed.assets)) appState.assets = parsed.assets;
        if (Array.isArray(parsed.apiConnectors)) {
          parsed.apiConnectors.forEach((inc, i) => {
            if (appState.apiConnectors[i]) {
              Object.assign(appState.apiConnectors[i], inc);
            }
          });
        }
        if (Array.isArray(parsed.cisControlsScores)) {
          parsed.cisControlsScores.forEach((sc) => {
            const ctrl = appState.cisControls.find((c) => c.id === sc.id || c.code === sc.code);
            if (ctrl && typeof sc.asIsScore === "number") {
              ctrl.asIsScore = sc.asIsScore;
            }
          });
        }
      }
      document.getElementById("globalIgSelector").value = appState.metadata.targetIG;
      saveState();
      renderAll();
    } catch (err) {
      alert("Erro ao importar arquivo JSON: " + err.message);
    }
    event.target.value = "";
  };
  reader.readAsText(file);
}

function renderAll() {
  renderGlobalKPIs();
  renderOverviewTab();
  renderConnectorsAndAssets();
  renderCoreRulesAndCompliance();
  renderGapAndRisksTab();
  renderActionPlanAndAutomation();
}

window.addEventListener("DOMContentLoaded", () => {
  document.getElementById("globalIgSelector").value = appState.metadata.targetIG;
  renderAll();
});
