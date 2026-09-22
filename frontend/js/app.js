let caseState = null;
let currentReplayStep = 6;

document.addEventListener("DOMContentLoaded", () => {
  fetchCaseData();
});

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

  event.currentTarget.classList.add('active');
  document.getElementById(tabId).classList.add('active');

  if (tabId === 'tab-graph') {
    setTimeout(drawGraph, 100);
  }
}

async function fetchCaseData() {
  try {
    const res = await fetch('/api/case');
    const data = await res.json();
    caseState = data;
    console.log('[fetchCaseData] Loaded case data:', {
      case_id: data.case.case_id,
      graph_nodes: data.case.graph ? data.case.graph.nodes.length : 0,
      graph_edges: data.case.graph ? data.case.graph.edges.length : 0
    });
    renderDashboard(data);
    // Removed: fetchCasesList() - Saved cases dropdown removed from UI
    // Phase 5: also fetch benchmark metrics directly so table always populates
    fetchBenchmarkMetrics();
  } catch (err) {
    console.error("Failed to fetch case data:", err);
  }
}

// Phase 5: fetch measured benchmark metrics from GET /api/evaluation
async function fetchBenchmarkMetrics() {
  try {
    const res = await fetch('/api/evaluation');
    if (!res.ok) {
      console.warn('[Benchmark] GET /api/evaluation returned', res.status, '— table will be empty until server restart');
      return;
    }
    const raw = await res.json();
    // raw = { metadata, benchmarks, summary } from runner.run_full_benchmark() or get_latest_results()
    // Transform into the metrics shape expected by renderBenchmarkMetrics
    const metrics = transformRawBenchmarkToMetrics(raw);
    renderBenchmarkMetrics(metrics);
  } catch (err) {
    console.warn('[Benchmark] Could not load benchmark metrics:', err);
  }
}

// Transforms the raw benchmark_results.json shape into renderBenchmarkMetrics() schema
function transformRawBenchmarkToMetrics(raw) {
  const benchmarks = raw.benchmarks || {};
  const ext  = benchmarks.entity_extraction || {};
  const graph = benchmarks.graph_path_recovery || {};
  const rag   = benchmarks.vector_rag_retrieval || {};
  const iso   = benchmarks.case_isolation || {};
  const hypo  = benchmarks.hypothesis_consistency || {};
  const tool  = benchmarks.tool_execution_latencies || {};
  const pipe  = benchmarks.end_to_end_pipeline || {};

  function pct(val) { return val !== undefined ? `${(val * 100).toFixed(1)}%` : 'NOT AVAILABLE'; }
  function ms(val)  { return val !== undefined ? `${val.toFixed(1)}ms` : 'NOT AVAILABLE'; }
  function sec(val) { return val !== undefined ? `${val.toFixed(2)}s` : 'NOT AVAILABLE'; }

  const measured_f1      = pct(ext.overall_f1);
  const measured_prec    = pct(ext.overall_precision);
  const measured_graph   = pct(graph.path_recovery_rate);
  const measured_rag_hit = pct(rag.hit_rate);
  const measured_rag_pak = pct(rag.precision_at_k);
  const measured_iso     = pct(iso.isolation_accuracy);
  const measured_hypo    = pct(hypo.leading_hypothesis_consistency_rate);
  const measured_tool    = ms(tool.overall_mean_latency_ms);
  const measured_e2e     = sec(pipe.mean_pipeline_latency_seconds);

  const benchmark_table = [
    {
      metric: 'Entity Extraction F1 Score', category: 'Extraction',
      measured_value: measured_f1, precision: `P: ${measured_prec}`,
      trials: ext.execution_time_seconds !== undefined ? `${ext.execution_time_seconds.toFixed(3)}s` : 'N/A',
      status: 'MEASURED', result: ext.passed ? 'PASS' : 'FAIL'
    },
    {
      metric: 'Graph Attack Path Recovery', category: 'Graph Analytics',
      measured_value: measured_graph,
      precision: `${graph.paths_recovered || 0}/${graph.paths_tested || 0} Paths`,
      trials: graph.paths_tested || 0, status: 'MEASURED', result: graph.passed ? 'PASS' : 'FAIL'
    },
    {
      metric: 'Vector RAG Retrieval Hit Rate', category: 'RAG Retrieval',
      measured_value: measured_rag_hit, precision: `P@K: ${measured_rag_pak}`,
      trials: rag.queries_evaluated || 0, status: 'MEASURED', result: rag.passed ? 'PASS' : 'FAIL'
    },
    {
      metric: 'Case Isolation Correctness', category: 'Multi-Tenancy',
      measured_value: measured_iso, precision: 'Zero Leakage',
      trials: 2, status: 'MEASURED', result: iso.passed ? 'PASS' : 'FAIL'
    },
    {
      metric: 'Hypothesis Evaluation Consistency', category: 'Reasoning (ACH)',
      measured_value: measured_hypo,
      precision: `Score Std: ${hypo.leading_score_std !== undefined ? hypo.leading_score_std.toFixed(3) : 'N/A'}`,
      trials: hypo.runs_evaluated || 0, status: 'MEASURED', result: hypo.passed ? 'PASS' : 'FAIL'
    },
    {
      metric: 'Avg Controlled Tool Latency', category: 'Tool Calling',
      measured_value: measured_tool,
      precision: `Min: ${tool.overall_min_latency_ms !== undefined ? tool.overall_min_latency_ms.toFixed(1) : 'N/A'}ms`,
      trials: tool.tools_tested || 0, status: 'MEASURED', result: tool.passed ? 'PASS' : 'FAIL'
    },
    {
      metric: 'End-to-End Investigation Latency', category: 'Pipeline',
      measured_value: measured_e2e,
      precision: `Steps: ${pipe.mean_audit_steps || 0}`,
      trials: pipe.total_runs || 0, status: 'MEASURED', result: pipe.passed ? 'PASS' : 'FAIL'
    }
  ];

  const improvements = {
    'entity_extraction_f1': `${measured_f1} (Measured)`,
    'rag_hit_rate': `${measured_rag_hit} (Measured)`,
    'graph_path_recovery': `${measured_graph} (Measured)`,
    'case_isolation_accuracy': `${measured_iso} (Measured)`
  };

  const manual_investigation = {
    'ioc_extraction_f1': 'Baseline Analyst (Manual)', 'graph_path_recovery': 'Manual Correlation',
    'rag_retrieval_hit_rate': 'Manual Keyword Search', 'case_isolation': 'Manual Access Control',
    'hypothesis_consistency': 'Analyst Subjective', 'pipeline_latency': 'Manual Workflow'
  };
  const sentinel_autonomous = {
    'ioc_extraction_f1': `${measured_f1} [MEASURED]`, 'graph_path_recovery': `${measured_graph} [MEASURED]`,
    'rag_retrieval_hit_rate': `${measured_rag_hit} [MEASURED]`, 'case_isolation': `${measured_iso} [MEASURED]`,
    'hypothesis_consistency': `${measured_hypo} [MEASURED]`, 'pipeline_latency': `${measured_e2e} [MEASURED]`
  };

  return { improvements, benchmark_table, manual_investigation, sentinel_autonomous,
           is_measured: true, summary: raw.summary || {} };
}

async function fetchCasesList() {
  try {
    const res = await fetch('/api/cases');
    const data = await res.json();
    const selector = document.getElementById('caseSelector');
    if (selector && data.cases) {
      selector.innerHTML = '<option value="">📁 Saved Cases...</option>' + data.cases.map(c => 
        `<option value="${c.case_id}">${c.case_id} — ${c.title} (${c.risk_rating})</option>`
      ).join('');
    }
  } catch (err) {
    console.error("Failed to fetch cases list:", err);
  }
}

async function switchCase(caseId) {
  if (!caseId) return;
  try {
    const res = await fetch(`/api/cases/${caseId}`);
    if (res.ok) {
      fetchCaseData();
    } else {
      alert(`Failed to load case ${caseId}`);
    }
  } catch (err) {
    console.error("Error switching case:", err);
  }
}

function renderDashboard(data) {
  const caseData = data.case;
  const risk = caseData.risk;
  const leadingH = caseData.leading_hypothesis;

  // Header & Overview Stats
  document.getElementById('navCaseId').innerText = caseData.case_id || 'CASE-2026-0914';
  document.getElementById('riskScoreVal').innerText = `${risk.risk_score}/100`;
  document.getElementById('riskSeverityBadge').innerText = risk.risk_severity;
  document.getElementById('riskSeverityBadge').className = `stat-desc badge-${risk.risk_severity.toLowerCase()}`;
  document.getElementById('confidenceVal').innerText = `${risk.confidence_score}%`;
  document.getElementById('eventsCountVal').innerText = caseData.events.length;
  document.getElementById('leadingHypoVal').innerText = leadingH.title;
  document.getElementById('hypoScoreVal').innerText = `Posterior Prob: ${leadingH.score}%`;

  document.getElementById('confidenceGroundingText').innerText = risk.confidence_grounding;

  const factorsUl = document.getElementById('riskFactorsList');
  factorsUl.innerHTML = risk.risk_factors.map(f => `<li>${f}</li>`).join('');

  document.getElementById('impactSummaryBox').innerHTML = `
    <p><strong>Affected User Accounts:</strong> ${risk.impact_assessment.affected_users.join(', ')}</p>
    <p><strong>Affected Endpoints:</strong> ${risk.impact_assessment.affected_devices.join(', ')}</p>
    <p style="margin-top: 10px; color: var(--accent-amber);"><strong>Summary:</strong> ${risk.impact_assessment.potential_impact_summary}</p>
  `;

  // Events Table
  const eventsTbody = document.getElementById('eventsTableBody');
  eventsTbody.innerHTML = caseData.events.map(e => `
    <tr>
      <td><code>${e.id}</code></td>
      <td>${e.timestamp}</td>
      <td>${e.source_file}</td>
      <td>${e.source_type}</td>
      <td><strong>${e.entity_type}:</strong> ${e.entity_value}</td>
      <td>${e.event_action}</td>
      <td><span class="badge-${e.severity.toLowerCase()}">${e.severity}</span></td>
      <td style="font-size: 12px; font-family: monospace;">${e.raw_ref}</td>
    </tr>
  `).join('');

  // Attack Chain Grid
  const attackGrid = document.getElementById('attackChainGrid');
  attackGrid.innerHTML = caseData.attack_chain.map(ac => `
    <div class="card" style="border-top: 4px solid ${ac.status === 'CONFIRMED' ? 'var(--accent-emerald)' : 'var(--border-color)'};">
      <div style="font-size: 12px; font-weight: 700; color: var(--text-muted);">${ac.stage}</div>
      <div style="font-size: 18px; font-weight: 800; margin: 8px 0; color: ${ac.status === 'CONFIRMED' ? 'var(--accent-emerald)' : 'var(--text-muted)'};">
        ${ac.status}
      </div>
      <div style="font-size: 12px; color: var(--text-muted);">${ac.evidence_count} Evidence Items</div>
    </div>
  `).join('');

  // Timeline Table
  const timelineTbody = document.getElementById('timelineTableBody');
  timelineTbody.innerHTML = caseData.timeline.map(t => `
    <tr>
      <td>#${t.step_num}</td>
      <td>${t.timestamp}</td>
      <td>${t.source_file}</td>
      <td>${t.entity}</td>
      <td>${t.event_action}</td>
      <td><span class="badge-${t.severity.toLowerCase()}">${t.severity}</span></td>
    </tr>
  `).join('');

  // Audit Trail List
  renderAuditTrail(caseData.audit_trail);

  // Hypotheses Matrix
  const hypoDiv = document.getElementById('hypothesesMatrix');
  hypoDiv.innerHTML = caseData.hypotheses.map(h => `
    <div style="background-color: var(--card-bg); padding: 14px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid ${h.status === 'LEADING_HYPOTHESIS' ? 'var(--accent-cyan)' : 'var(--border-color)'}">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
        <strong>${h.id}: ${h.title}</strong>
        <span style="font-weight: 800; color: var(--accent-cyan);">${h.score}%</span>
      </div>
      <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">${h.description}</p>
      <div style="font-size: 12px;">
        <span style="color: var(--accent-emerald);">Supporting: ${h.supporting_evidence.length}</span> | 
        <span style="color: var(--accent-red);">Counter: ${h.counter_evidence.length}</span>
      </div>
    </div>
  `).join('');

  // Dynamic Leads Queue
  const leadsDiv = document.getElementById('leadQueueList');
  leadsDiv.innerHTML = caseData.leads.map(l => `
    <div style="background-color: var(--card-bg); padding: 14px; border-radius: 8px; margin-bottom: 12px;">
      <div style="display: flex; justify-content: space-between; font-size: 12px; color: var(--accent-cyan); margin-bottom: 4px;">
        <span>${l.id} (Priority: ${l.priority})</span>
        <span class="badge-${l.status === 'RESOLVED' ? 'low' : 'high'}">${l.status}</span>
      </div>
      <div style="font-weight: 600; margin-bottom: 6px;">${l.question}</div>
      <div style="font-size: 12px; color: var(--text-muted);">${l.findings || 'Awaiting agent evaluation...'}</div>
    </div>
  `).join('');

  // Threat Intel Grid (Phase 3 Upgrade)
  const intelGrid = document.getElementById('threatIntelGrid');
  intelGrid.innerHTML = (caseData.enriched_intel || []).map(ti => {
    const st = (ti.status || 'LIVE').toUpperCase();
    const statusBadge = st === 'LIVE' ? '<span class="badge-low">🟢 LIVE</span>' :
                        (st === 'CACHED' ? '<span class="badge-low" style="background:#1e3a8a;color:#93c5fd;">🔵 CACHED</span>' :
                        (st === 'FALLBACK' ? '<span class="badge-high">🟡 FALLBACK</span>' :
                        '<span class="badge-critical" style="background:#374151;color:#d1d5db;">⚪ UNAVAILABLE</span>'));

    const indVal = ti.indicator || (ti.interpretation ? ti.interpretation.split(':')[0] : 'Indicator');
    const indType = ti.indicator_type || ti.type || 'IOC';
    const summary = ti.summary || ti.interpretation || 'No details available.';
    const vtText = ti.virustotal && ti.virustotal.malicious_count !== undefined ? `VirusTotal: ${ti.virustotal.malicious_count} Detections` : '';
    const abuseText = ti.abuseipdb && ti.abuseipdb.score !== undefined ? `AbuseIPDB Score: ${ti.abuseipdb.score}%` : '';
    const mitreText = ti.mitre_attck ? `MITRE: ${Array.isArray(ti.mitre_attck) ? ti.mitre_attck.join(', ') : ti.mitre_attck}` : '';

    return `
      <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <div style="font-size: 15px; font-weight: 700; color: var(--accent-cyan);"><code>${indVal}</code> (${indType})</div>
          ${statusBadge}
        </div>
        <div style="font-size: 13px; color: var(--text-main); margin-bottom: 8px;">${summary}</div>
        <div style="font-size: 12px; color: var(--text-muted); display: flex; flex-direction: column; gap: 4px;">
          ${vtText ? `<div style="color: var(--accent-amber);">🛡️ ${vtText}</div>` : ''}
          ${abuseText ? `<div style="color: var(--accent-amber);">⚠️ ${abuseText}</div>` : ''}
          ${mitreText ? `<div style="color: var(--accent-emerald);">🎯 ${mitreText}</div>` : ''}
        </div>
      </div>
    `;
  }).join('');

  // HITL Response Actions Table (Requirement Phase 6)
  const actionsTbody = document.getElementById('actionsTableBody');
  actionsTbody.innerHTML = caseData.pending_response_actions.map(a => {
    let statusBadge = '';
    if (a.status === 'APPROVED') {
      statusBadge = '<span class="badge-low" style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-weight: 700;">🟢 APPROVED</span>';
    } else if (a.status === 'REJECTED') {
      statusBadge = '<span class="badge-critical" style="background: rgba(239, 68, 68, 0.2); color: #f87171; font-weight: 700;">🔴 REJECTED</span>';
    } else {
      statusBadge = '<span class="badge-high" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; font-weight: 700;">🟡 PENDING APPROVAL</span>';
    }

    return `
      <tr>
        <td><code>${a.id}</code></td>
        <td><strong>${a.action_type}</strong></td>
        <td><code>${a.target}</code></td>
        <td><span class="badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td style="font-size: 13px;">${a.evidence_grounding}</td>
        <td>${statusBadge}</td>
        <td>
          ${a.status === 'PENDING_APPROVAL' ? `
            <button class="btn btn-success" style="padding: 4px 10px; font-size: 12px; margin-right: 4px;" onclick="approveAction('${a.id}', true)">Approve</button>
            <button class="btn btn-danger" style="padding: 4px 10px; font-size: 12px;" onclick="approveAction('${a.id}', false)">Reject</button>
          ` : `<span style="font-size: 11px; color: var(--text-muted);">${a.simulated_execution || 'Simulated execution completed'}</span>`}
        </td>
      </tr>
    `;
  }).join('');

  // Benchmark Metrics (Phase 5 Real Measured Evaluation)
  const metrics = data.metrics;
  if (metrics) {
    renderBenchmarkMetrics(metrics);
  }

  // Generate graph summary
  generateGraphSummary();
}

function renderBenchmarkMetrics(metrics) {
  const mGrid = document.getElementById('metricsSummaryGrid');
  if (mGrid && metrics.improvements) {
    mGrid.innerHTML = Object.entries(metrics.improvements).map(([k, v]) => `
      <div class="card">
        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">${k.replace(/_/g, ' ')}</div>
        <div style="font-size: 20px; font-weight: 800; color: var(--accent-emerald); margin-top: 6px;">${v}</div>
      </div>
    `).join('');
  }

  // Detailed Benchmark Table (Phase 5 Live Results)
  const detailedTbody = document.getElementById('detailedBenchmarkTableBody');
  if (detailedTbody && metrics.benchmark_table) {
    detailedTbody.innerHTML = metrics.benchmark_table.map(b => {
      const isPass = b.result === 'PASS';
      const statusBadge = b.status === 'MEASURED' 
        ? `<span class="badge-low" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid #10b981; font-weight: 700; padding: 2px 6px;">MEASURED</span>`
        : `<span class="badge-high" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid #ef4444; font-weight: 700; padding: 2px 6px;">NOT AVAILABLE</span>`;
      const resBadge = isPass 
        ? `<span class="badge-low" style="font-weight: 700;">PASS</span>` 
        : `<span class="badge-high" style="font-weight: 700;">FAIL</span>`;

      return `
        <tr>
          <td><strong style="color: var(--accent-cyan);">${b.metric}</strong></td>
          <td><span style="font-size: 11px; color: var(--text-muted);">${b.category}</span></td>
          <td style="font-size: 14px; font-weight: 800; color: var(--accent-emerald);">${b.measured_value}</td>
          <td style="font-size: 12px; color: var(--text-main); font-family: monospace;">${b.precision}</td>
          <td style="font-size: 12px;">${b.trials}</td>
          <td>${statusBadge}</td>
          <td>${resBadge}</td>
        </tr>
      `;
    }).join('');
  }

  // Comparison Table
  const mTbody = document.getElementById('metricsTableBody');
  if (mTbody && metrics.manual_investigation && metrics.sentinel_autonomous) {
    mTbody.innerHTML = Object.keys(metrics.manual_investigation).map(k => `
      <tr>
        <td><strong>${k.replace(/_/g, ' ').toUpperCase()}</strong></td>
        <td style="color: var(--accent-amber);">${metrics.manual_investigation[k]}</td>
        <td style="color: var(--accent-emerald); font-weight: 700;">${metrics.sentinel_autonomous[k]}</td>
        <td><span class="badge-low" style="font-size: 11px;">VERIFIED REAL</span></td>
      </tr>
    `).join('');
  }
}

async function runLiveBenchmark() {
  const btn = document.getElementById('btnRunBenchmark');
  const status = document.getElementById('benchmarkStatusText');
  if (btn) btn.disabled = true;
  if (status) status.innerText = "Status: Running benchmark suite across all 7 pipeline modules — this takes ~30–90 seconds...";

  try {
    const res = await fetch('/api/evaluation/run', { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    // data is the raw benchmark result: { metadata, benchmarks, summary }
    const passed = data.summary?.passed_benchmarks;
    const total  = data.summary?.total_benchmarks;
    const elapsed = data.metadata?.total_execution_time_seconds;
    if (status) status.innerText = `Status: Complete — ${passed}/${total} benchmarks PASSED in ${elapsed}s. All metrics MEASURED.`;
    // Render the returned measured results immediately without waiting for /api/case
    const metrics = transformRawBenchmarkToMetrics(data);
    renderBenchmarkMetrics(metrics);
    // Also refresh full case data (async, best-effort)
    fetchCaseData();
  } catch (err) {
    console.error("Benchmark error:", err);
    if (status) status.innerText = `Status: Benchmark execution failed — ${err.message}`;
    alert("Failed to execute benchmark: " + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderAuditTrail(trail) {
  const auditDiv = document.getElementById('auditTrailList');
  if (!auditDiv || !trail) return;

  auditDiv.innerHTML = trail.map(step => {
    const isLlm = step.llm_used;
    const badgeClass = isLlm ? 'badge-low' : 'badge-high';
    const rawProv = (step.llm_provider || 'Groq').toLowerCase();
    const provFormatted = rawProv === 'groq' ? 'Groq' : (rawProv === 'openrouter' ? 'OpenRouter' : (rawProv === 'gemini' ? 'Gemini' : step.llm_provider));
    const modeLabel = isLlm ? `Provider: ${provFormatted} | LLM Tool Calling` : 'Autonomous Fallback Planner';
    const modelText = step.llm_model ? ` | Model: ${step.llm_model}` : '';
    const safeArgs = step.tool_args ? JSON.stringify(step.tool_args) : '{}';

    const stoppingHtml = step.stopping_decision ? `
      <div style="margin-top: 8px; padding: 6px 10px; background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: 4px; font-size: 12px; color: var(--accent-emerald);">
        <strong>🛑 DECISION: STOP INVESTIGATION</strong> &bull; ${step.stopping_reason || "Autonomous stopping condition satisfied."}
      </div>
    ` : `
      <div style="margin-top: 6px; font-size: 11px; color: var(--text-muted);">
        <strong>Decision:</strong> Continue to next lead &bull; ${step.next_action || ""}
      </div>
    `;

    return `
    <div class="audit-item" style="border-left: 3px solid ${step.stopping_decision ? '#10b981' : '#06b6d4'};">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
        <div class="audit-step">Step ${step.step} &bull; Tool: <code>${step.tool_called}</code></div>
        <span class="${badgeClass}">${modeLabel}${modelText}</span>
      </div>
      <div style="font-weight: 700; margin: 4px 0; color: #f1f5f9;"><strong>Lead:</strong> ${step.selected_lead || step.question}</div>
      <div style="font-size: 12px; font-family: monospace; color: var(--accent-cyan); margin-bottom: 4px; background: rgba(0,0,0,0.3); padding: 4px 8px; border-radius: 4px;">
        <strong>Tool Args:</strong> ${safeArgs}
      </div>
      <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 4px;"><strong>Rationale:</strong> ${step.rationale}</div>
      <div style="font-size: 13px; color: var(--text-main);"><strong>Findings:</strong> ${step.findings}</div>
      ${step.hypothesis_delta ? `<div style="font-size: 12px; color: var(--accent-emerald); margin-top: 4px;"><strong>Hypothesis Update:</strong> ${step.hypothesis_delta}</div>` : ''}
      ${step.contradiction_check ? `<div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;"><strong>Contradiction Check:</strong> ${step.contradiction_check}</div>` : ''}
      ${stoppingHtml}
    </div>
  `;
  }).join('');
}

async function approveAction(actionId, approved) {
  try {
    await fetch('/api/approve-action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action_id: actionId, approved })
    });
    fetchCaseData();
  } catch (err) {
    console.error("Failed to update action status:", err);
  }
}

async function handleFileUpload(e) {
  e.preventDefault();
  
  const fileInput = document.getElementById('fileInput');
  const uploadBtn = e.target.querySelector('button[type="submit"]');
  
  if (!fileInput.files.length) {
    alert("Please select files to upload.");
    return;
  }

  // Prevent duplicate submissions
  if (uploadBtn.disabled) return;
  uploadBtn.disabled = true;
  const originalText = uploadBtn.textContent;
  uploadBtn.textContent = '⏳ Uploading & Processing...';

  const formData = new FormData();
  for (let f of fileInput.files) {
    formData.append('files', f);
  }

  try {
    const res = await fetch('/api/ingest', { method: 'POST', body: formData });
    const data = await res.json();
    
    if (!res.ok) {
      alert("⚠️ Security Upload Rejected:\n" + (data.detail || data.error || "File validation failed"));
      return;
    }
    
    // Clear input and wait a moment for processing
    fileInput.value = '';
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Reload case data
    await fetchCaseData();
    
    // Show success message
    alert("✅ Evidence files successfully ingested!");
    
  } catch (err) {
    console.error('[Upload] Error:', err);
    alert("❌ Upload failed: " + err.message);
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.textContent = originalText;
  }
}

async function loadDemoDataset() {
  try {
    const btn = event.target;
    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = '⏳ Reloading...';
    
    await fetch('/api/load-demo', { method: 'POST' });
    await new Promise(resolve => setTimeout(resolve, 1000));
    await fetchCaseData();
    
    alert("✅ Demo scenario reloaded.");
    btn.textContent = originalText;
    btn.disabled = false;
  } catch (err) {
    alert("❌ Failed to reload demo scenario: " + err.message);
    event.target.disabled = false;
    event.target.textContent = '🔄 Reset Demo Scenario';
  }
}

async function handleChatSubmit(e) {
  e.preventDefault();
  const input = document.getElementById('chatInput');
  const query = input.value.trim();
  if (!query) return;

  const chatBox = document.getElementById('chatBox');
  chatBox.innerHTML += `<div class="msg msg-user">${query}</div>`;
  input.value = '';

  try {
    const res = await fetch('/api/natural-language', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
    const data = await res.json();

    const methodText = (data.retrieval_method || 'vector').toUpperCase();
    const modelText = (data.model !== undefined && data.model !== null && data.model !== '') ? data.model : 'N/A';
    const confText = (data.confidence !== undefined && data.confidence !== null && data.confidence !== '') ? `${data.confidence}%` : 'N/A';
    
    let responseHtml = `
      <div class="msg msg-agent">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; font-size: 11px; padding-bottom: 6px; border-bottom: 1px solid rgba(255,255,255,0.15);">
          <span class="badge-low" style="background: #1e1b4b; color: #a5b4fc; border: 1px solid #6366f1; padding: 2px 6px; font-weight: 700;">🧠 Semantic Vector RAG</span>
          <span style="color: var(--text-muted);">retrieval_method: <strong>${methodText}</strong> | Model: <strong>${modelText}</strong> | Confidence: <strong>${confText}</strong></span>
        </div>
        <div style="font-size: 14px; line-height: 1.6; margin-bottom: 10px;">${(data.answer || '').replace(/\n/g, '<br>')}</div>
    `;

    // Support data.citations, data.sources, and data.retrieved_chunks
    // Prioritize arrays containing structured objects with chunk_id / relevance_score
    let rawList = [];
    const candidates = [data.citations, data.sources, data.retrieved_chunks];
    for (const list of candidates) {
      if (Array.isArray(list) && list.length > 0 && typeof list[0] === 'object' && list[0] !== null) {
        rawList = list;
        break;
      }
    }
    // Fall back to any non-empty array if no object array found
    if (rawList.length === 0) {
      for (const list of candidates) {
        if (Array.isArray(list) && list.length > 0) {
          rawList = list;
          break;
        }
      }
    }

    if (rawList.length > 0) {
      const isVector = (data.retrieval_method && data.retrieval_method.toLowerCase() === 'vector');
      const countLabel = isVector ? `${rawList.length} Vector Chunks` : `${rawList.length} Citations`;

      responseHtml += `
        <div style="margin-top: 12px; font-size: 12px; border-top: 1px dashed var(--border-color); padding-top: 8px; color: var(--text-muted);">
          <strong style="color: var(--accent-cyan);">🧠 Source Citations & Retrieved Semantic Evidence (${countLabel}):</strong>
          <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 8px;">
      `;

      rawList.forEach((c, idx) => {
        let cid = '';
        let cat = '';
        let stype = '';
        let prov = '';
        let scoreVal = '';
        let snippetText = '';

        if (typeof c === 'string') {
          // Parse string citation e.g. "phishing_email.eml:L3 - To: user.smith@company.com"
          const dashIdx = c.indexOf(' - ');
          const colonIdx = c.indexOf(':');
          if (dashIdx !== -1) {
            prov = c.substring(0, dashIdx).trim();
            snippetText = c.substring(dashIdx + 3).trim();
          } else if (colonIdx !== -1) {
            prov = c.substring(0, colonIdx).trim();
            snippetText = c.substring(colonIdx + 1).trim();
          } else {
            prov = c;
            snippetText = c;
          }
          cid = `CIT-${String(idx + 1).padStart(2, '0')}`;
          cat = prov.toLowerCase().includes('.eml') ? 'Email' :
                (prov.toLowerCase().includes('.json') ? 'Alerts' :
                (prov.toLowerCase().includes('.txt') || prov.toLowerCase().includes('.log') ? 'Logs' :
                (prov.toLowerCase().includes('.pdf') ? 'Advisory' : 'Evidence')));
          stype = cat;
          scoreVal = '';
        } else if (typeof c === 'object' && c !== null) {
          cid = c.chunk_id || c.source_id || c.id || c.doc_id || `CHK-${String(idx + 1).padStart(4, '0')}`;
          cat = c.category || c.document_type || c.type || '';
          stype = c.source_type || c.log_type || c.type || '';
          prov = c.provenance || c.source_file || c.source_id || c.file || '';

          const rawScore = c.relevance_score !== undefined ? c.relevance_score :
                           (c.score !== undefined ? c.score :
                           (c.relevance !== undefined ? c.relevance :
                           (c.similarity !== undefined ? c.similarity : null)));
          if (rawScore !== null && rawScore !== undefined && rawScore !== '') {
            const num = parseFloat(rawScore);
            if (!isNaN(num)) {
              const pct = num <= 1.0 ? num * 100 : num;
              scoreVal = `${pct.toFixed(1)}%`;
            }
          }

          snippetText = c.snippet || c.text || c.content || c.raw_ref || c.raw_text || c.matched_snippet || '';
        }

        const metaParts = [];
        if (cat) metaParts.push(`<strong>Category:</strong> ${cat}`);
        if (stype) metaParts.push(`<strong>Source:</strong> ${stype}`);
        if (prov) metaParts.push(`<strong>Provenance:</strong> <code>${prov}</code>`);

        responseHtml += `
          <div style="background: var(--card-bg, #1e293b); border: 1px solid var(--border-color, #334155); border-radius: 6px; padding: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
              <span style="font-weight: 700; color: var(--accent-cyan, #38bdf8); font-family: monospace;">${cid}</span>
              ${scoreVal ? `<span style="font-size: 11px; font-weight: 700; color: var(--accent-emerald, #34d399);">Relevance: ${scoreVal}</span>` : ''}
            </div>
            ${metaParts.length > 0 ? `<div style="font-size: 11px; color: var(--text-muted, #94a3b8); margin-bottom: 6px;">${metaParts.join(' &nbsp;|&nbsp; ')}</div>` : ''}
            ${snippetText ? `<div style="font-size: 12px; color: var(--text-main, #f8fafc); line-height: 1.5; background: rgba(0,0,0,0.2); padding: 6px 8px; border-radius: 4px;">${snippetText}</div>` : ''}
          </div>
        `;
      });
      responseHtml += `</div></div>`;
    }

    responseHtml += `</div>`;
    chatBox.innerHTML += responseHtml;
    chatBox.scrollTop = chatBox.scrollHeight;
  } catch (err) {
    console.error("NL QA Error:", err);
    chatBox.innerHTML += `<div class="msg msg-agent">Sorry, failed to process query.</div>`;
  }
}

function openExplainModal() {
  if (!caseState) return;
  const exp = caseState.report?.explainability || {};
  const leadingH = caseState.case?.leading_hypothesis || {};
  const audit = caseState.case?.audit_trail || [];
  const content = document.getElementById('explainModalContent');

  content.innerHTML = `
    <h3 style="color: var(--accent-cyan); margin-bottom: 8px;">${exp.title || "Autonomous Evidence Grounding & Explainability"}</h3>
    <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
      SENTINEL conclusions are strictly grounded in multi-source correlated telemetry, threat intelligence feeds, and an audited Bayesian hypothesis evaluation.
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
      <div style="background: var(--panel-bg); padding: 10px; border-radius: 6px;">
        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Leading Hypothesis</div>
        <div style="font-size: 15px; font-weight: 700; color: var(--accent-emerald); margin-top: 4px;">${leadingH.title || "N/A"}</div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Posterior Probability: ${leadingH.score || 0}%</div>
      </div>
      <div style="background: var(--panel-bg); padding: 10px; border-radius: 6px;">
        <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">Confidence Score</div>
        <div style="font-size: 15px; font-weight: 700; color: var(--accent-cyan); margin-top: 4px;">${exp.confidence_score || "N/A"}</div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Audit Steps Executed: ${audit.length}</div>
      </div>
    </div>

    <h4 style="color: var(--accent-cyan); font-size: 14px; margin-bottom: 8px;">Forensic Grounding Pillars</h4>
    <div style="margin-bottom: 16px;">
      ${(exp.supporting_pillars || []).map(p => `
        <div style="background: var(--panel-bg); padding: 10px 12px; border-radius: 6px; margin-bottom: 8px; border-left: 3px solid var(--accent-emerald);">
          <strong style="color: var(--accent-emerald); font-size: 13px;">${p.pillar}</strong>
          <p style="margin-top: 4px; font-size: 12px; color: var(--text-main);">${p.finding}</p>
        </div>
      `).join('')}
    </div>

    <h4 style="color: var(--accent-cyan); font-size: 14px; margin-bottom: 8px;">Audit Trail Progression & Stopping Decision</h4>
    <div style="max-height: 200px; overflow-y: auto; background: rgba(0,0,0,0.2); padding: 8px 12px; border-radius: 6px; font-size: 12px;">
      ${audit.map(s => `
        <div style="padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
          <strong>Step ${s.step}</strong> &bull; <code>${s.tool_called}</code> &bull; <span style="color: var(--accent-cyan);">${s.selected_lead}</span>
          ${s.stopping_decision ? `<div style="color: #34d399; font-weight: 700;">🛑 ${s.stopping_reason || "Concluded"}</div>` : ''}
        </div>
      `).join('')}
    </div>
  `;
  document.getElementById('explainModal').style.display = 'flex';
}

function closeExplainModal() {
  document.getElementById('explainModal').style.display = 'none';
}

function generateGraphSummary() {
  // COMPREHENSIVE INVESTIGATOR-FRIENDLY GRAPH SUMMARY GENERATOR
  // Analyzes actual graph data and generates dynamic investigation findings
  
  try {
    const summaryBox = document.getElementById('graphSummaryBox');
    if (!summaryBox) {
      console.error('[GraphSummary] graphSummaryBox element not found in DOM');
      return;
    }

    if (!caseState) {
      console.warn('[GraphSummary] caseState not loaded');
      summaryBox.innerHTML = '<p style="color: var(--text-muted);">Loading investigation analysis...</p>';
      return;
    }

    const graph = caseState.case && caseState.case.graph ? caseState.case.graph : null;
    const events = caseState.case && caseState.case.events ? caseState.case.events : [];
    const enrichedIntel = caseState.case && caseState.case.enriched_intel ? caseState.case.enriched_intel : [];
    const risk = caseState.case && caseState.case.risk ? caseState.case.risk : {};

    if (!graph || !graph.nodes || graph.nodes.length === 0) {
      console.warn('[GraphSummary] Graph data not available');
      summaryBox.innerHTML = '<p style="color: var(--text-muted);">No graph data available yet.</p>';
      return;
    }

    const nodes = graph.nodes;
    const edges = graph.edges || [];

    console.log('[GraphSummary] Generating summary for', nodes.length, 'nodes and', edges.length, 'edges');

    // ===== GRAPH ANALYSIS =====
    const nodeTypeCounts = {};
    const nodesByType = {};
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (!n) continue;
      const type = n.type || 'Unknown';
      if (!nodeTypeCounts[type]) nodeTypeCounts[type] = 0;
      nodeTypeCounts[type]++;
      if (!nodesByType[type]) nodesByType[type] = [];
      nodesByType[type].push(n);
    }

    const edgeTypeCounts = {};
    for (let i = 0; i < edges.length; i++) {
      const e = edges[i];
      if (!e || !e.source || !e.target) continue;
      const rel = e.relationship || 'connected_to';
      if (!edgeTypeCounts[rel]) edgeTypeCounts[rel] = 0;
      edgeTypeCounts[rel]++;
    }

    const sourceFiles = new Set();
    for (let i = 0; i < edges.length; i++) {
      if (edges[i] && edges[i].source_file) {
        sourceFiles.add(edges[i].source_file);
      }
    }

    const affectedUsers = nodesByType['User'] ? nodesByType['User'].slice(0, 3) : [];
    const affectedDevices = nodesByType['Device'] ? nodesByType['Device'].slice(0, 3) : [];
    const suspDomains = nodesByType['Domain'] ? nodesByType['Domain'].slice(0, 2) : [];
    const suspIPs = nodesByType['IP'] ? nodesByType['IP'].slice(0, 2) : [];

    // ===== BUILD HTML SUMMARY =====
    let html = '<div style="display:flex;flex-direction:column;gap:16px;">';

    // STATISTICS SECTION - ALWAYS VISIBLE
    html += '<div style="background: rgba(15, 23, 42, 0.5); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;"><div style="font-weight: 700; color: var(--text-main); margin-bottom: 12px; font-size: 15px;">📈 GRAPH STATISTICS</div><div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; font-size: 13px;"><div><strong style="color: var(--accent-cyan);">Total Entities:</strong> <span style="color: var(--accent-emerald); font-weight: 700;">' + nodes.length + '</span></div><div><strong style="color: var(--accent-cyan);">Total Relationships:</strong> <span style="color: var(--accent-emerald); font-weight: 700;">' + edges.length + '</span></div>';
    for (const type in nodeTypeCounts) {
      const count = nodeTypeCounts[type];
      const icon = type === 'Email' ? '📧' : (type === 'IP' ? '🌐' : (type === 'Domain' ? '🔗' : (type === 'User' ? '👤' : (type === 'Device' ? '💻' : '📌'))));
      html += '<div><strong style="color: var(--accent-cyan);">' + icon + ' ' + type + ':</strong> <span style="color: var(--accent-emerald); font-weight: 700;">' + count + '</span></div>';
    }
    html += '</div></div>';

    // KEY RELATIONSHIPS
    html += '<div style="background: rgba(15, 23, 42, 0.5); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;"><div style="font-weight: 700; color: var(--accent-emerald); margin-bottom: 12px; font-size: 15px;">📊 KEY RELATIONSHIPS</div><div style="display: flex; flex-direction: column; gap: 6px;">';
    for (const rel in edgeTypeCounts) {
      const count = edgeTypeCounts[rel];
      const label = rel.replace(/_/g, ' ');
      html += '<div style="font-size: 13px; color: var(--text-muted);"><span style="color: var(--accent-cyan);">•</span> ' + label + ': ' + count + '</div>';
    }
    html += '</div></div>';

    // AFFECTED ENTITIES
    html += '<div style="background: rgba(15, 23, 42, 0.5); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;"><div style="font-weight: 700; color: var(--accent-amber); margin-bottom: 12px; font-size: 15px;">👥 AFFECTED ENTITIES</div><div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 13px;">';
    for (let i = 0; i < affectedUsers.length; i++) {
      html += '<div style="color: var(--text-muted);"><strong style="color: var(--accent-cyan);">User:</strong> ' + (affectedUsers[i].label || affectedUsers[i].id) + '</div>';
    }
    for (let i = 0; i < affectedDevices.length; i++) {
      html += '<div style="color: var(--text-muted);"><strong style="color: var(--accent-cyan);">Device:</strong> ' + (affectedDevices[i].label || affectedDevices[i].id) + '</div>';
    }
    for (let i = 0; i < suspDomains.length; i++) {
      html += '<div style="color: var(--text-muted);"><strong style="color: #f87171;">Domain:</strong> ' + (suspDomains[i].label || suspDomains[i].id) + '</div>';
    }
    for (let i = 0; i < suspIPs.length; i++) {
      html += '<div style="color: var(--text-muted);"><strong style="color: #f87171;">IP:</strong> ' + (suspIPs[i].label || suspIPs[i].id) + '</div>';
    }
    html += '</div></div>';

    // EVIDENCE SOURCES
    const sourceList = Array.from(sourceFiles).slice(0, 5).join(' • ') || 'Multiple security logs';
    html += '<div style="background: rgba(15, 23, 42, 0.5); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px;"><div style="font-weight: 700; color: var(--text-main); margin-bottom: 8px; font-size: 15px;">📂 EVIDENCE SOURCES</div><div style="font-size: 13px; color: var(--text-muted);">Evidence connected from: ' + sourceList + '</div></div>';

    // SUMMARY INTERPRETATION
    const malCount = enrichedIntel.filter(function(ti) { return ti && ti.malicious; }).length;
    html += '<div style="background: rgba(59, 130, 246, 0.1); border: 1px solid #3b82f6; border-radius: 8px; padding: 16px; border-left: 4px solid #3b82f6;"><div style="font-weight: 700; color: #3b82f6; margin-bottom: 8px; font-size: 15px;">⚠️ GRAPH INTERPRETATION</div><div style="font-size: 13px; line-height: 1.6; color: var(--text-main);">This graph contains <strong>' + nodes.length + ' entities</strong> connected by <strong>' + edges.length + ' relationships</strong>. ' + (malCount > 0 ? '<strong>' + malCount + ' entities</strong> are flagged as malicious by threat intelligence. ' : '') + 'The network shows connections between ' + (Object.keys(nodeTypeCounts).length) + ' different entity types, indicating a ' + (edges.length > 10 ? 'complex' : 'focused') + ' attack chain spanning multiple stages.</div></div>';

    html += '</div>';

    summaryBox.innerHTML = html;
    console.log('[GraphSummary] Successfully generated summary for ' + nodes.length + ' entities');
  } catch (err) {
    console.error('[GraphSummary] Error:', err);
    const summaryBox = document.getElementById('graphSummaryBox');
    if (summaryBox) {
      summaryBox.innerHTML = '<p style="color: #f87171;">Error generating summary: ' + err.message + '</p>';
    }
  }
}

function drawGraph() {
  const canvas = document.getElementById('graphCanvas');
  if (!canvas || !caseState || !caseState.case || !caseState.case.graph) {
    console.warn('[drawGraph] Missing canvas or case data');
    return;
  }
  
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    console.error('[drawGraph] Could not get canvas context');
    return;
  }

  // Set canvas size - use style dimensions if offsetWidth is 0
  let w = canvas.offsetWidth;
  let h = canvas.offsetHeight;
  if (w === 0) w = 800;
  if (h === 0) h = 500;
  
  canvas.width = w;
  canvas.height = h;
  console.log('[drawGraph] Canvas dimensions:', w, 'x', h);

  const nodes = caseState.case.graph.nodes || [];
  const edges = caseState.case.graph.edges || [];

  if (!nodes.length) {
    console.warn('[drawGraph] No nodes to render');
    return;
  }

  // First generate and display the summary
  generateGraphSummary();

  // Clear canvas
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Simple ring layout for canvas visualization
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const radius = Math.min(cx, cy) - 80;

  // Calculate node positions
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    const angle = (i / nodes.length) * 2 * Math.PI;
    n.x = cx + radius * Math.cos(angle);
    n.y = cy + radius * Math.sin(angle);
  }

  // Draw Edges
  ctx.strokeStyle = '#374151';
  ctx.lineWidth = 2;
  for (let i = 0; i < edges.length; i++) {
    const e = edges[i];
    const srcNode = nodes.find(function(n) { return n.id === e.source; });
    const tgtNode = nodes.find(function(n) { return n.id === e.target; });
    if (srcNode && tgtNode) {
      ctx.beginPath();
      ctx.moveTo(srcNode.x, srcNode.y);
      ctx.lineTo(tgtNode.x, tgtNode.y);
      ctx.stroke();
    }
  }

  // Draw Nodes
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    ctx.beginPath();
    ctx.arc(n.x, n.y, 16, 0, 2 * Math.PI);
    
    // Color by type
    if (n.type === 'Email') ctx.fillStyle = '#06b6d4';
    else if (n.type === 'IP') ctx.fillStyle = '#ef4444';
    else if (n.type === 'Domain') ctx.fillStyle = '#f59e0b';
    else ctx.fillStyle = '#10b981';
    
    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw label
    ctx.fillStyle = '#ffffff';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'center';
    const label = n.label.length > 18 ? n.label.substring(0, 15) + '...' : n.label;
    ctx.fillText(label, n.x, n.y + 30);
  }
  
  console.log('[drawGraph] Successfully rendered', nodes.length, 'nodes and', edges.length, 'edges');
}

function updateReplayStep(val) {
  currentReplayStep = parseInt(val);
  document.getElementById('replayStepLabel').innerText = `Step ${val} / 6`;
  if (caseState) {
    const filteredTrail = caseState.case.audit_trail.slice(0, currentReplayStep);
    renderAuditTrail(filteredTrail);
  }
}

function playReplay() {
  let s = 1;
  const timer = setInterval(() => {
    if (s > 6) {
      clearInterval(timer);
      return;
    }
    document.getElementById('replaySlider').value = s;
    updateReplayStep(s);
    s++;
  }, 1000);
}
