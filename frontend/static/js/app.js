/**
 * Primary SOC Dashboard Application Logic
 * Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
 */

let pollingInterval = null;
let isPollingActive = true;

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  initTabs();
  initFilters();
  refreshDashboardData();

  // Auto-polling every 2.5 seconds
  pollingInterval = setInterval(() => {
    if (isPollingActive) {
      refreshDashboardData();
    }
  }, 2500);

  // Poll simulator status
  checkSimulatorStatus();
});

function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.style.display = "none");

      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.target);
      if (target) target.style.display = "block";

      if (btn.dataset.target === "tab-rules") {
        loadRulesTable();
      }
    });
  });
}

function initFilters() {
  document.getElementById("filterSeverity")?.addEventListener("change", loadAlertsTable);
  document.getElementById("filterStatus")?.addEventListener("change", loadAlertsTable);
  document.getElementById("filterSearch")?.addEventListener("input", debounce(loadAlertsTable, 300));
}

function debounce(func, delay) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), delay);
  };
}

async function refreshDashboardData() {
  try {
    await Promise.all([
      loadStats(),
      loadTrafficChartData(),
      loadAlertsBreakdown(),
      loadDistributions(),
      loadAlertsTable(),
      loadRecentFlows(),
      checkSimulatorStatus()
    ]);
  } catch (err) {
    console.error("Dashboard refresh error:", err);
  }
}

async function loadStats() {
  const res = await fetch("/api/dashboard/stats");
  if (!res.ok) return;
  const s = await res.json();

  document.getElementById("statTotalFlows").innerText = s.total_flows.toLocaleString();
  document.getElementById("statNormalFlows").innerText = s.normal_flows.toLocaleString();
  document.getElementById("statSuspiciousFlows").innerText = s.suspicious_flows.toLocaleString();
  document.getElementById("statOpenAlerts").innerText = s.open_alerts.toLocaleString();
  document.getElementById("statCriticalAlerts").innerText = s.critical_alerts.toLocaleString();
  document.getElementById("statAvgRisk").innerText = `${s.average_risk_score} / 100`;

  updateNormalSuspiciousChart(s.normal_flows, s.suspicious_flows);
}

async function loadTrafficChartData() {
  const res = await fetch("/api/dashboard/traffic?limit=25");
  if (!res.ok) return;
  const data = await res.json();
  updateTrafficChart(data);
}

async function loadAlertsBreakdown() {
  const res = await fetch("/api/dashboard/alerts-breakdown");
  if (!res.ok) return;
  const data = await res.json();
  updateAlertsBreakdownChart(data);
}

async function loadDistributions() {
  const [protoRes, portRes, srcRes, riskRes] = await Promise.all([
    fetch("/api/dashboard/protocols"),
    fetch("/api/dashboard/ports"),
    fetch("/api/dashboard/top-sources"),
    fetch("/api/dashboard/risk-distribution")
  ]);

  if (protoRes.ok) updateProtocolChart(await protoRes.json());
  if (portRes.ok) updatePortChart(await portRes.json());
  if (srcRes.ok) updateTopSourcesChart(await srcRes.json());
  if (riskRes.ok) updateRiskDistributionChart(await riskRes.json());
}

async function loadAlertsTable() {
  const sev = document.getElementById("filterSeverity")?.value || "";
  const status = document.getElementById("filterStatus")?.value || "";
  const search = document.getElementById("filterSearch")?.value || "";

  let url = `/api/alerts?limit=15`;
  if (sev) url += `&severity=${sev}`;
  if (status) url += `&status=${status}`;
  if (search) url += `&search=${encodeURIComponent(search)}`;

  const res = await fetch(url);
  if (!res.ok) return;
  const alerts = await res.json();

  const tbody = document.getElementById("alertsTableBody");
  if (!tbody) return;

  if (alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #94a3b8; padding: 1.5rem;">No security alerts matching criteria.</td></tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td><code>${a.alert_id}</code></td>
      <td>${a.created_at.replace("T", " ").substring(0, 19)}</td>
      <td><strong>${a.source_ip}</strong>:${a.source_port}</td>
      <td>${a.destination_ip}:${a.destination_port}</td>
      <td><span style="font-weight: 600; color: #38bdf8;">${a.protocol}</span></td>
      <td>${a.alert_type}</td>
      <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
      <td><strong>${a.risk_score}</strong></td>
      <td><span class="badge badge-status">${a.status}</span></td>
      <td>
        <button class="btn btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" onclick="openInvestigation('${a.alert_id}')">
          Investigate
        </button>
      </td>
    </tr>
  `).join("");
}

async function loadRecentFlows() {
  const res = await fetch("/api/flows?limit=12");
  if (!res.ok) return;
  const flows = await res.json();

  const tbody = document.getElementById("flowsTableBody");
  if (!tbody) return;

  tbody.innerHTML = flows.map(f => {
    const isSusp = f.classification !== "NORMAL";
    return `
      <tr>
        <td><code>${f.flow_id}</code></td>
        <td>${f.timestamp.replace("T", " ").substring(0, 19)}</td>
        <td>${f.source_ip}:${f.source_port}</td>
        <td>${f.destination_ip}:${f.destination_port}</td>
        <td>${f.protocol}</td>
        <td>${f.packet_count}</td>
        <td>${(f.byte_count / 1024).toFixed(1)} KB</td>
        <td><span style="color: ${isSusp ? '#ef4444' : '#10b981'}; font-weight: 600;">${f.classification}</span></td>
        <td><strong>${f.risk_score}</strong></td>
      </tr>
    `;
  }).join("");
}

async function loadRulesTable() {
  const res = await fetch("/api/rules");
  if (!res.ok) return;
  const rules = await res.json();

  const tbody = document.getElementById("rulesTableBody");
  if (!tbody) return;

  tbody.innerHTML = rules.map(r => `
    <tr>
      <td><code>${r.rule_id}</code></td>
      <td><strong>${r.rule_name}</strong></td>
      <td><span class="badge badge-${r.severity.toLowerCase()}">${r.severity}</span></td>
      <td style="font-size: 0.8rem; color: #94a3b8;">${r.description}</td>
      <td><code>${JSON.stringify(r.threshold)}</code></td>
      <td>
        <button class="btn ${r.enabled ? 'btn-danger' : 'btn-primary'}" style="padding: 0.2rem 0.6rem; font-size: 0.75rem;" onclick="toggleRule('${r.rule_id}', ${!r.enabled})">
          ${r.enabled ? 'Disable' : 'Enable'}
        </button>
      </td>
    </tr>
  `).join("");
}

async function toggleRule(ruleId, newStatus) {
  try {
    const res = await fetch(`/api/rules/${ruleId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: newStatus })
    });
    if (res.ok) {
      loadRulesTable();
      showToast(`Rule ${ruleId} ${newStatus ? 'enabled' : 'disabled'}.`);
    }
  } catch (err) {
    console.error("Rule toggle error:", err);
  }
}

// Simulation Controls
async function checkSimulatorStatus() {
  const res = await fetch("/api/simulation/status");
  if (!res.ok) return;
  const s = await res.json();

  const statusBadge = document.getElementById("simStatusBadge");
  const toggleBtn = document.getElementById("simToggleBtn");

  if (s.running) {
    if (statusBadge) {
      statusBadge.innerText = `RUNNING (${s.mode.toUpperCase()}, ${s.speed.toUpperCase()})`;
      statusBadge.style.color = "#10b981";
    }
    if (toggleBtn) {
      toggleBtn.innerText = "Stop Continuous Simulator";
      toggleBtn.className = "btn btn-danger";
      toggleBtn.onclick = stopSimulator;
    }
  } else {
    if (statusBadge) {
      statusBadge.innerText = "IDLE";
      statusBadge.style.color = "#94a3b8";
    }
    if (toggleBtn) {
      toggleBtn.innerText = "Start Continuous Simulator";
      toggleBtn.className = "btn btn-primary";
      toggleBtn.onclick = startSimulator;
    }
  }
}

async function startSimulator() {
  const mode = document.getElementById("simModeSelect")?.value || "mixed";
  const speed = document.getElementById("simSpeedSelect")?.value || "fast";

  const res = await fetch("/api/simulation/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode, speed })
  });

  if (res.ok) {
    showToast("Background simulator started.");
    checkSimulatorStatus();
  }
}

async function stopSimulator() {
  const res = await fetch("/api/simulation/stop", { method: "POST" });
  if (res.ok) {
    showToast("Background simulator paused.");
    checkSimulatorStatus();
  }
}

async function triggerScenario(scenarioType) {
  try {
    const res = await fetch("/api/simulation/trigger-scenario", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario_type: scenarioType })
    });

    if (res.ok) {
      const data = await res.json();
      const r = data.result;
      showToast(`Injected Scenario [${scenarioType}]: Risk ${r.risk_score}/100 (${r.classification})`);
      refreshDashboardData();
    }
  } catch (err) {
    console.error("Scenario trigger error:", err);
  }
}

async function resetDatabase() {
  if (!confirm("Are you sure you want to reset all simulated flows and alerts?")) return;
  try {
    const res = await fetch("/api/flows/reset", { method: "POST" });
    if (res.ok) {
      showToast("Database reset successfully.");
      refreshDashboardData();
    }
  } catch (err) {
    console.error("Reset error:", err);
  }
}
