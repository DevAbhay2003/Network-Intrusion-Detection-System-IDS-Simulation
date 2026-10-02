/**
 * SOC Dashboard Chart Visualizations using Chart.js
 * Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
 */

let chartTraffic = null;
let chartNormalSuspicious = null;
let chartSeverity = null;
let chartAlertTypes = null;
let chartProtocols = null;
let chartPorts = null;
let chartTopSources = null;
let chartRiskDistribution = null;

// Global Chart.js styling defaults for dark SOC theme
Chart.defaults.color = "#94a3b8";
Chart.defaults.borderColor = "#1e293b";
Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";

function initCharts() {
  // 1. Traffic Over Time (Packets & Bytes)
  const ctxTraffic = document.getElementById("chartTraffic")?.getContext("2d");
  if (ctxTraffic) {
    chartTraffic = new Chart(ctxTraffic, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Packets",
            data: [],
            borderColor: "#06b6d4",
            backgroundColor: "rgba(6, 182, 212, 0.1)",
            tension: 0.3,
            fill: true,
            yAxisID: "yPackets",
          },
          {
            label: "Bytes (KB)",
            data: [],
            borderColor: "#8b5cf6",
            backgroundColor: "transparent",
            borderDash: [4, 4],
            tension: 0.3,
            yAxisID: "yBytes",
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "top" } },
        scales: {
          x: { grid: { display: false } },
          yPackets: { position: "left", title: { display: true, text: "Packets" } },
          yBytes: { position: "right", title: { display: true, text: "KB" }, grid: { display: false } }
        }
      }
    });
  }

  // 2. Normal vs Suspicious (Doughnut)
  const ctxNormalSusp = document.getElementById("chartNormalSuspicious")?.getContext("2d");
  if (ctxNormalSusp) {
    chartNormalSuspicious = new Chart(ctxNormalSusp, {
      type: "doughnut",
      data: {
        labels: ["Normal", "Suspicious"],
        datasets: [{
          data: [0, 0],
          backgroundColor: ["#10b981", "#ef4444"],
          borderColor: "#111827",
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } },
        cutout: "70%"
      }
    });
  }

  // 3. Alerts by Severity (Bar)
  const ctxSev = document.getElementById("chartSeverity")?.getContext("2d");
  if (ctxSev) {
    chartSeverity = new Chart(ctxSev, {
      type: "bar",
      data: {
        labels: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        datasets: [{
          label: "Alerts",
          data: [0, 0, 0, 0, 0],
          backgroundColor: ["#38bdf8", "#34d399", "#fbbf24", "#f97316", "#ef4444"],
          borderRadius: 6,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } }
      }
    });
  }

  // 4. Top Alert Types (Horizontal Bar)
  const ctxTypes = document.getElementById("chartAlertTypes")?.getContext("2d");
  if (ctxTypes) {
    chartAlertTypes = new Chart(ctxTypes, {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          label: "Count",
          data: [],
          backgroundColor: "#0284c7",
          borderRadius: 4,
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true } }
      }
    });
  }

  // 5. Protocol Distribution (Pie)
  const ctxProto = document.getElementById("chartProtocols")?.getContext("2d");
  if (ctxProto) {
    chartProtocols = new Chart(ctxProto, {
      type: "pie",
      data: {
        labels: ["TCP", "UDP", "ICMP"],
        datasets: [{
          data: [0, 0, 0],
          backgroundColor: ["#0284c7", "#10b981", "#f59e0b"],
          borderColor: "#111827",
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "bottom" } }
      }
    });
  }

  // 6. Destination Port Distribution (Bar)
  const ctxPorts = document.getElementById("chartPorts")?.getContext("2d");
  if (ctxPorts) {
    chartPorts = new Chart(ctxPorts, {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          label: "Flows",
          data: [],
          backgroundColor: "#8b5cf6",
          borderRadius: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } }
      }
    });
  }

  // 7. Top Source IPs (Bar)
  const ctxSources = document.getElementById("chartTopSources")?.getContext("2d");
  if (ctxSources) {
    chartTopSources = new Chart(ctxSources, {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          label: "Alerts",
          data: [],
          backgroundColor: "#f43f5e",
          borderRadius: 4,
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true } }
      }
    });
  }

  // 8. Risk Score Distribution (Bar)
  const ctxRisk = document.getElementById("chartRiskDistribution")?.getContext("2d");
  if (ctxRisk) {
    chartRiskDistribution = new Chart(ctxRisk, {
      type: "bar",
      data: {
        labels: ["NORMAL (0-20)", "LOW (21-40)", "SUSPICIOUS (41-60)", "HIGH (61-80)", "CRITICAL (81-100)"],
        datasets: [{
          label: "Flow Count",
          data: [0, 0, 0, 0, 0],
          backgroundColor: ["#10b981", "#34d399", "#fbbf24", "#f97316", "#ef4444"],
          borderRadius: 6,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } }
      }
    });
  }
}

// Update Functions
function updateTrafficChart(trafficData) {
  if (!chartTraffic) return;
  chartTraffic.data.labels = trafficData.labels || [];
  chartTraffic.data.datasets[0].data = trafficData.packets || [];
  chartTraffic.data.datasets[1].data = (trafficData.bytes || []).map(b => Math.round(b / 1024));
  chartTraffic.update("none");
}

function updateNormalSuspiciousChart(normalCount, suspiciousCount) {
  if (!chartNormalSuspicious) return;
  chartNormalSuspicious.data.datasets[0].data = [normalCount, suspiciousCount];
  chartNormalSuspicious.update("none");
}

function updateAlertsBreakdownChart(breakdown) {
  if (!chartSeverity || !chartAlertTypes) return;
  const sev = breakdown.by_severity || {};
  chartSeverity.data.datasets[0].data = [
    sev["INFO"] || 0,
    sev["LOW"] || 0,
    sev["MEDIUM"] || 0,
    sev["HIGH"] || 0,
    sev["CRITICAL"] || 0
  ];
  chartSeverity.update("none");

  const types = breakdown.by_type || {};
  chartAlertTypes.data.labels = Object.keys(types);
  chartAlertTypes.data.datasets[0].data = Object.values(types);
  chartAlertTypes.update("none");
}

function updateProtocolChart(protoDict) {
  if (!chartProtocols) return;
  chartProtocols.data.labels = Object.keys(protoDict);
  chartProtocols.data.datasets[0].data = Object.values(protoDict);
  chartProtocols.update("none");
}

function updatePortChart(portDict) {
  if (!chartPorts) return;
  chartPorts.data.labels = Object.keys(portDict);
  chartPorts.data.datasets[0].data = Object.values(portDict);
  chartPorts.update("none");
}

function updateTopSourcesChart(sourcesList) {
  if (!chartTopSources) return;
  chartTopSources.data.labels = sourcesList.map(s => s.source_ip);
  chartTopSources.data.datasets[0].data = sourcesList.map(s => s.alert_count);
  chartTopSources.update("none");
}

function updateRiskDistributionChart(riskTiers) {
  if (!chartRiskDistribution) return;
  chartRiskDistribution.data.datasets[0].data = Object.values(riskTiers);
  chartRiskDistribution.update("none");
}
