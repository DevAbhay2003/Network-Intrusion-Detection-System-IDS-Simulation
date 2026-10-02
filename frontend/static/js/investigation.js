/**
 * SOC Analyst Event Investigation & Incident Workflow Module
 * Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
 */

let activeAlertId = null;

async function openInvestigation(alertId) {
  activeAlertId = alertId;
  const modal = document.getElementById("investigationModal");
  if (!modal) return;

  modal.style.display = "flex";
  document.getElementById("modalAlertId").innerText = `Investigating ${alertId}`;

  try {
    const res = await fetch(`/api/alerts/${alertId}`);
    if (!res.ok) throw new Error("Failed to load alert details");
    const data = await res.json();

    // Populate Alert Overview
    document.getElementById("invAlertId").innerText = data.alert_id;
    document.getElementById("invTimestamp").innerText = data.created_at.replace("T", " ").substring(0, 19);
    document.getElementById("invSource").innerText = `${data.source_ip}:${data.source_port}`;
    document.getElementById("invDestination").innerText = `${data.destination_ip}:${data.destination_port}`;
    document.getElementById("invProtocol").innerText = data.protocol;
    document.getElementById("invType").innerText = data.alert_type;

    // Severity & Risk Badge
    const sevBadge = document.getElementById("invSeverity");
    sevBadge.className = `badge badge-${data.severity.toLowerCase()}`;
    sevBadge.innerText = data.severity;

    document.getElementById("invRiskScore").innerText = `${data.risk_score} / 100`;
    document.getElementById("invRule").innerText = data.rule_id;
    document.getElementById("invDescription").innerText = data.description;

    // Flow Statistics
    const fd = data.flow_details || {};
    document.getElementById("invPackets").innerText = fd.packet_count ?? "-";
    document.getElementById("invBytes").innerText = fd.byte_count ? `${(fd.byte_count / 1024).toFixed(1)} KB` : "-";
    document.getElementById("invDuration").innerText = fd.duration ? `${fd.duration}s` : "-";
    document.getElementById("invScenario").innerText = fd.scenario_type ?? "-";

    // Set Status Dropdown
    const statusSelect = document.getElementById("invStatusSelect");
    if (statusSelect) {
      statusSelect.value = data.status;
    }

    // Populate SOP Recommendations
    const sopList = document.getElementById("invSopList");
    sopList.innerHTML = "";
    (data.investigation_steps || []).forEach(step => {
      const li = document.createElement("li");
      li.innerText = step;
      sopList.appendChild(li);
    });

    // Populate Analyst Notes
    renderNotesList(data.notes || []);

  } catch (err) {
    console.error("Error loading alert dossier:", err);
    alert("Could not load alert investigation data.");
  }
}

function closeInvestigation() {
  const modal = document.getElementById("investigationModal");
  if (modal) modal.style.display = "none";
  activeAlertId = null;
}

function renderNotesList(notes) {
  const container = document.getElementById("invNotesContainer");
  if (!container) return;

  if (notes.length === 0) {
    container.innerHTML = `<p style="font-size: 0.8rem; color: #94a3b8; font-style: italic;">No investigation notes recorded yet.</p>`;
    return;
  }

  container.innerHTML = notes.map(n => `
    <div class="note-entry">
      <div class="note-meta">${n.analyst_name} • ${n.created_at.replace("T", " ").substring(0, 19)}</div>
      <div class="note-text">${escapeHtml(n.note)}</div>
    </div>
  `).join("");
}

async function updateAlertStatusFromModal() {
  if (!activeAlertId) return;
  const select = document.getElementById("invStatusSelect");
  const newStatus = select.value;

  try {
    const res = await fetch(`/api/alerts/${activeAlertId}/status`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    });

    if (res.ok) {
      showToast(`Alert status updated to ${newStatus}`);
      if (typeof refreshDashboardData === "function") {
        refreshDashboardData();
      }
    } else {
      alert("Failed to update status.");
    }
  } catch (err) {
    console.error("Status update error:", err);
  }
}

async function submitAnalystNote() {
  if (!activeAlertId) return;
  const noteInput = document.getElementById("invNewNote");
  const text = noteInput.value.trim();
  if (!text) return;

  try {
    const res = await fetch(`/api/alerts/${activeAlertId}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note: text, analyst_name: "SOC Analyst Tier 1" }),
    });

    if (res.ok) {
      noteInput.value = "";
      showToast("Analyst note appended to case timeline.");
      // Reload notes
      openInvestigation(activeAlertId);
    } else {
      alert("Failed to submit note.");
    }
  } catch (err) {
    console.error("Note submit error:", err);
  }
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function showToast(msg) {
  const toast = document.getElementById("socToast");
  if (!toast) return;
  toast.innerText = msg;
  toast.style.display = "block";
  setTimeout(() => { toast.style.display = "none"; }, 3000);
}

// Close on backdrop click
window.addEventListener("click", (e) => {
  const modal = document.getElementById("investigationModal");
  if (e.target === modal) {
    closeInvestigation();
  }
});

// Close on ESC key
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeInvestigation();
  }
});
