// DNS-WUI Client Scripts

function showToast(message, isError = false) {
  let toast = document.getElementById("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    toast.className = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.style.borderColor = isError ? "var(--danger)" : "var(--accent)";
  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 3500);
}

// Initialize View Mode on Load (Defaults to Table)
document.addEventListener("DOMContentLoaded", () => {
  const savedMode = localStorage.getItem("dns_view_mode") || "table";
  setViewMode(savedMode);
});

// View Mode Toggle (Cards vs Compact Table)
function setViewMode(mode) {
  localStorage.setItem("dns_view_mode", mode);
  const cardsContainer = document.getElementById("viewCards");
  const tableContainer = document.getElementById("viewTable");
  const btnCards = document.getElementById("btnViewCards");
  const btnTable = document.getElementById("btnViewTable");

  if (mode === "table") {
    if (cardsContainer) cardsContainer.style.display = "none";
    if (tableContainer) tableContainer.style.display = "block";
    if (btnCards) btnCards.classList.remove("btn-primary");
    if (btnCards) btnCards.classList.add("btn-secondary");
    if (btnTable) btnTable.classList.remove("btn-secondary");
    if (btnTable) btnTable.classList.add("btn-primary");
  } else {
    if (cardsContainer) cardsContainer.style.display = "grid";
    if (tableContainer) tableContainer.style.display = "none";
    if (btnCards) btnCards.classList.remove("btn-secondary");
    if (btnCards) btnCards.classList.add("btn-primary");
    if (btnTable) btnTable.classList.remove("btn-primary");
    if (btnTable) btnTable.classList.add("btn-secondary");
  }
}

// Modal Helpers
function openModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.add("active");
}

function closeModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.remove("active");
}

// Quick Record Filter
function filterRecords(query) {
  const q = query.toLowerCase().trim();
  const rows = document.querySelectorAll(".record-row");
  rows.forEach(row => {
    const text = row.innerText.toLowerCase();
    row.style.display = text.includes(q) ? "" : "none";
  });
}

// Record Type change handler for auto PTR suggestion
function onRecordTypeChange(typeSelectId, ptrCheckContainerId) {
  const select = document.getElementById(typeSelectId);
  const container = document.getElementById(ptrCheckContainerId);
  if (select && container) {
    const val = select.value.toUpperCase();
    if (val === "A" || val === "AAAA") {
      container.style.display = "flex";
      const check = container.querySelector("input[type='checkbox']");
      if (check) check.checked = true;
    } else {
      container.style.display = "none";
      const check = container.querySelector("input[type='checkbox']");
      if (check) check.checked = false;
    }
  }
}

// Reload Zone Action
async function reloadZone(zoneName, btn) {
  const orig = btn.innerText;
  btn.disabled = true;
  btn.innerText = "Reloading...";
  try {
    const res = await fetch(`/api/v1/zones/${encodeURIComponent(zoneName)}/reload`, { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      showToast(`Reloaded: ${data.message}`);
    } else {
      showToast(`Error: ${data.detail}`, true);
    }
  } catch (err) {
    showToast(`Failed: ${err}`, true);
  } finally {
    btn.disabled = false;
    btn.innerText = orig;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const savedMode = localStorage.getItem("dns_view_mode") || "cards";
  setViewMode(savedMode);
});
