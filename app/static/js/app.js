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

// Modal Helpers
function openModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) {
    el.classList.add("active");
  } else {
    console.warn("Modal not found in DOM:", modalId);
  }
}

function closeModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) {
    el.classList.remove("active");
  }
}

// Global "New Zone" launcher that works across all pages
function triggerNewZone() {
  const modal = document.getElementById("createZoneModal");
  if (modal) {
    if (typeof openCreateZoneModal === "function") {
      openCreateZoneModal();
    } else {
      openModal("createZoneModal");
    }
  } else {
    window.location.href = "/?open_create=true";
  }
}

// Global dismiss listeners for modal backdrops & Escape key
document.addEventListener("click", (e) => {
  if (e.target && e.target.classList && e.target.classList.contains("modal-backdrop")) {
    e.target.classList.remove("active");
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document.querySelectorAll(".modal-backdrop.active").forEach(m => m.classList.remove("active"));
  }
});

// Quick Record Filter
function filterRecords(query) {
  const q = query.toLowerCase().trim();
  const rows = document.querySelectorAll(".record-row");
  rows.forEach(row => {
    const text = row.innerText.toLowerCase();
    row.style.display = text.includes(q) ? "" : "none";
  });
}

// Table Filter for Zones
function filterZonesTable(query) {
  const q = query.toLowerCase().trim();
  const rows = document.querySelectorAll(".zone-row");
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

// Global BIND validation test from topbar
async function runCheckconfGlobal(btn) {
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerText = "Checking...";
  try {
    const res = await fetch("/api/v1/system/checkconf", { method: "POST" });
    const data = await res.json();
    if (res.ok && data.valid) {
      showToast("BIND 9 Configuration Valid: named-checkconf OK");
    } else {
      showToast(`Syntax Error: ${data.message || data.detail}`, true);
    }
  } catch (err) {
    showToast(`Validation Error: ${err}`, true);
  } finally {
    btn.disabled = false;
    btn.innerHTML = orig;
  }
}
