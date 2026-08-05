"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const OUTCOMES = {
  "": "— не отмечен —",
  alive: "живёт",
  verification: "верификация",
  banned: "бан",
};

let currentScanId = null;
let pollTimer = null;

// ------------------------------------------------------------------- api

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (res.status === 401) {
    showLogin();
    throw new Error("unauthorized");
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch (_) { /* keep the status line */ }
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

// ----------------------------------------------------------------- login

function showLogin() {
  $("login").classList.remove("hidden");
  $("app").classList.add("hidden");
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = $("token-input").value.trim();
  const errorBox = $("login-error");
  errorBox.classList.add("hidden");
  try {
    const res = await fetch("/api/session", {
      method: "POST",
      headers: { "X-Auth-Token": token },
      credentials: "same-origin",
    });
    if (!res.ok) throw new Error("Неверный токен");
    $("login").classList.add("hidden");
    $("app").classList.remove("hidden");
    boot();
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
  }
});

// ------------------------------------------------------------------ tabs

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const target = tab.dataset.view;
    ["scan", "history", "calibration"].forEach((view) => {
      $(`view-${view}`).classList.toggle("hidden", view !== target);
    });
    if (target === "history") loadHistory();
    if (target === "calibration") loadCalibration();
  });
});

// ------------------------------------------------------------------ scan

$("scan-btn").addEventListener("click", async () => {
  const raw = $("domains").value.trim();
  const errorBox = $("scan-error");
  errorBox.classList.add("hidden");
  if (!raw) {
    errorBox.textContent = "Введи хотя бы один домен";
    errorBox.classList.remove("hidden");
    return;
  }
  $("scan-btn").disabled = true;
  try {
    const body = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify({
        domains: raw.split("\n"),
        label: $("label").value.trim() || null,
      }),
    });
    currentScanId = body.scan_id;
    if (body.rejected.length) {
      errorBox.textContent =
        "Пропущено: " + body.rejected.map((r) => `${r.input} (${r.reason})`).join("; ");
      errorBox.classList.remove("hidden");
    }
    $("progress-panel").classList.remove("hidden");
    $("results").classList.add("hidden");
    poll();
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
    $("scan-btn").disabled = false;
  }
});

$("cancel-btn").addEventListener("click", async () => {
  if (!currentScanId) return;
  await api(`/api/scans/${currentScanId}/cancel`, { method: "POST" });
});

function poll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    try {
      const data = await api(`/api/scans/${currentScanId}`);
      renderProgress(data.scan);
      renderResults(data);
      if (data.scan.status === "queued" || data.scan.status === "running") {
        poll();
      } else {
        $("scan-btn").disabled = false;
        $("progress-panel").classList.add("hidden");
      }
    } catch (err) {
      $("scan-btn").disabled = false;
      $("progress-detail").textContent = err.message;
    }
  }, 1200);
}

function renderProgress(scan) {
  const pct = scan.domain_count ? (scan.done_count / scan.domain_count) * 100 : 0;
  $("progress-bar").style.width = `${pct}%`;
  if (scan.status === "queued") {
    // "В очереди" without a position is indistinguishable from a hang.
    const pos = scan.queue_position || 1;
    $("progress-label").textContent =
      pos > 1
        ? `В очереди — ${pos}-й (одновременно идёт ${scan.queue_capacity || "?"})`
        : "В очереди — вот-вот стартует";
  } else {
    $("progress-label").textContent = `Сканирую… ${scan.done_count}/${scan.domain_count}`;
  }
  $("progress-detail").textContent = scan.error || "";
}

// --------------------------------------------------------------- results

function renderResults(data) {
  const { scan, results } = data;
  if (!results.length) return;

  $("results").classList.remove("hidden");
  for (const format of ["csv", "json", "md"]) {
    $(`export-${format}`).href = `/api/scans/${scan.id}/export?format=${format}`;
  }

  const list = $("result-list");
  list.innerHTML = "";
  results.forEach((report) => list.appendChild(renderResult(report)));

  const links = scan.footprint || [];
  $("footprint-panel").classList.toggle("hidden", links.length === 0);
  const linkList = $("footprint-list");
  linkList.innerHTML = "";
  links.forEach((link) => {
    const item = el("div", "link-item");
    item.appendChild(el("span", `sev ${link.severity}`, link.severity));
    const body = el("div");
    body.appendChild(el("div", null, link.message));
    body.appendChild(el("div", "link-domains", link.domains.join(", ")));
    item.appendChild(body);
    linkList.appendChild(item);
  });
}

function findingsOf(report) {
  const out = [];
  (report.checks || []).forEach((check) =>
    (check.findings || []).forEach((f) => out.push(f))
  );
  return out.sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  );
}

function renderResult(report) {
  const wrap = el("div", `result ${report.verdict}`);
  const head = el("div", "result-head");

  head.appendChild(el("span", "chev", "›"));
  head.appendChild(el("span", "score", String(report.score)));
  head.appendChild(el("span", `verdict ${report.verdict}`, report.verdict));
  head.appendChild(el("span", "domain", report.domain));

  const scored = findingsOf(report).filter((f) => (f.weight || 0) > 0);
  // A domain that never got scanned has no findings, which is not the same
  // thing as having no problems -- never label it "чисто".
  const errors = (report.checks || [])
    .filter((c) => c.status === "error" && c.error)
    .map((c) => c.error);
  const headline = scored.length
    ? scored[0].message
    : errors.length
    ? errors[0]
    : "чисто";
  head.appendChild(el("span", "top-issue", headline));
  wrap.appendChild(head);

  const body = el("div", "result-body hidden");

  const missing = report.unavailable_checks || [];
  if (missing.length) {
    const total = (report.checks || []).filter(
      (c) => !(c.status === "skipped" && c.skip_kind === "config")
    ).length;
    const pct = total ? Math.round(((total - missing.length) / total) * 100) : 0;
    const note = el(
      "div",
      `confidence ${pct < 75 ? "low" : ""}`,
      `Покрытие ${pct}% — нет данных от: ${missing.join(", ")}` +
        (pct < 75 ? ". Вердикт предварительный." : "")
    );
    body.appendChild(note);
  }

  if (!scored.length) {
    body.appendChild(
      el("div", "muted small", errors.length ? errors.join("; ") : "Значимых находок нет.")
    );
  }
  scored.forEach((finding) => {
    const row = el("div", "finding");
    row.appendChild(el("span", `sev ${finding.severity}`, finding.severity));
    const text = el("div");
    text.appendChild(el("div", null, finding.message));
    text.appendChild(el("div", "code", finding.code));
    row.appendChild(text);
    body.appendChild(row);
  });

  body.appendChild(outcomeControl(report));
  wrap.appendChild(body);

  head.addEventListener("click", () => {
    wrap.classList.toggle("open");
    body.classList.toggle("hidden");
  });
  return wrap;
}

function outcomeControl(report) {
  const row = el("div", "outcome-row");
  row.appendChild(el("span", "small muted", "Что стало с доменом:"));

  const select = el("select");
  Object.entries(OUTCOMES).forEach(([value, label]) => {
    const option = el("option", null, label);
    option.value = value;
    if ((report.outcome || "") === value) option.selected = true;
    select.appendChild(option);
  });

  const saved = el("span", "small muted", "");
  select.addEventListener("change", async () => {
    try {
      await api(`/api/domains/${encodeURIComponent(report.domain)}/outcome`, {
        method: "PUT",
        body: JSON.stringify({ outcome: select.value || "unknown" }),
      });
      saved.textContent = "сохранено";
      setTimeout(() => (saved.textContent = ""), 1500);
    } catch (err) {
      saved.textContent = err.message;
    }
  });

  row.appendChild(select);
  row.appendChild(saved);
  return row;
}

// --------------------------------------------------------------- history

async function loadHistory() {
  const scans = (await api("/api/scans?limit=50")).scans;
  const scanBox = $("scan-list");
  scanBox.innerHTML = "";
  if (!scans.length) {
    scanBox.appendChild(el("div", "empty", "Сканов пока нет"));
  } else {
    scanBox.appendChild(
      buildTable(
        ["Дата", "Метка", "Доменов", "Худший счёт", "Статус", ""],
        scans.map((scan) => [
          new Date(scan.created_at * 1000).toLocaleString(),
          scan.label || "—",
          { text: String(scan.domain_count), cls: "num" },
          { text: scan.worst_score == null ? "—" : String(scan.worst_score), cls: "num" },
          scan.status,
          openButton(scan.id),
        ])
      )
    );
  }

  const data = await api("/api/domains?limit=300");
  const domainBox = $("domain-list");
  domainBox.innerHTML = "";
  if (!data.domains.length) {
    domainBox.appendChild(el("div", "empty", "Доменов пока нет"));
    return;
  }
  domainBox.appendChild(
    buildTable(
      ["Домен", "Счёт", "Вердикт", "Проверен", "Судьба"],
      data.domains.map((row) => [
        row.domain,
        { text: String(row.score), cls: "num" },
        row.verdict,
        new Date(row.created_at * 1000).toLocaleDateString(),
        outcomeSelect(row),
      ])
    )
  );
}

function openButton(scanId) {
  const button = el("button", "ghost small", "Открыть");
  button.addEventListener("click", async () => {
    currentScanId = scanId;
    document.querySelector('.tab[data-view="scan"]').click();
    renderResults(await api(`/api/scans/${scanId}`));
  });
  return button;
}

function outcomeSelect(row) {
  const select = el("select");
  Object.entries(OUTCOMES).forEach(([value, label]) => {
    const option = el("option", null, label);
    option.value = value;
    if ((row.outcome || "") === value) option.selected = true;
    select.appendChild(option);
  });
  select.addEventListener("change", () =>
    api(`/api/domains/${encodeURIComponent(row.domain)}/outcome`, {
      method: "PUT",
      body: JSON.stringify({ outcome: select.value || "unknown" }),
    })
  );
  return select;
}

// ----------------------------------------------------------- calibration

async function loadCalibration() {
  const data = await api("/api/calibration");
  const totals = data.totals || {};
  const alive = totals.alive || 0;
  const flagged = (totals.verification || 0) + (totals.banned || 0);

  $("calibration-summary").textContent =
    `Размечено: ${alive} живых, ${flagged} проблемных.` +
    (alive < 5 || flagged < 5
      ? " Маловато для выводов — отмечай судьбу доменов во вкладке «История»."
      : "");

  const box = $("calibration-list");
  box.innerHTML = "";
  if (!data.codes.length) {
    box.appendChild(el("div", "empty", "Нет размеченных доменов"));
    return;
  }
  const maxLift = Math.max(...data.codes.map((c) => Math.abs(c.lift)), 0.01);
  box.appendChild(
    buildTable(
      ["Код находки", "Важность", "У живых", "У проблемных", "Lift"],
      data.codes.map((code) => {
        const bar = el("span", "lift-bar");
        bar.style.width = `${Math.max(2, (Math.abs(code.lift) / maxLift) * 90)}px`;
        bar.style.background = code.lift >= 0 ? "var(--avoid)" : "var(--clean)";
        const cell = el("span");
        cell.appendChild(bar);
        cell.appendChild(el("span", "small muted", ` ${code.lift > 0 ? "+" : ""}${code.lift}`));
        return [
          { text: code.code, cls: "code" },
          code.severity,
          { text: `${Math.round(code.alive_rate * 100)}%`, cls: "num" },
          { text: `${Math.round(code.flagged_rate * 100)}%`, cls: "num" },
          cell,
        ];
      })
    )
  );
}

// ---------------------------------------------------------------- shared

function buildTable(headers, rows) {
  const table = el("table");
  const thead = el("thead");
  const headRow = el("tr");
  headers.forEach((h) => headRow.appendChild(el("th", null, h)));
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el("tbody");
  rows.forEach((cells) => {
    const tr = el("tr");
    cells.forEach((cell) => {
      const td = el("td");
      if (cell instanceof Node) td.appendChild(cell);
      else if (cell && typeof cell === "object") {
        td.textContent = cell.text;
        if (cell.cls) td.className = cell.cls;
      } else td.textContent = cell ?? "";
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  return table;
}

// ------------------------------------------------------------------ boot

async function boot() {
  try {
    const health = await api("/api/health");
    const keys = health.checks_configured;
    const missing = Object.entries(keys)
      .filter(([, on]) => !on)
      .map(([name]) => name);
    $("api-status").textContent =
      `v${health.version}` + (missing.length ? ` · без ключей: ${missing.join(", ")}` : " · все ключи на месте");
  } catch (_) { /* showLogin already handled it */ }
}

(async function start() {
  try {
    const res = await fetch("/api/health", { credentials: "same-origin" });
    const health = await res.json();
    if (!health.auth_required) {
      $("app").classList.remove("hidden");
      boot();
      return;
    }
    // Auth is on: probe whether the cookie is still valid.
    const probe = await fetch("/api/scans?limit=1", { credentials: "same-origin" });
    if (probe.ok) {
      $("app").classList.remove("hidden");
      boot();
    } else {
      showLogin();
    }
  } catch (_) {
    showLogin();
  }
})();
