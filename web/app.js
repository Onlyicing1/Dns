/* ============================================================
   DNS CONSOLE — front-end logic (vanilla, no build step)
   ============================================================ */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  /* ---------- clock ---------- */
  const clock = $("clock");
  const tick = () => {
    const d = new Date();
    clock.textContent = d.toTimeString().slice(0, 8);
  };
  tick();
  setInterval(tick, 1000);

  /* ---------- connection state ---------- */
  const dot = $("conn-dot");
  const connText = $("conn-text");
  fetch("/api/health")
    .then((r) => r.json())
    .then(() => { dot.classList.add("live"); connText.textContent = "online"; })
    .catch(() => { connText.textContent = "offline"; });
  $("footer-port").textContent = location.host;

  /* ---------- helpers ---------- */
  const fmt = (v, unit = "ms", digits = 1) =>
    v == null ? "—" : `${Number(v).toFixed(digits)}${unit}`;

  function statusPill(status) {
    const s = el("span", "pill " + status);
    s.textContent = status === "ok" ? "ok" : status === "warn" ? "spike" : "fail";
    return s;
  }

  /* ---------- scanner ---------- */
  const targetsBox = $("targets");
  const runBtn = $("run");
  const progressBar = $("progress-bar");
  const progressText = $("progress-text");
  const resultsBody = $("results-body");
  let currentES = null;

  const parseTargets = () =>
    targetsBox.value
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

  function resetMetrics() {
    $("m-best").textContent = "—";
    $("m-avg").textContent = "—";
    $("m-loss").textContent = "—";
    $("m-resp").textContent = "—";
  }

  function runScan() {
    const targets = parseTargets();
    if (!targets.length) {
      progressText.textContent = "add a target first";
      return;
    }
    const count = Math.max(1, Math.min(10, parseInt($("count").value, 10) || 3));

    if (currentES) currentES.close();
    resultsBody.innerHTML = "";
    resetMetrics();
    runBtn.disabled = true;
    runBtn.querySelector(".run-label").textContent = "SCANNING…";

    const rows = [];
    const url = `/api/scan?targets=${encodeURIComponent(targets.join(","))}&count=${count}`;
    const es = new EventSource(url);
    currentES = es;

    es.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }

      if (msg.type === "start") {
        progressText.textContent = `0 / ${msg.targets.length}`;
        progressBar.style.width = "0%";
      } else if (msg.type === "result") {
        rows.push(msg);
        renderResults(rows);
      } else if (msg.type === "progress") {
        const pct = (msg.done / msg.total) * 100;
        progressBar.style.width = pct + "%";
        progressText.textContent = `${msg.done} / ${msg.total}`;
      } else if (msg.type === "summary") {
        renderStability(msg.rows);
      } else if (msg.type === "done") {
        progressText.textContent =
          `done — ${msg.summary.ok} ok / ${msg.summary.failed} failed`;
        finish();
      } else if (msg.type === "error") {
        progressText.textContent = "error: " + msg.message;
        finish();
      }
    };
    es.onerror = () => {
      if (runBtn.disabled) progressText.textContent = "stream closed";
      finish();
    };

    function finish() {
      if (currentES) { currentES.close(); currentES = null; }
      runBtn.disabled = false;
      runBtn.querySelector(".run-label").textContent = "RUN SCAN";
      updateMetrics(rows);
    }
  }

  function renderResults(rows) {
    const maxLat = Math.max(...rows.filter((r) => r.latency != null).map((r) => r.latency), 1);
    resultsBody.innerHTML = "";
    rows.forEach((r, i) => {
      const tr = el("tr", r.status === "ok" ? "row-ok" : "row-fail");
      tr.appendChild(el("td", null, String(i + 1)));
      tr.appendChild(el("td", null, r.target));

      const latCell = el("td");
      if (r.latency != null) {
        const wrap = el("div", "bar-cell");
        const bar = el("span", "mini-bar");
        bar.style.width = Math.max(2, (r.latency / maxLat) * 70) + "px";
        wrap.appendChild(bar);
        wrap.appendChild(el("span", null, fmt(r.latency)));
        latCell.appendChild(wrap);
      } else latCell.textContent = "—";
      tr.appendChild(latCell);

      tr.appendChild(el("td", null, fmt(r.jitter)));
      tr.appendChild(el("td", null, fmt(r.loss, "%", 0)));
      const st = el("td");
      st.appendChild(statusPill(r.status));
      tr.appendChild(st);
      resultsBody.appendChild(tr);
    });
  }

  function updateMetrics(rows) {
    const ok = rows.filter((r) => r.status === "ok" && r.latency != null);
    if (!ok.length) return;
    const best = ok.reduce((a, b) => (a.latency < b.latency ? a : b));
    const avg = ok.reduce((s, r) => s + r.latency, 0) / ok.length;
    const loss = rows.reduce((s, r) => s + (r.loss || 0), 0) / rows.length;
    $("m-best").textContent = fmt(best.latency);
    $("m-avg").textContent = fmt(avg);
    $("m-loss").textContent = fmt(loss, "%", 0);
    $("m-resp").textContent = `${ok.length}/${rows.length}`;
  }

  runBtn.addEventListener("click", runScan);
  targetsBox.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runScan();
  });
  $("clear-targets").addEventListener("click", () => { targetsBox.value = ""; targetsBox.focus(); });
  $("use-list").addEventListener("click", async () => {
    const r = await fetch("/api/dns-list").then((x) => x.json());
    if (r.list && r.list.length) {
      targetsBox.value = r.list.join("\n");
      progressText.textContent = `loaded ${r.list.length} from saved list`;
    } else {
      progressText.textContent = "saved list is empty";
    }
  });

  /* ---------- stability ---------- */
  function renderStability(rows) {
    const box = $("stab-list");
    box.innerHTML = "";
    if (!rows || !rows.length) {
      box.appendChild(el("div", "empty-note", "Run a scan to build history."));
      return;
    }
    rows.forEach((r) => {
      const item = el("div", "stab-item");
      const left = el("div");
      left.appendChild(el("div", "ip", r.target));
      left.appendChild(el("div", "meta",
        `${r.success_rate}% success · ${r.cycles} cycles · ${r.spikes} spikes`));
      const score = el("div", "stab-score", r.score);
      const track = el("div", "stab-track");
      const fill = el("div", "stab-fill");
      fill.style.width = r.score + "%";
      track.appendChild(fill);
      item.append(left, score, track);
      box.appendChild(item);
    });
  }

  async function loadStability() {
    const r = await fetch("/api/stability").then((x) => x.json());
    renderStability(r.rows);
  }
  $("refresh-stab").addEventListener("click", loadStability);
  loadStability();

  /* ---------- dns list ---------- */
  const dnsList = $("dns-list");

  function renderDnsList(list) {
    dnsList.innerHTML = "";
    if (!list || !list.length) {
      const li = el("li", null, "no saved servers yet");
      li.style.color = "var(--dim-2)";
      li.style.fontStyle = "italic";
      dnsList.appendChild(li);
      return;
    }
    list.forEach((addr) => {
      const li = el("li");
      li.appendChild(el("span", null, addr));
      const del = el("button", "del", "remove");
      del.addEventListener("click", () => mutateList({ delete: addr }));
      li.appendChild(del);
      dnsList.appendChild(li);
    });
  }

  async function mutateList(payload) {
    const r = await fetch("/api/dns-list", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then((x) => x.json());
    renderDnsList(r.list);
  }

  async function loadDnsList() {
    const r = await fetch("/api/dns-list").then((x) => x.json());
    renderDnsList(r.list);
  }
  $("add-dns").addEventListener("click", () => {
    const v = $("new-dns").value.trim();
    if (v) { mutateList({ add: v }); $("new-dns").value = ""; }
  });
  $("new-dns").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("add-dns").click();
  });
  loadDnsList();

  /* ---------- probe tools ---------- */
  const toolOut = $("tool-out");
  const toolHost = $("tool-host");

  function renderTool(html) { toolOut.innerHTML = html; }
  const kv = (k, v) => `<span class="k">${k}</span> <span class="v">${v}</span>`;

  const tools = {
    resolve: async (host) => {
      const r = await post("/api/tools/resolve", { host, dns: "8.8.8.8" });
      return r.ip
        ? kv("resolved", `${r.host} → ${r.ip}`) + "\n" + kv("query time", `${r.ms} ms`)
        : `<span class="err">could not resolve ${host}</span>`;
    },
    tcp: async (host) => {
      const r = await post("/api/tools/tcp", { host, port: 443 });
      return r.ok ? kv("tcp 443", `${r.ms} ms (open)`)
                  : `<span class="err">tcp 443 closed / unreachable</span>`;
    },
    tls: async (host) => {
      const r = await post("/api/tools/tls", { host, port: 443 });
      return r.ok ? kv("tls handshake", `${r.ms} ms`)
                  : `<span class="err">tls handshake failed</span>`;
    },
    http: async (host) => {
      const r = await post("/api/tools/http", { url: host });
      return r.ok ? kv("http", `${r.status} · ${r.ms} ms · ${r.bytes} bytes`)
                  : `<span class="err">http request failed</span>`;
    },
  };

  async function post(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((x) => x.json());
  }

  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", async () => {
      const host = toolHost.value.trim();
      if (!host) { renderTool(`<span class="err">enter a host first</span>`); return; }
      document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      renderTool("probing…");
      try {
        renderTool(await tools[chip.dataset.tool](host));
      } catch (e) {
        renderTool(`<span class="err">error: ${e}</span>`);
      }
    });
  });

  /* ---------- keyboard: Enter in targets triggers scan on desktop ---------- */
  targetsBox.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      runScan();
    }
  });

  targetsBox.value = "8.8.8.8, 1.1.1.1, 9.9.9.9, 8.8.4.4";
})();
