document.addEventListener("DOMContentLoaded", () => {
  // --- Mock Data ---
  const incidents = [
    {
      id: "INC-2048",
      title: "Possible data exfiltration",
      severity: "Critical",
      source: "10.42.18.94",
      destination: "198.51.100.24",
      asset: "APP-SRV-04",
      zone: "Application",
      time: "10:42 UTC",
      description:
        "An application server initiated an unusual volume of outbound traffic to an external address. The pattern deviates from its normal baseline and warrants validation.",
      evidence: [
        ["Detection rule", "Anomalous outbound transfer"],
        ["Protocol / port", "HTTPS / 443"],
        ["Observed volume", "2.8 GB in 17 minutes"],
        ["Confidence", "High · 92%"],
      ],
      timeline: [
        ["10:42 UTC", "Alert generated", "Outbound transfer exceeded the learned traffic baseline."],
        ["10:31 UTC", "Sustained connection", "A persistent connection to the external destination began."],
        ["10:25 UTC", "First observed activity", "Initial outbound request from APP-SRV-04 was recorded."],
      ],
    },
    {
      id: "INC-2047",
      title: "Brute-force login attempt",
      severity: "High",
      source: "203.0.113.58",
      destination: "10.42.3.12",
      asset: "AUTH-GW-01",
      zone: "Identity",
      time: "10:26 UTC",
      description:
        "A high rate of failed authentication attempts from one external source targeted the identity gateway within a short interval.",
      evidence: [
        ["Detection rule", "Authentication failure burst"],
        ["Protocol / port", "HTTPS / 443"],
        ["Failed attempts", "186 in 6 minutes"],
        ["Confidence", "High · 88%"],
      ],
      timeline: [
        ["10:26 UTC", "Alert generated", "Failed authentication threshold was crossed."],
        ["10:23 UTC", "Attempt rate increased", "Multiple account names were attempted from one address."],
        ["10:20 UTC", "First failed login", "Initial rejected authentication request was recorded."],
      ],
    },
    {
      id: "INC-2046",
      title: "Network port sweep",
      severity: "Medium",
      source: "192.0.2.147",
      destination: "10.42.0.0/24",
      asset: "EDGE-FW-02",
      zone: "Perimeter",
      time: "09:58 UTC",
      description:
        "A remote host probed multiple service ports across the perimeter segment, consistent with reconnaissance activity.",
      evidence: [
        ["Detection rule", "Horizontal port scan"],
        ["Protocol / port", "TCP / multiple"],
        ["Ports probed", "43 distinct ports"],
        ["Confidence", "Medium · 79%"],
      ],
      timeline: [
        ["09:58 UTC", "Alert generated", "Scan threshold reached across monitored hosts."],
        ["09:52 UTC", "Probe expanded", "Requests spread to additional destination hosts."],
        ["09:49 UTC", "First probe", "Initial connection attempt was observed."],
      ],
    },
    {
      id: "INC-2045",
      title: "Suspicious DNS queries",
      severity: "Medium",
      source: "10.42.22.16",
      destination: "192.0.2.53",
      asset: "USER-WS-16",
      zone: "Corporate",
      time: "09:17 UTC",
      description:
        "A workstation made repeated DNS requests with unusually long subdomains. The pattern may indicate tunneling or automated beaconing.",
      evidence: [
        ["Detection rule", "DNS query anomaly"],
        ["Protocol / port", "DNS / 53"],
        ["Query count", "312 in 20 minutes"],
        ["Confidence", "Medium · 74%"],
      ],
      timeline: [
        ["09:17 UTC", "Alert generated", "Query pattern matched anomaly rules."],
        ["09:09 UTC", "Repetition detected", "Long encoded-looking subdomains recurred."],
        ["08:57 UTC", "First unusual query", "Initial query was recorded."],
      ],
    },
    {
      id: "INC-2044",
      title: "Policy-blocked connection",
      severity: "Low",
      source: "10.42.7.21",
      destination: "203.0.113.91",
      asset: "USER-WS-21",
      zone: "Corporate",
      time: "08:43 UTC",
      description:
        "A workstation attempted to connect to a destination disallowed by the perimeter policy. The connection was blocked.",
      evidence: [
        ["Detection rule", "Outbound policy violation"],
        ["Protocol / port", "TCP / 8080"],
        ["Connection attempts", "4 blocked"],
        ["Confidence", "High · 95%"],
      ],
      timeline: [
        ["08:43 UTC", "Alert generated", "Repeated blocked attempts triggered an alert."],
        ["08:41 UTC", "Connection blocked", "Perimeter policy denied the outbound request."],
        ["08:40 UTC", "First attempt", "Initial connection request was observed."],
      ],
    },
  ];

  const datasets = {
    "24h": {
      labels: ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "23:59"],
      traffic: [35, 29, 45, 52, 47, 69, 61],
      threats: [12, 18, 14, 33, 22, 48, 30],
      metrics: ["2.48M", "128", "1,842", "342"],
    },
    "7d": {
      labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
      traffic: [39, 49, 42, 65, 57, 74, 62],
      threats: [15, 21, 31, 22, 46, 35, 29],
      metrics: ["16.9M", "864", "12,406", "342"],
    },
    "30d": {
      labels: ["Week 1", "Week 2", "Week 3", "Week 4"],
      traffic: [42, 54, 66, 61],
      threats: [19, 33, 26, 43],
      metrics: ["71.2M", "3,421", "48,690", "342"],
    },
  };

  const zones = ["Perimeter", "Identity", "Application", "Corporate"];
  const zoneColors = ["#55d9ed", "#9a88ff", "#ff667f", "#55d7ad"];
  const liveTemplates = [
    { title: "Outbound transfer anomaly", severity: "Critical", zone: "Application", id: "INC-2048" },
    { title: "Authentication failure burst", severity: "High", zone: "Identity", id: "INC-2047" },
    { title: "Port sweep signature", severity: "Medium", zone: "Perimeter", id: "INC-2046" },
    { title: "Unusual DNS query pattern", severity: "Medium", zone: "Corporate", id: "INC-2045" },
    { title: "Policy-blocked connection", severity: "Low", zone: "Corporate", id: "INC-2044" },
  ];

  // --- State ---
  let selectedId = incidents[0].id;
  const liveEvents = [];
  let liveTicks = 0;
  let livePaused = false;

  // --- Utilities ---
  const escapeHTML = (str) =>
    String(str).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]));

  const sevClass = (severity) => severity.toLowerCase();

  async function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        // Fall through to legacy fallback
      }
    }
    const temp = document.createElement("textarea");
    temp.value = text;
    temp.style.position = "fixed";
    temp.style.opacity = "0";
    document.body.appendChild(temp);
    temp.select();
    const ok = document.execCommand("copy");
    temp.remove();
    return ok;
  }

  // --- Navigation ---
  function showView(view) {
    const names = {
      overview: "Security Overview",
      investigation: "Incident Investigation",
      live: "Live Threat Detection",
    };

    for (const key of Object.keys(names)) {
      document.getElementById(`${key}-view`).hidden = key !== view;
      const navBtn = document.getElementById(`nav-${key}`);
      navBtn.classList.toggle("active", key === view);
      navBtn.setAttribute("aria-current", key === view ? "page" : "false");
    }

    document.getElementById("breadcrumb-current").textContent = names[view];
  }

  function openIncident(id) {
    selectedId = id;
    renderList();
    renderDetail();
    showView("investigation");
  }

  // --- Overview Rendering ---
  function renderRecent() {
    const tbody = document.getElementById("recent-body");
    tbody.innerHTML = incidents
      .slice(0, 4)
      .map(
        (i) => `
        <tr class="row-click" tabindex="0" role="button" data-id="${i.id}" aria-label="Investigate ${escapeHTML(i.title)}">
          <td><strong>${escapeHTML(i.title)}</strong><br><span class="incident-id-sub">${i.id}</span></td>
          <td><span class="tag ${sevClass(i.severity)}">${i.severity}</span></td>
          <td>${i.source}</td>
          <td>${i.time}</td>
        </tr>`
      )
      .join("");

    tbody.querySelectorAll(".row-click").forEach((row) => {
      row.addEventListener("click", () => openIncident(row.dataset.id));
      row.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          openIncident(row.dataset.id);
        }
      });
    });
  }

  // --- Investigation Rendering ---
  function renderList() {
    const query = document.getElementById("incident-search").value.trim().toLowerCase();
    const sev = document.getElementById("severity-filter").value;

    const matches = incidents.filter(
      (i) =>
        (sev === "all" || i.severity === sev) &&
        [i.id, i.title, i.source, i.destination, i.asset].some((val) =>
          val.toLowerCase().includes(query)
        )
    );

    const listEl = document.getElementById("incident-list");
    listEl.innerHTML = matches.length
      ? matches
          .map(
            (i) => `
          <button type="button" class="incident-item ${i.id === selectedId ? "selected" : ""}" data-id="${i.id}" aria-pressed="${i.id === selectedId}">
            <span class="incident-top">
              <strong>${i.id}</strong>
              <span class="tag ${sevClass(i.severity)}">${i.severity}</span>
            </span>
            <p>${escapeHTML(i.title)}</p>
            <span class="incident-meta">
              <span>${i.source}</span>
              <span>${i.time}</span>
            </span>
          </button>`
          )
          .join("")
      : '<div class="empty">No incidents match these filters. Try another search or severity.</div>';

    listEl.querySelectorAll(".incident-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        selectedId = btn.dataset.id;
        renderList();
        renderDetail();
      });
    });
  }

  function renderDetail() {
    const incident = incidents.find((x) => x.id === selectedId);
    if (!incident) return;

    const detailEl = document.getElementById("incident-detail");
    detailEl.innerHTML = `
      <div class="detail-top">
        <div>
          <span class="tag ${sevClass(incident.severity)}">${incident.severity} severity</span>
          <h2>${escapeHTML(incident.title)}</h2>
          <p class="detail-description">${escapeHTML(incident.description)}</p>
        </div>
        <button id="copy-id" class="copy-btn" type="button">
          <i data-lucide="copy"></i> Copy ID
        </button>
      </div>

      <div class="facts">
        <div class="fact"><small>Incident ID</small><strong>${incident.id}</strong></div>
        <div class="fact"><small>Detected</small><strong>${incident.time}</strong></div>
        <div class="fact"><small>Affected asset</small><strong>${incident.asset}</strong></div>
        <div class="fact"><small>Network zone</small><strong>${incident.zone}</strong></div>
      </div>

      <div class="detail-section">
        <h3>Network evidence</h3>
        <div class="evidence">
          ${incident.evidence
            .map(
              ([k, v]) => `
            <div class="evidence-card">
              <small>${escapeHTML(k)}</small>
              <strong>${escapeHTML(v)}</strong>
            </div>`
            )
            .join("")}
          <div class="evidence-card"><small>Source IP</small><strong>${incident.source}</strong></div>
          <div class="evidence-card"><small>Destination IP</small><strong>${incident.destination}</strong></div>
        </div>
      </div>

      <div class="detail-section">
        <h3>Event timeline</h3>
        <ol class="timeline">
          ${incident.timeline
            .map(
              ([t, title, body]) => `
            <li>
              <time>${t}</time>
              <strong>${escapeHTML(title)}</strong>
              <p>${escapeHTML(body)}</p>
            </li>`
            )
            .join("")}
        </ol>
      </div>

      <div id="copy-status" class="notice" role="status"></div>
    `;

    document.getElementById("copy-id").addEventListener("click", async () => {
      const ok = await copyToClipboard(incident.id);
      document.getElementById("copy-status").textContent = ok
        ? `${incident.id} copied to clipboard.`
        : "Could not copy the incident ID.";
    });

    lucide.createIcons();
  }

  // --- Live Detection Rendering ---
  function renderLive() {
    const filter = document.getElementById("live-filter").value;
    const visible = liveEvents.filter((e) => filter === "all" || e.severity === filter);

    const feedEl = document.getElementById("live-feed");
    feedEl.innerHTML = visible.length
      ? visible
          .map(
            (e) => `
          <div class="feed-entry">
            <div>
              <span class="tag ${sevClass(e.severity)}">${e.severity}</span>
              <strong>${escapeHTML(e.title)}</strong>
              <p>${escapeHTML(e.zone)} zone · ${escapeHTML(e.source)} → ${escapeHTML(e.destination)} · ${e.time}</p>
              <button type="button" data-live-id="${e.id}">Investigate ${e.id} →</button>
            </div>
            <time>${e.age}s ago</time>
          </div>`
          )
          .join("")
      : '<div class="live-empty">No alerts for this severity yet.</div>';

    feedEl.querySelectorAll("[data-live-id]").forEach((btn) => {
      btn.addEventListener("click", () => openIncident(btn.dataset.liveId));
    });

    const counts = zones.map((z) => liveEvents.filter((e) => e.zone === z).length);
    document.getElementById("zone-bars").innerHTML = zones
      .map(
        (z, idx) => `
        <div class="zone-row">
          <header><span>${z}</span><strong>${counts[idx]} signals</strong></header>
          <div class="bar">
            <span style="width: ${Math.max(5, Math.min(100, counts[idx] * 18))}%; background: ${zoneColors[idx]};"></span>
          </div>
        </div>`
      )
      .join("");
  }

  function tickLive() {
    if (livePaused) return;
    liveTicks++;
    liveEvents.forEach((e) => (e.age += 5));

    const template = liveTemplates[(liveTicks * 3 + 1) % liveTemplates.length];
    const incident = incidents.find((i) => i.id === template.id);
    const timeStr =
      new Date().toLocaleTimeString("en-GB", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        timeZone: "UTC",
      }) + " UTC";

    liveEvents.unshift({
      ...template,
      source: incident.source,
      destination: incident.destination,
      time: timeStr,
      age: 0,
    });

    if (liveEvents.length > 30) liveEvents.pop();

    document.getElementById("live-signals").textContent = liveTicks.toLocaleString();
    document.getElementById("live-alerts").textContent = liveTicks.toLocaleString();
    document.getElementById("live-severity").textContent =
      ["Critical", "High", "Medium", "Low"].find((s) => liveEvents.some((e) => e.severity === s)) || "—";
    document.getElementById("live-updated").textContent = `Last signal: ${liveEvents[0].time}`;

    renderLive();
  }

  // --- Traffic & Threats Chart ---
  const ctx = document.getElementById("traffic-chart").getContext("2d");
  const trafficChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: datasets["24h"].labels,
      datasets: [
        {
          label: "Traffic",
          data: datasets["24h"].traffic,
          borderColor: "#55d9ed",
          backgroundColor: "#55d9ed14",
          fill: true,
          tension: 0.42,
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
        },
        {
          label: "Threats",
          data: datasets["24h"].threats,
          borderColor: "#9a88ff",
          backgroundColor: "transparent",
          tension: 0.42,
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { intersect: false, mode: "index" },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#20314b",
          titleColor: "#fff",
          bodyColor: "#cbd8ea",
          borderColor: "#435873",
          borderWidth: 1,
        },
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: "#8192ad", font: { size: 10 } },
          border: { display: false },
        },
        y: {
          min: 0,
          max: 100,
          grid: { color: "#29374e" },
          ticks: {
            color: "#8192ad",
            font: { size: 10 },
            stepSize: 25,
            callback: (v) => `${v}%`,
          },
          border: { display: false },
        },
      },
    },
  });

  // --- Event Listeners ---
  document.getElementById("nav-overview").addEventListener("click", () => showView("overview"));
  document.getElementById("nav-investigation").addEventListener("click", () => showView("investigation"));
  document.getElementById("nav-live").addEventListener("click", () => showView("live"));
  document.getElementById("view-all").addEventListener("click", () => showView("investigation"));

  document.getElementById("incident-search").addEventListener("input", renderList);
  document.getElementById("severity-filter").addEventListener("change", renderList);
  document.getElementById("live-filter").addEventListener("change", renderLive);

  document.getElementById("live-toggle").addEventListener("click", () => {
    livePaused = !livePaused;
    const toggleBtn = document.getElementById("live-toggle");
    toggleBtn.textContent = livePaused ? "Resume feed" : "Pause feed";
    toggleBtn.setAttribute("aria-pressed", String(livePaused));
    document.getElementById("live-state").classList.toggle("paused", livePaused);
    document.getElementById("live-state-text").textContent = livePaused
      ? "SIMULATION PAUSED"
      : "SIMULATION LIVE";
    if (!livePaused) tickLive();
  });

  document.querySelectorAll("[data-range]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-range]").forEach((b) => {
        b.classList.toggle("active", b === btn);
        b.setAttribute("aria-pressed", String(b === btn));
      });

      const d = datasets[btn.dataset.range];
      trafficChart.data.labels = d.labels;
      trafficChart.data.datasets[0].data = d.traffic;
      trafficChart.data.datasets[1].data = d.threats;
      trafficChart.update();

      ["events", "threats", "blocked", "assets"].forEach((key, idx) => {
        document.getElementById(`metric-${key}`).textContent = d.metrics[idx];
      });
    });
  });

  // --- Initialize ---
  renderRecent();
  renderList();
  renderDetail();
  tickLive();
  setInterval(tickLive, 5000);
  lucide.createIcons();
});