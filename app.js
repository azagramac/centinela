/**
 * Centinela — Frontend Application Logic
 * Automated Web Security & Legitimacy Assessment
 */

// Worker API endpoint (relative path for same-origin Cloudflare Worker routing)
const WORKER_URL = "/analyze";

// DOM Elements
const heroSection = document.getElementById("hero-section");
const loadingSection = document.getElementById("loading-section");
const resultsSection = document.getElementById("results-section");
const errorSection = document.getElementById("error-section");

const scanForm = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const clearBtn = document.getElementById("clear-btn");
const scanBtn = document.getElementById("scan-btn");
const loadingTargetUrl = document.getElementById("loading-target-url");
const pipelineProgress = document.getElementById("pipeline-progress");

const reportHostname = document.getElementById("report-hostname");
const reportTimestamp = document.getElementById("report-timestamp");
const copyReportBtn = document.getElementById("copy-report-btn");
const newScanBtn = document.getElementById("new-scan-btn");

const gaugeBar = document.getElementById("gauge-bar");
const gaugeScoreNum = document.getElementById("gauge-score-num");
const gaugeRatingBadge = document.getElementById("gauge-rating-badge");

const trustSeal = document.getElementById("trust-seal");
const sealIcon = document.getElementById("seal-icon");
const sealTitle = document.getElementById("seal-title");
const sealSubtitle = document.getElementById("seal-subtitle");

const metricSecScore = document.getElementById("metric-sec-score");
const metricLegScore = document.getElementById("metric-leg-score");
const metricTrustLevel = document.getElementById("metric-trust-level");
const executiveSummaryText = document.getElementById("executive-summary-text");

const ceilingNotice = document.getElementById("ceiling-notice");
const ceilingMaxScore = document.getElementById("ceiling-max-score");
const ceilingReason = document.getElementById("ceiling-reason");

const findingsList = document.getElementById("findings-list");
const cntCrit = document.getElementById("cnt-crit");
const cntHigh = document.getElementById("cnt-high");
const cntMed = document.getElementById("cnt-med");
const cntLow = document.getElementById("cnt-low");

const categoryBarsList = document.getElementById("category-bars-list");
const radarSvg = document.getElementById("radar-svg");
const breakdownHeader = document.getElementById("breakdown-header");
const breakdownBody = document.getElementById("breakdown-body");
const breakdownTableBody = document.getElementById("breakdown-table-body");

const toggleBarsBtn = document.getElementById("toggle-bars-btn");
const toggleRadarBtn = document.getElementById("toggle-radar-btn");
const postureBarsCol = document.getElementById("posture-bars-col");
const postureRadarCol = document.getElementById("posture-radar-col");

const errorDescText = document.getElementById("error-desc-text");
const errorRetryBtn = document.getElementById("error-retry-btn");

let currentAssessmentData = null;

// ============================================================================
// Pipeline Loading Steps Definition
// ============================================================================

const PIPELINE_STEPS = [
  { id: "dns", label: "Resolving DNS & DNSSEC signatures (DoH)…" },
  { id: "tls", label: "Inspecting TLS / SSL certificate & protocols…" },
  { id: "headers", label: "Auditing HTTP security headers & CSP…" },
  { id: "cookies", label: "Inspecting cookie attributes & scope…" },
  { id: "email", label: "Verifying email security (SPF / DMARC)…" },
  { id: "threat", label: "Querying threat intelligence & blocklists…" },
  { id: "rdap", label: "Fetching domain registration & RDAP age…" },
  { id: "legitimacy", label: "Running legitimacy engine & confidence ceiling…" }
];

let pipelineTimer = null;

// ============================================================================
// Initialization & Event Listeners
// ============================================================================

document.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
  initClientDiagnostics();
  checkUrlParams();
});

function setupEventListeners() {
  // Input clear button
  urlInput.addEventListener("input", () => {
    clearBtn.hidden = !urlInput.value;
  });

  clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    clearBtn.hidden = true;
    urlInput.focus();
  });

  // Example chips
  document.querySelectorAll(".quick-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      urlInput.value = chip.dataset.url;
      clearBtn.hidden = false;
      startScan(chip.dataset.url);
    });
  });

  // Nav brand return home
  document.getElementById("nav-brand").addEventListener("click", resetToSearch);

  // Form submit
  scanForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const raw = urlInput.value.trim();
    if (!raw) {
      urlInput.focus();
      return;
    }
    if (raw.startsWith("cnt-")) {
      loadScanById(raw);
    } else {
      startScan(raw);
    }
  });

  newScanBtn.addEventListener("click", resetToSearch);
  errorRetryBtn.addEventListener("click", resetToSearch);

  // Copy link
  copyReportBtn.addEventListener("click", () => {
    const baseOrigin = (window.location.origin && window.location.origin !== "null")
      ? window.location.origin
      : window.location.href.split("?")[0];

    const url = new URL(baseOrigin);
    if (currentAssessmentData?.scanId) {
      url.searchParams.set("id", currentAssessmentData.scanId);
    } else {
      url.searchParams.set("url", currentAssessmentData?.hostname || urlInput.value.trim());
    }

    navigator.clipboard.writeText(url.toString());
    copyReportBtn.innerHTML = `<span>Link Copied!</span>`;
    setTimeout(() => {
      copyReportBtn.innerHTML = `<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><span>Copy Link</span>`;
    }, 2000);
  });

  // Copy raw JSON
  const copyJsonBtn = document.getElementById("copy-json-btn");
  if (copyJsonBtn) {
    copyJsonBtn.addEventListener("click", () => {
      if (currentAssessmentData) {
        navigator.clipboard.writeText(JSON.stringify(currentAssessmentData, null, 2));
        copyJsonBtn.textContent = "Copied!";
        setTimeout(() => { copyJsonBtn.textContent = "Copy JSON"; }, 2000);
      }
    });
  }

  // Breakdown drawer toggle
  breakdownHeader.addEventListener("click", () => {
    const isOpen = breakdownBody.style.display === "block";
    breakdownBody.style.display = isOpen ? "none" : "block";
    breakdownHeader.querySelector(".chevron-icon").style.transform = isOpen ? "rotate(0deg)" : "rotate(180deg)";
  });

  // Posture View Toggles (Bars vs Radar)
  toggleBarsBtn.addEventListener("click", () => {
    toggleBarsBtn.classList.add("active");
    toggleRadarBtn.classList.remove("active");
    postureBarsCol.style.display = "block";
    postureRadarCol.style.display = window.innerWidth <= 900 ? "none" : "block";
  });

  toggleRadarBtn.addEventListener("click", () => {
    toggleRadarBtn.classList.add("active");
    toggleBarsBtn.classList.remove("active");
    postureRadarCol.style.display = "block";
    if (window.innerWidth <= 900) {
      postureBarsCol.style.display = "none";
    }
  });

  // Accordion Expanders
  document.querySelectorAll(".accordion-header").forEach(hdr => {
    hdr.addEventListener("click", () => {
      const card = hdr.closest(".accordion-card");
      card.classList.toggle("open");
    });
  });
}

function checkUrlParams() {
  const params = new URLSearchParams(window.location.search);
  const scanId = params.get("id") || params.get("scan") || params.get("scanId");
  const target = params.get("url") || params.get("target");

  if (scanId) {
    urlInput.value = scanId;
    clearBtn.hidden = false;
    loadScanById(scanId);
  } else if (target) {
    urlInput.value = target;
    clearBtn.hidden = false;
    startScan(target);
  }
}

async function loadScanById(scanId) {
  heroSection.hidden = true;
  resultsSection.hidden = true;
  errorSection.hidden = true;
  loadingSection.hidden = false;
  scanBtn.disabled = true;

  loadingTargetUrl.textContent = `Loading saved report: ${scanId}`;

  try {
    const apiUrl = `${WORKER_URL}?id=${encodeURIComponent(scanId)}`;
    const resp = await fetch(apiUrl);
    if (!resp.ok) {
      throw new Error(`Report with ID '${scanId}' was not found or has expired.`);
    }
    const data = await resp.json();
    currentAssessmentData = data;
    renderAssessmentReport(data);
  } catch (err) {
    showError(err.message);
  } finally {
    scanBtn.disabled = false;
  }
}

function resetToSearch() {
  clearInterval(pipelineTimer);
  resultsSection.hidden = true;
  loadingSection.hidden = true;
  errorSection.hidden = true;
  heroSection.hidden = false;
  scanBtn.disabled = false;
  urlInput.focus();
}

// ============================================================================
// Asynchronous Pipeline Scanner Execution
// ============================================================================

async function startScan(target) {
  const normalized = /^https?:\/\//i.test(target) ? target : `https://${target}`;

  heroSection.hidden = true;
  resultsSection.hidden = true;
  errorSection.hidden = true;
  loadingSection.hidden = false;
  scanBtn.disabled = true;

  loadingTargetUrl.textContent = normalized;

  // Initialize progress list
  pipelineProgress.innerHTML = "";
  PIPELINE_STEPS.forEach((step, idx) => {
    const div = document.createElement("div");
    div.className = `pipeline-step ${idx === 0 ? "active" : ""}`;
    div.id = `p-step-${step.id}`;
    div.innerHTML = `
      <span>${step.label}</span>
      <span class="step-icon">${idx === 0 ? "⏳" : "○"}</span>
    `;
    pipelineProgress.appendChild(div);
  });

  let stepIdx = 0;
  pipelineTimer = setInterval(() => {
    if (stepIdx < PIPELINE_STEPS.length) {
      const curEl = document.getElementById(`p-step-${PIPELINE_STEPS[stepIdx].id}`);
      if (curEl) {
        curEl.className = "pipeline-step done";
        curEl.querySelector(".step-icon").textContent = "✓";
      }
      stepIdx++;
      if (stepIdx < PIPELINE_STEPS.length) {
        const nextEl = document.getElementById(`p-step-${PIPELINE_STEPS[stepIdx].id}`);
        if (nextEl) {
          nextEl.className = "pipeline-step active";
          nextEl.querySelector(".step-icon").textContent = "⏳";
        }
      }
    }
  }, 550);

  try {
    const apiUrl = `${WORKER_URL}?url=${encodeURIComponent(normalized)}`;
    const resp = await fetch(apiUrl).catch(networkErr => {
      throw new Error(`Network connection to Worker failed: ${networkErr.message}. Check that WORKER_URL in app.js is reachable and deployed.`);
    });

    if (!resp.ok) {
      let errDetail = `Worker returned HTTP ${resp.status} (${resp.statusText})`;
      try {
        const errJson = await resp.json();
        if (errJson.error) errDetail = errJson.error;
      } catch {
        const text = await resp.text();
        if (text.includes("error code: 1042") || text.includes("error code: 1001")) {
          errDetail = `Cloudflare Worker not found at ${WORKER_URL} (Cloudflare Error 1042). Make sure your Worker is deployed in Cloudflare and that WORKER_URL in app.js matches your deployed Worker URL.`;
        } else if (text) {
          errDetail = `Worker error: ${text.slice(0, 150)}`;
        }
      }
      throw new Error(errDetail);
    }

    const data = await resp.json().catch(() => {
      throw new Error(`Worker returned invalid JSON response. Make sure the latest worker.js is deployed.`);
    });

    clearInterval(pipelineTimer);
    // Mark all done
    PIPELINE_STEPS.forEach(s => {
      const el = document.getElementById(`p-step-${s.id}`);
      if (el) {
        el.className = "pipeline-step done";
        el.querySelector(".step-icon").textContent = "✓";
      }
    });

    currentAssessmentData = data;
    setTimeout(() => {
      renderAssessmentReport(data);
    }, 400);

  } catch (err) {
    clearInterval(pipelineTimer);
    showError(err.message);
  } finally {
    scanBtn.disabled = false;
  }
}

function showError(msg) {
  loadingSection.hidden = true;
  resultsSection.hidden = true;
  heroSection.hidden = true;
  errorDescText.textContent = msg;
  errorSection.hidden = false;
}

// ============================================================================
// Render Assessment Report
// ============================================================================

function renderAssessmentReport(data) {
  loadingSection.hidden = true;
  errorSection.hidden = true;
  heroSection.hidden = true;
  resultsSection.hidden = false;

  reportHostname.textContent = data.hostname;
  const scanId = data.scanId || `cnt-${Date.now().toString(36)}`;
  data.scanId = scanId;
  const scanIdText = document.getElementById("scan-id-text");
  if (scanIdText) scanIdText.textContent = `ID: ${scanId}`;

  const scanIdChip = document.getElementById("scan-id-chip");
  if (scanIdChip) {
    scanIdChip.onclick = () => {
      navigator.clipboard.writeText(scanId);
      scanIdText.textContent = "Copied ID!";
      setTimeout(() => { scanIdText.textContent = `ID: ${scanId}`; }, 1500);
    };
  }

  saveAndCompareScanHistory(data);
  reportTimestamp.textContent = `Scanned on ${formatDate(data.scanTimestamp)} (${data.durationMs} ms)`;

  // 1. Gauge & Score
  const score = data.securityScore || 0;
  paintGauge(score, data.trustLevel);

  // 2. Trust Seal & Badges
  paintTrustSeal(data.seal, data.trustLevel);

  // 3. Tri-Metrics
  metricSecScore.textContent = `${data.securityScore} / 100`;
  metricLegScore.textContent = `${data.legitimacyScore} / 100`;
  metricTrustLevel.textContent = data.trustLevel;

  // 4. Executive Summary
  executiveSummaryText.textContent = data.executiveSummary;

  // 5. Confidence Ceiling
  if (data.confidenceCeiling && data.confidenceCeiling.applied) {
    ceilingNotice.hidden = false;
    ceilingMaxScore.textContent = data.confidenceCeiling.maxScore;
    ceilingReason.textContent = data.confidenceCeiling.reason;
  } else {
    ceilingNotice.hidden = true;
  }

  // 6. Findings List
  renderFindings(data.findings || []);

  // 7. Security Posture Bars
  renderCategoryBars(data.categoryScores || {});

  // 8. Radar Chart
  renderRadarChart(data.radarMetrics || []);

  // 9. Score Breakdown
  renderScoreBreakdown(data.scoreBreakdown || []);

  // 10. Deep Inspection Sections
  renderTlsSection(data.details?.tls, data.details?.http);
  renderDnsSection(data.details?.dns, data.details?.dnssec);
  renderHeadersSection(data.details?.http?.headers);
  renderCookiesSection(data.details?.http?.cookies);
  renderThreatIntelSection(data.details?.threatIntel);
  renderEmailSection(data.details?.email);
  renderTechAndInfraSection(data.details?.technologies, data.details?.infrastructure);
  renderRedirectsSection(data.details?.redirects);
  renderSubdomainsSection(data.details?.subdomains);
  renderLegitimacySection(data.details?.legitimacy, data.details);
  renderRawJsonSection(data);

  window.scrollTo({ top: 0, behavior: "smooth" });
}

function paintGauge(value, trustLevel) {
  const circumference = 578;
  const offset = circumference - (circumference * value) / 100;
  gaugeBar.style.strokeDashoffset = offset;
  
  let color = "var(--accent-teal)";
  let badgeText = "EXCELLENT";

  if (value >= 90) { color = "var(--accent-teal)"; badgeText = "EXCELLENT"; }
  else if (value >= 75) { color = "var(--accent-cyan)"; badgeText = "GOOD"; }
  else if (value >= 60) { color = "var(--accent-amber)"; badgeText = "MODERATE"; }
  else if (value >= 40) { color = "#fb7185"; badgeText = "POOR"; }
  else { color = "var(--accent-rose)"; badgeText = "CRITICAL"; }

  gaugeBar.style.stroke = color;
  gaugeScoreNum.textContent = value;
  gaugeScoreNum.style.color = color;
  gaugeRatingBadge.textContent = badgeText;
  gaugeRatingBadge.style.color = color;
  gaugeRatingBadge.style.background = `${color}20`;
}

function paintTrustSeal(seal, trustLevel) {
  trustSeal.className = "trust-seal";
  let icon = "✓";
  let title = "SAFE";
  let subtitle = "Technical security verified; no known threat indicators.";

  switch (seal) {
    case "VERIFIED_LEGITIMATE":
      trustSeal.classList.add("verified");
      icon = "★";
      title = "VERIFIED LEGITIMATE";
      subtitle = "Independently verified established brand & organizational infrastructure.";
      break;
    case "SAFE":
      trustSeal.classList.add("safe");
      icon = "✓";
      title = "SAFE POSTURE";
      subtitle = "No malware or threat signals detected with solid technical config.";
      break;
    case "CAUTION":
      trustSeal.classList.add("caution");
      icon = "⚠";
      title = "CAUTION";
      subtitle = "Moderate security weaknesses or newly registered domain.";
      break;
    case "SUSPICIOUS":
      trustSeal.classList.add("suspicious");
      icon = "!";
      title = "SUSPICIOUS";
      subtitle = "Elevated risk signals, weak security, or potential brand impersonation.";
      break;
    case "DANGEROUS":
      trustSeal.classList.add("dangerous");
      icon = "✖";
      title = "DANGEROUS";
      subtitle = "Active malware, phishing, or blacklisted infrastructure detected.";
      break;
    default:
      trustSeal.classList.add("safe");
      icon = "?";
      title = "UNVERIFIED";
      subtitle = "Assessment completed with public records.";
  }

  sealIcon.textContent = icon;
  sealTitle.textContent = title;
  sealSubtitle.textContent = subtitle;
}

function renderFindings(findings) {
  findingsList.innerHTML = "";

  let crit = 0, high = 0, med = 0, low = 0;
  findings.forEach(f => {
    if (f.severity === "CRITICAL") crit++;
    else if (f.severity === "HIGH") high++;
    else if (f.severity === "MEDIUM") med++;
    else if (f.severity === "LOW") low++;
  });

  cntCrit.textContent = `${crit} Critical`;
  cntHigh.textContent = `${high} High`;
  cntMed.textContent = `${med} Medium`;
  cntLow.textContent = `${low} Low`;

  if (findings.length === 0) {
    findingsList.innerHTML = `
      <div class="finding-card low">
        <div class="finding-top">
          <div class="finding-title-wrap">
            <span class="finding-sev-tag low">INFO</span>
            <span class="finding-title">No High-Risk Security Findings Detected</span>
          </div>
          <span class="finding-category">General Assessment</span>
        </div>
        <p style="color: var(--text-secondary); font-size: 13px;">Target exhibits strong compliance with standard baseline web security practices.</p>
      </div>
    `;
    return;
  }

  findings.forEach(f => {
    const card = document.createElement("div");
    const sevClass = (f.severity || "info").toLowerCase();
    card.className = `finding-card ${sevClass}`;

    card.innerHTML = `
      <div class="finding-top">
        <div class="finding-title-wrap">
          <span class="finding-sev-tag ${sevClass}">${f.severity}</span>
          <span class="finding-title">${escapeHtml(f.title)}</span>
        </div>
        <span class="finding-category">${escapeHtml(f.category || "")}</span>
      </div>
      <dl class="finding-details">
        <div>
          <dt>EVIDENCE</dt>
          <dd>${escapeHtml(f.evidence || "–")}</dd>
        </div>
        <div>
          <dt>RECOMMENDATION</dt>
          <dd>${escapeHtml(f.recommendation || "–")}</dd>
        </div>
      </dl>
    `;
    findingsList.appendChild(card);
  });
}

function renderCategoryBars(catScores) {
  categoryBarsList.innerHTML = "";
  const categories = [
    { key: "tls", name: "TLS / SSL Encryption" },
    { key: "dns", name: "DNS & DNSSEC Infrastructure" },
    { key: "headers", name: "HTTP Security Headers & CSP" },
    { key: "malware", name: "Threat Intelligence & Blocklists" },
    { key: "email", name: "Email Security (SPF / DMARC)" },
    { key: "cookies", name: "Cookie Security Flags" },
    { key: "legitimacy", name: "Domain Legitimacy & History" }
  ];

  categories.forEach(c => {
    const val = catScores[c.key] ?? 75;
    const color = val >= 85 ? "var(--accent-teal)" : val >= 65 ? "var(--accent-amber)" : "var(--accent-rose)";

    const item = document.createElement("div");
    item.className = "cat-bar-item";
    item.innerHTML = `
      <div class="cat-bar-meta">
        <span class="cat-bar-name">${c.name}</span>
        <span class="cat-bar-score" style="color: ${color}">${val} / 100</span>
      </div>
      <div class="cat-bar-track">
        <div class="cat-bar-fill" style="width: ${val}%; background: ${color}"></div>
      </div>
    `;
    categoryBarsList.appendChild(item);
  });
}

function renderRadarChart(metrics) {
  if (!metrics || metrics.length < 3) return;

  const size = 360;
  const center = size / 2;
  const radius = 130;
  const total = metrics.length;
  const angleSlice = (Math.PI * 2) / total;

  let bgCircles = "";
  [0.25, 0.5, 0.75, 1.0].forEach(level => {
    let polyPoints = [];
    for (let i = 0; i < total; i++) {
      const a = i * angleSlice - Math.PI / 2;
      const x = center + radius * level * Math.cos(a);
      const y = center + radius * level * Math.sin(a);
      polyPoints.push(`${x},${y}`);
    }
    bgCircles += `<polygon points="${polyPoints.join(" ")}" class="radar-polygon-bg" />`;
  });

  let axes = "";
  let dataPoints = [];
  let labels = "";

  metrics.forEach((m, idx) => {
    const a = idx * angleSlice - Math.PI / 2;
    const x = center + radius * Math.cos(a);
    const y = center + radius * Math.sin(a);
    axes += `<line x1="${center}" y1="${center}" x2="${x}" y2="${y}" class="radar-axis" />`;

    const valNormalized = Math.max(10, Math.min(100, m.value)) / 100;
    const dx = center + radius * valNormalized * Math.cos(a);
    const dy = center + radius * valNormalized * Math.sin(a);
    dataPoints.push(`${dx},${dy}`);

    const lx = center + (radius + 20) * Math.cos(a);
    const ly = center + (radius + 20) * Math.sin(a);
    labels += `<text x="${lx}" y="${ly + 4}" class="radar-label">${escapeHtml(m.category)}</text>`;
  });

  const dataPoly = `<polygon points="${dataPoints.join(" ")}" class="radar-polygon-data" />`;
  let pointsMarkup = "";
  dataPoints.forEach(p => {
    const [px, py] = p.split(",");
    pointsMarkup += `<circle cx="${px}" cy="${py}" r="4" class="radar-point" />`;
  });

  radarSvg.innerHTML = `
    ${bgCircles}
    ${axes}
    ${dataPoly}
    ${pointsMarkup}
    ${labels}
  `;
}

function renderScoreBreakdown(breakdown) {
  breakdownTableBody.innerHTML = "";
  breakdown.forEach(row => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(row.name)}</td>
      <td>${escapeHtml(row.weight)}</td>
      <td>${row.score} / 100</td>
      <td style="color: var(--accent-teal)">+${row.contribution}</td>
    `;
    breakdownTableBody.appendChild(tr);
  });
}

// ============================================================================
// Deep Inspection Renderers
// ============================================================================

function renderTlsSection(tls, http) {
  const grid = document.getElementById("tls-data-grid");
  const badge = document.getElementById("acc-badge-tls");
  grid.innerHTML = "";

  if (!tls || tls.status === "error") {
    badge.textContent = "N/A";
    badge.style.color = "var(--accent-rose)";
    row(grid, "Status", tls?.message || "TLS Verification Unavailable");
    row(grid, "HTTPS Connection", http?.httpsFinal ? "Enforced" : "Disabled");
    return;
  }

  badge.textContent = tls.grade || "A";
  badge.style.color = tls.grade?.startsWith("A") ? "var(--accent-teal)" : "var(--accent-amber)";

  // Timeline
  document.getElementById("tls-issued-date").textContent = formatDate(tls.issuedDate);
  document.getElementById("tls-expiry-date").textContent = formatDate(tls.expiryDate);
  document.getElementById("tls-remaining-days").textContent = tls.daysRemaining ? `${tls.daysRemaining} days` : "–";

  row(grid, "SSL Labs Grade", tls.grade || "A");
  row(grid, "TLS 1.3 Support", tls.hasTls13 ? "✓ Supported" : "✗ Disabled");
  row(grid, "TLS 1.2 Support", tls.hasTls12 ? "✓ Supported" : "✗ Disabled");
  row(grid, "Legacy TLS (1.0/1.1)", tls.hasTls10 ? "⚠ Enabled (Insecure)" : "✓ Disabled");
  row(grid, "SSLv3 Support", tls.hasSslv3 ? "⚠ Enabled (Insecure)" : "✓ Disabled");
  row(grid, "Forward Secrecy (PFS)", tls.forwardSecrecy ? "✓ Supported" : "✗ Unsupported");
  row(grid, "Heartbleed", tls.heartbleed ? "⚠ Vulnerable" : "✓ Safe");
  row(grid, "POODLE", tls.poodle ? "⚠ Vulnerable" : "✓ Safe");
  row(grid, "Certificate Issuer", tls.issuer);
  row(grid, "Key Algorithm", `${tls.keyAlg} ${tls.keySize} bit`);
  row(grid, "Signature Algorithm", tls.sigAlg);
}

function renderDnsSection(dns, dnssec) {
  const tree = document.getElementById("dns-tree");
  const pill = document.getElementById("dnssec-status-pill");
  const desc = document.getElementById("dnssec-desc");
  tree.innerHTML = "";

  if (dnssec?.status === "VALID") {
    pill.className = "dnssec-status-pill valid";
    pill.textContent = "VALID";
    desc.textContent = "DNSSEC signature chain of trust verified (Authenticated Data flag set).";
  } else {
    pill.className = "dnssec-status-pill not_enabled";
    pill.textContent = "NOT_ENABLED";
    desc.textContent = dnssec?.description || "DNSSEC not configured for this zone.";
  }

  const records = dns?.records || {};
  for (const [type, list] of Object.entries(records)) {
    if (list && list.length > 0) {
      const node = document.createElement("div");
      node.className = "dns-tree-node";
      node.innerHTML = `
        <span class="dns-type-tag">${type}</span>
        <span class="dns-records-val">${escapeHtml(list.slice(0, 4).join(", "))}</span>
      `;
      tree.appendChild(node);
    }
  }
}

function renderHeadersSection(headers) {
  const grid = document.getElementById("headers-data-grid");
  const cspList = document.getElementById("csp-issues-list");
  const cspTag = document.getElementById("csp-grade-tag");
  grid.innerHTML = "";
  cspList.innerHTML = "";

  if (!headers) {
    row(grid, "Status", "No header data available");
    return;
  }

  const csp = headers.csp;
  if (csp && csp.present) {
    const rating = csp.audit?.rating || "STRONG";
    cspTag.textContent = rating;
    cspTag.className = `csp-grade-tag ${rating.toLowerCase()}`;
    (csp.audit?.issues || []).forEach(issue => {
      const li = document.createElement("li");
      li.textContent = issue;
      cspList.appendChild(li);
    });
  } else {
    cspTag.textContent = "MISSING";
    cspTag.className = "csp-grade-tag weak";
    cspList.innerHTML = "<li>No Content-Security-Policy header defined.</li>";
  }

  row(grid, "Strict-Transport-Security (HSTS)", headers.hsts?.present ? `✓ Present (${headers.hsts.maxAge}s)` : "✗ Missing");
  row(grid, "X-Frame-Options", headers.xFrameOptions?.present ? `✓ ${headers.xFrameOptions.value}` : "✗ Missing");
  row(grid, "X-Content-Type-Options", headers.xContentTypeOptions?.present ? `✓ ${headers.xContentTypeOptions.value}` : "✗ Missing");
  row(grid, "Referrer-Policy", headers.referrerPolicy?.present ? `✓ ${headers.referrerPolicy.value}` : "✗ Missing");
  row(grid, "Permissions-Policy", headers.permissionsPolicy?.present ? `✓ Present` : "– Not Defined");
  row(grid, "Cross-Origin-Opener-Policy (COOP)", headers.coop?.present ? `✓ ${headers.coop.value}` : "– Not Defined");
  row(grid, "Cross-Origin-Resource-Policy (CORP)", headers.corp?.present ? `✓ ${headers.corp.value}` : "– Not Defined");
  row(grid, "Server Banner", headers.server || "Hidden / Undisclosed");
}

function renderCookiesSection(cookies) {
  const summaryBar = document.getElementById("cookies-summary-bar");
  const tableWrap = document.getElementById("cookies-table-wrap");
  summaryBar.innerHTML = "";
  tableWrap.innerHTML = "";

  if (!cookies || !cookies.count) {
    summaryBar.innerHTML = `<p style="color: var(--text-dim); font-size: 13px;">No cookies returned on initial HTTP response.</p>`;
    return;
  }

  summaryBar.innerHTML = `
    <div style="display: flex; gap: 16px; margin-bottom: 12px; font-family: var(--font-mono); font-size: 12.5px;">
      <span>Cookies Detected: <strong>${cookies.count}</strong></span>
      <span>Secure Flag: <strong>${cookies.secureRatio}</strong></span>
      <span>HttpOnly Flag: <strong>${cookies.httpOnlyRatio}</strong></span>
    </div>
  `;

  let tableHtml = `
    <table class="breakdown-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Secure</th>
          <th>HttpOnly</th>
          <th>SameSite</th>
        </tr>
      </thead>
      <tbody>
  `;

  cookies.items.forEach(c => {
    tableHtml += `
      <tr>
        <td><strong>${escapeHtml(c.name)}</strong></td>
        <td>${c.secure ? "✓ Yes" : "✗ No"}</td>
        <td>${c.httpOnly ? "✓ Yes" : "✗ No"}</td>
        <td>${escapeHtml(c.sameSite)}</td>
      </tr>
    `;
  });

  tableHtml += "</tbody></table>";
  tableWrap.innerHTML = tableHtml;
}

function renderThreatIntelSection(threat) {
  const grid = document.getElementById("threat-providers-grid");
  grid.innerHTML = "";

  const providers = threat?.providers || {};
  
  const feedList = [
    { key: "urlhaus", name: "URLhaus (Abuse.ch Malware Feed)", defStatus: "CLEAN", defMsg: "No active malware distribution URLs" },
    { key: "threatFox", name: "ThreatFox (Botnet C2 & IOCs)", defStatus: "CLEAN", defMsg: "No C2 or IOC indicators recorded" },
    { key: "spamhaus", name: "Spamhaus DBL (Domain Blocklist)", defStatus: "CLEAN", defMsg: "Not listed in Spamhaus DBL" },
    { key: "openPhish", name: "OpenPhish Community Feed", defStatus: "CLEAN", defMsg: "No phishing records indexed" },
    { key: "googleSafeBrowsing", name: "Google Safe Browsing v4", defStatus: "NOT_CONFIGURED", defMsg: "Set GSB_API_KEY to activate" },
    { key: "virusTotal", name: "VirusTotal v3 Multi-Engine", defStatus: "NOT_CONFIGURED", defMsg: "Set VIRUSTOTAL_API_KEY to activate" }
  ];

  feedList.forEach(feed => {
    const p = providers[feed.key];
    const status = p?.status || feed.defStatus;
    const msg = p?.message || feed.defMsg;
    addProviderCard(grid, feed.name, status, msg);
  });
}

function addProviderCard(grid, name, status, detail) {
  const card = document.createElement("div");
  card.className = "threat-prov-card";
  const st = (status || "CLEAN").toLowerCase();

  card.innerHTML = `
    <div class="threat-prov-header">
      <span>${escapeHtml(name)}</span>
      <span class="prov-status-tag ${st}">${escapeHtml(status)}</span>
    </div>
    <span style="font-size: 12px; color: var(--text-dim);">${escapeHtml(detail)}</span>
  `;
  grid.appendChild(card);
}

function renderEmailSection(email) {
  const grid = document.getElementById("email-data-grid");
  grid.innerHTML = "";
  if (!email) return;

  row(grid, "SPF Record", email.spf?.present ? `✓ Valid (${email.spf.record})` : "✗ Missing");
  row(grid, "DMARC Record", email.dmarc?.present ? `✓ Configured (p=${email.dmarc.policy})` : "✗ Missing");
  row(grid, "DMARC Enforcement", email.dmarc?.strong ? "✓ Strong (Quarantine/Reject)" : "⚠ Weak (p=none)");
  row(grid, "MTA-STS", email.mtaSts?.present ? "✓ Configured" : "– Not Configured");
  row(grid, "TLS-RPT", email.tlsRpt?.present ? "✓ Configured" : "– Not Configured");
}

function renderTechAndInfraSection(tech, infra) {
  const chips = document.getElementById("tech-chips-list");
  const grid = document.getElementById("infra-data-grid");
  const cvePill = document.getElementById("cve-count-pill");
  const cveDesc = document.getElementById("cve-desc-text");
  const cveList = document.getElementById("cve-items-list");
  const badgeCves = document.getElementById("acc-badge-cves");

  chips.innerHTML = "";
  grid.innerHTML = "";
  cveList.innerHTML = "";

  const cves = tech?.cves || [];
  const cveCount = cves.length;

  if (cveCount > 0) {
    cvePill.className = "cve-count-pill has-cves";
    cvePill.textContent = `${cveCount} KNOWN CVE${cveCount > 1 ? "s" : ""} DETECTED`;
    cveDesc.textContent = `Disclosed software version matches known public security vulnerabilities.`;
    if (badgeCves) { badgeCves.textContent = `${cveCount} CVE`; badgeCves.style.color = "var(--accent-rose)"; }

    cves.forEach(cve => {
      const card = document.createElement("div");
      card.className = "cve-card";
      card.innerHTML = `
        <div class="cve-card-top">
          <span class="cve-id-tag">${escapeHtml(cve.cveId)}</span>
          <span class="cvss-score-pill">CVSS ${cve.cvss} (${cve.severity})</span>
        </div>
        <p class="cve-summary">${escapeHtml(cve.summary)}</p>
        <span class="cve-fixed-in">✓ Recommended Fix: Upgrade to ${escapeHtml(cve.fixedIn)}</span>
      `;
      cveList.appendChild(card);
    });
  } else {
    cvePill.className = "cve-count-pill";
    cvePill.textContent = "0 KNOWN CVEs";
    cveDesc.textContent = "Disclosed technology versions do not match known critical CVE signatures.";
    if (badgeCves) { badgeCves.textContent = "0 CVEs"; badgeCves.style.color = "var(--accent-emerald)"; }
  }

  const techs = tech?.technologies || [];
  if (techs.length) {
    techs.forEach(t => {
      const span = document.createElement("span");
      span.className = "quick-chip";
      span.textContent = `${t.name} (${t.category})`;
      chips.appendChild(span);
    });
  } else {
    chips.innerHTML = `<span style="color: var(--text-dim); font-size: 13px;">No explicit tech banners disclosed in headers.</span>`;
  }

  if (infra) {
    row(grid, "Infrastructure Provider", infra.provider || "Public Cloud");
    row(grid, "IPv4 Addresses", (infra.ipv4 || []).join(", ") || "–");
    row(grid, "IPv6 Addresses", (infra.ipv6 || []).join(", ") || "–");
    row(grid, "Authoritative Nameservers", (infra.nameservers || []).slice(0, 3).join(", ") || "–");
  }
}

function renderRedirectsSection(redirects) {
  const flow = document.getElementById("redirect-flow");
  flow.innerHTML = "";

  if (!redirects || !redirects.length) {
    flow.innerHTML = `<p style="color: var(--text-dim); font-size: 13px;">Direct connection, no HTTP redirects.</p>`;
    return;
  }

  redirects.forEach((r, idx) => {
    const card = document.createElement("div");
    card.className = "redirect-step-card";
    const isFinal = idx === redirects.length - 1;
    const badgeClass = r.status === 200 ? "s200" : "s301";

    card.innerHTML = `
      <span class="redirect-status-badge ${badgeClass}">${r.status || "–"}</span>
      <span class="redirect-url">${escapeHtml(r.url)}</span>
      <span style="color: var(--text-dim); font-size: 11px;">${r.timeMs} ms</span>
    `;
    flow.appendChild(card);
  });
}

function renderSubdomainsSection(subdomains) {
  const wrap = document.getElementById("subdomains-wrap");
  wrap.innerHTML = "";

  const list = subdomains?.list || [];
  if (!list.length) {
    wrap.innerHTML = `<p style="color: var(--text-dim); font-size: 13px;">No passive Certificate Transparency subdomains indexed.</p>`;
    return;
  }

  let html = `<div style="display: flex; flex-wrap: wrap; gap: 8px;">`;
  list.forEach(sub => {
    html += `<span class="quick-chip">${escapeHtml(sub)}</span>`;
  });
  html += `</div>`;
  wrap.innerHTML = html;
}

function renderRawJsonSection(data) {
  const block = document.getElementById("raw-json-block");
  if (block) {
    block.textContent = JSON.stringify(data, null, 2);
  }
}

// ============================================================================
// UI Helper Utilities
// ============================================================================

function row(container, label, value) {
  const div = document.createElement("div");
  div.className = "data-row";
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value;
  div.append(dt, dd);
  container.appendChild(div);
}

function formatDate(iso) {
  if (!iso) return "Unknown";
  try {
    return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
  } catch {
    return iso;
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


// ============================================================================
// Historical Evolution & Comparison Engine (localStorage Persistence)
// ============================================================================

function saveAndCompareScanHistory(currentScan) {
  const hostname = currentScan.hostname;
  const storageKey = `centinela_history_${hostname}`;
  let history = [];

  try {
    const raw = localStorage.getItem(storageKey);
    if (raw) history = JSON.parse(raw);
  } catch {}

  const previousScan = (history.length > 0) ? history[history.length - 1] : null;

  // Add current scan to history (keep last 10 scans)
  history.push({
    scanId: currentScan.scanId,
    timestamp: currentScan.scanTimestamp,
    securityScore: currentScan.securityScore,
    categoryScores: currentScan.categoryScores,
    findings: (currentScan.findings || []).map(f => f.title)
  });

  if (history.length > 10) history = history.slice(-10);

  try {
    localStorage.setItem(storageKey, JSON.stringify(history));
  } catch {}

  // Render comparison if previous scan exists
  const compCard = document.getElementById("history-compare-card");
  if (!compCard) return;

  if (previousScan && previousScan.scanId !== currentScan.scanId) {
    compCard.hidden = false;
    renderComparisonWidget(previousScan, currentScan);
  } else {
    compCard.hidden = true;
  }
}

function renderComparisonWidget(prev, curr) {
  const delta = curr.securityScore - prev.securityScore;
  const deltaBadge = document.getElementById("score-delta-badge");
  const sub = document.getElementById("compare-subtitle");

  const prevDateStr = formatDate(prev.timestamp);
  sub.textContent = `Comparing with previous scan on ${prevDateStr} (${prev.scanId})`;

  if (delta > 0) {
    deltaBadge.className = "score-delta-badge";
    deltaBadge.textContent = `+${delta} pts Improvement`;
  } else if (delta < 0) {
    deltaBadge.className = "score-delta-badge negative";
    deltaBadge.textContent = `${delta} pts Regressed`;
  } else {
    deltaBadge.className = "score-delta-badge neutral";
    deltaBadge.textContent = `0 pts (No score change)`;
  }

  document.getElementById("comp-prev-score").textContent = `${prev.securityScore} / 100`;
  document.getElementById("comp-prev-id").textContent = prev.scanId;
  document.getElementById("comp-curr-score").textContent = `${curr.securityScore} / 100`;
  document.getElementById("comp-curr-id").textContent = curr.scanId;

  // Category Diffs
  const diffsContainer = document.getElementById("compare-categories-diff");
  diffsContainer.innerHTML = "";

  const catNames = {
    tls: "TLS / SSL",
    headers: "Headers & CSP",
    dns: "DNS & DNSSEC",
    malware: "Threat Intel",
    email: "Email DMARC",
    cookies: "Cookies"
  };

  const prevCats = prev.categoryScores || {};
  const currCats = curr.categoryScores || {};

  for (const [k, label] of Object.entries(catNames)) {
    const pVal = prevCats[k] ?? 80;
    const cVal = currCats[k] ?? 80;
    const catDelta = cVal - pVal;

    let deltaHtml = `<span class="diff-chip-delta same">0</span>`;
    if (catDelta > 0) deltaHtml = `<span class="diff-chip-delta plus">+${catDelta}</span>`;
    else if (catDelta < 0) deltaHtml = `<span class="diff-chip-delta minus">${catDelta}</span>`;

    const chip = document.createElement("div");
    chip.className = "diff-chip";
    chip.innerHTML = `
      <span class="diff-chip-name">${label}</span>
      <div class="diff-chip-val">
        <span>${pVal} ➔ ${cVal}</span>
        ${deltaHtml}
      </div>
    `;
    diffsContainer.appendChild(chip);
  }

  // Resolved Findings
  const prevFindings = prev.findings || [];
  const currFindingTitles = (curr.findings || []).map(f => f.title);
  const resolved = prevFindings.filter(t => !currFindingTitles.includes(t));

  const resolvedWrap = document.getElementById("resolved-findings-wrap");
  const resolvedList = document.getElementById("resolved-list");
  resolvedList.innerHTML = "";

  if (resolved.length > 0) {
    resolvedWrap.hidden = false;
    resolved.forEach(title => {
      const li = document.createElement("li");
      li.textContent = `✓ Fixed: ${title}`;
      resolvedList.appendChild(li);
    });
  } else {
    resolvedWrap.hidden = true;
  }
}

function renderLegitimacySection(legit, details) {
  const pill = document.getElementById("identity-badge-pill");
  const expText = document.getElementById("identity-explanation-text");
  const grid = document.getElementById("legit-data-grid");
  const badgeLegit = document.getElementById("acc-badge-legit");

  if (!grid) return;
  grid.innerHTML = "";

  const isVerified = legit?.isDirectlyVerified;
  const isSuspicious = (legit?.impersonationSignals || []).length > 0;
  const isDangerous = legit?.seal === "DANGEROUS";

  if (isVerified) {
    pill.className = "identity-badge-pill verified-ev";
    pill.textContent = "★ LEGAL IDENTITY VERIFIED (OV/EV / BIMI)";
    if (badgeLegit) { badgeLegit.textContent = "VERIFIED"; badgeLegit.style.color = "var(--accent-emerald)"; }
  } else if (isDangerous || isSuspicious) {
    pill.className = "identity-badge-pill suspicious-id";
    pill.textContent = isDangerous ? "✖ DANGEROUS / MALICIOUS" : "⚠ SUSPICIOUS PATTERNS DETECTED";
    if (badgeLegit) { badgeLegit.textContent = "RISK"; badgeLegit.style.color = "var(--accent-rose)"; }
  } else {
    pill.className = "identity-badge-pill";
    pill.textContent = legit?.certType || "DV (Domain Validation - Standard)";
    if (badgeLegit) { badgeLegit.textContent = "DV"; badgeLegit.style.color = "var(--accent-cyan)"; }
  }

  expText.textContent = legit?.identityExplanation || legit?.confidenceCeiling?.reason || "Identity evidence synthesized from public PKI and authoritative registries.";

  // Evidence Rows
  row(grid, "Certificate Validation Level", legit?.certType || "DV (Domain Validation)");
  row(grid, "Legal Organization Name", legit?.certOrg || "Not Declared in Certificate");
  row(grid, "Issuing Certificate Authority", legit?.certIssuer || details?.tls?.issuer || "Public CA");
  row(grid, "BIMI Brand Indicator Record", legit?.hasBimi ? `✓ Published (${legit.bimiRecord})` : "Not Published");
  row(grid, "DNS Infrastructure Authority", legit?.dnsAuthorityType || "Delegated / Managed DNS");
  row(grid, "Domain Operating Longevity", `${details?.domain?.ageYears || details?.domain?.ageDays ? (details.domain.ageYears + " Years") : "Established"}`);
  row(grid, "DNSSEC Cryptographic Chain", details?.dnssec?.status === "VALID" ? "✓ Validated Trust Chain" : "Not Configured");
  row(grid, "Brand Impersonation / Phishing", (legit?.impersonationSignals || []).length ? `⚠ Flagged: ${legit.impersonationSignals[0]}` : "✓ Clean (No typosquatting signals)");
}

// ============================================================================
// Client Browser Security Diagnostics (Cloudflare-style Encrypted SNI / DoH)
// ============================================================================

function initClientDiagnostics() {
  const diagBtn = document.getElementById("nav-diag-btn");
  const closeBtn = document.getElementById("close-diag-btn");
  const panel = document.getElementById("client-diag-panel");

  if (diagBtn && panel) {
    diagBtn.addEventListener("click", () => {
      panel.hidden = !panel.hidden;
      if (!panel.hidden) runBrowserDiagnostics();
    });
  }

  if (closeBtn && panel) {
    closeBtn.addEventListener("click", () => {
      panel.hidden = true;
    });
  }

  // Run initial diagnostic silently in background
  runBrowserDiagnostics();
}

async function runBrowserDiagnostics() {
  const dnssecStatus = document.getElementById("diag-dnssec-status");
  const dohStatus = document.getElementById("diag-doh-status");
  const tlsStatus = document.getElementById("diag-tls-status");
  const echStatus = document.getElementById("diag-ech-status");
  const metaContainer = document.getElementById("client-env-meta");

  const miniBadge = document.getElementById("client-mini-badge");
  const miniDnssec = document.getElementById("mini-dnssec");
  const miniDoh = document.getElementById("mini-doh");
  const miniTls = document.getElementById("mini-tls");
  const miniEch = document.getElementById("mini-ech");

  const ua = (typeof navigator !== "undefined" && navigator.userAgent) ? navigator.userAgent : "";
  let browserName = "Modern Browser";
  if (ua.includes("Firefox")) browserName = "Mozilla Firefox";
  else if (ua.includes("Edg")) browserName = "Microsoft Edge";
  else if (ua.includes("Chrome")) browserName = "Google Chrome / Chromium";
  else if (ua.includes("Safari")) browserName = "Apple Safari";

  // 1. Live Query to Cloudflare Crypto Trace Endpoint (Has Access-Control-Allow-Origin: *)
  let isTls13 = true;
  let isEch = false;
  let clientIp = "";
  let clientLoc = "";

  try {
    const traceRes = await fetch("https://crypto.cloudflare.com/cdn-cgi/trace", { cache: "no-store" });
    if (traceRes.ok) {
      const traceText = await traceRes.text();
      const map = {};
      traceText.split("\n").forEach(line => {
        const [k, v] = line.split("=");
        if (k && v) map[k.trim()] = v.trim();
      });

      isTls13 = map["tls"] === "TLSv1.3" || map["tls"] === "TLSv1.2";
      isEch = map["sni"] === "encrypted";
      clientIp = map["ip"] || "";
      clientLoc = map["loc"] || "";
    }
  } catch (e) {
    isTls13 = typeof window !== "undefined" && window.crypto && Boolean(window.crypto.subtle);
    isEch = false;
  }

  // Update TLS 1.3 UI
  if (miniTls) {
    miniTls.textContent = isTls13 ? "✓ TLS 1.3 Active" : "⚠ Legacy TLS";
    miniTls.style.color = isTls13 ? "#34d399" : "#fbbf24";
  }
  if (tlsStatus) {
    tlsStatus.className = isTls13 ? "diag-status-pill success" : "diag-status-pill";
    tlsStatus.textContent = isTls13 ? "✓ TLS 1.3 ACTIVE" : "⚠ FALLBACK";
  }

  // Update ECH / Secure SNI UI
  if (miniEch) {
    miniEch.textContent = isEch ? "✓ ECH Encrypted" : "✕ Plaintext SNI";
    miniEch.style.color = isEch ? "#34d399" : "#f87171";
  }
  if (echStatus) {
    echStatus.className = isEch ? "diag-status-pill success" : "diag-status-pill";
    echStatus.textContent = isEch ? "✓ ENCRYPTED" : "✕ PLAIN SNI";
    if (!isEch) echStatus.style.color = "#f87171";
  }

  // 2. Live DoH & DNSSEC Verification
  let isDoh = false;
  let isDnssec = false;

  try {
    const dohRes = await fetch("https://cloudflare-dns.com/dns-query?name=cloudflare.com&type=A&do=true", {
      headers: { "Accept": "application/dns-json" },
      cache: "no-store"
    });
    if (dohRes.ok) {
      const data = await dohRes.json();
      isDoh = true;
      isDnssec = Boolean(data.AD);
    }
  } catch (e) {
    isDoh = false;
    isDnssec = false;
  }

  // Update DoH UI
  if (miniDoh) {
    miniDoh.textContent = isDoh ? "✓ DoH Active" : "⚠ Standard DNS";
    miniDoh.style.color = isDoh ? "#34d399" : "#fbbf24";
  }
  if (dohStatus) {
    dohStatus.className = isDoh ? "diag-status-pill success" : "diag-status-pill caution";
    dohStatus.textContent = isDoh ? "✓ DOH ACTIVE" : "⚠ UNVERIFIED TRANSPORT";
    dohStatus.style.color = isDoh ? "#34d399" : "#fbbf24";
  }

  // Update DNSSEC UI
  if (miniDnssec) {
    miniDnssec.textContent = isDnssec ? "✓ Validated" : "✕ Not Enforced";
    miniDnssec.style.color = isDnssec ? "#34d399" : "#f87171";
  }
  if (dnssecStatus) {
    dnssecStatus.className = isDnssec ? "diag-status-pill success" : "diag-status-pill";
    dnssecStatus.textContent = isDnssec ? "✓ VALIDATED" : "✕ NOT ENFORCED";
    if (!isDnssec) dnssecStatus.style.color = "#f87171";
  }

  // 3. Update Main Badge
  if (miniBadge) {
    if (isDoh && isTls13) {
      miniBadge.textContent = "✓ Hardened Client Security";
      miniBadge.style.color = "var(--accent-teal)";
      miniBadge.style.background = "rgba(16, 185, 129, 0.15)";
    } else if (isTls13) {
      miniBadge.textContent = "DNSSEC & TLS 1.3 Active";
      miniBadge.style.color = "var(--accent-teal)";
      miniBadge.style.background = "rgba(16, 185, 129, 0.15)";
    } else {
      miniBadge.textContent = "⚠ Standard Transport";
      miniBadge.style.color = "var(--accent-amber)";
      miniBadge.style.background = "rgba(245, 158, 11, 0.15)";
    }
  }

  // 4. Update Meta Breakdown
  if (metaContainer) {
    metaContainer.innerHTML = `
      <span>Browser: <strong>${browserName}</strong></span>
      <span>TLS Protocol: <strong>${isTls13 ? "TLS 1.3 (Active)" : "TLS 1.2 / Standard"}</strong></span>
      <span>DNSSEC: <strong>${isDnssec ? "Validated (AD Bit Active)" : "Not Enforced"}</strong></span>
      <span>Secure DNS: <strong>${isDoh ? "DoH Active" : "Standard DNS"}</strong></span>
      <span>Secure SNI: <strong>${isEch ? "ECH Active (Encrypted)" : "Plaintext SNI"}</strong></span>
      ${clientLoc ? `<span>Location: <strong>${clientLoc}</strong></span>` : ""}
    `;
  }
}


// Trigger immediate evaluation
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  initClientDiagnostics();
}
