// SIH-2026/script.js
let mapInstance = null;
let mapMarker = null;

// Initialize the Leaflet Map
function initMap() {
  if (!mapInstance) {
    // Default view: global centered
    mapInstance = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; OpenStreetMap &copy; CARTO',
      maxZoom: 18
    }).addTo(mapInstance);
  }
}

// Update Map with Latitude & Longitude from IP OSINT
function updateMapLocation(lat, lon, label) {
  initMap();
  if (lat && lon) {
    if (mapMarker) {
      mapInstance.removeLayer(mapMarker);
    }
    mapInstance.setView([lat, lon], 9);
    mapMarker = L.marker([lat, lon])
      .addTo(mapInstance)
      .bindPopup(`<b>${label}</b><br>Lat: ${lat}, Lon: ${lon}`)
      .openPopup();
    mapInstance.invalidateSize();
  }
}

// Setup WebSocket Connection
const WS_URL = "wss://sih-2026-qzr1.onrender.com/ws";
const statusBadge = document.getElementById("connection-status");
const ws = new WebSocket(WS_URL);

ws.onopen = () => {
  statusBadge.textContent = "SOC WebSocket Connected";
  statusBadge.className = "px-3 py-1 text-xs font-mono rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
  initMap();
};

ws.onclose = () => {
  statusBadge.textContent = "Disconnected (Retrying...)";
  statusBadge.className = "px-3 py-1 text-xs font-mono rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20";
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  document.getElementById("empty-state").classList.add("hidden");
  document.getElementById("report-view").classList.remove("hidden");

  // 1. Timestamps & Basic Headers
  document.getElementById("scan-timestamp").textContent = `Scanned at ${data.timestamp}`;
  document.getElementById("email-subject").textContent = data.summary.subject || "(No Subject)";
  document.getElementById("email-sender").textContent = data.summary.sender || "Unknown Sender";

  // 2. Risk Score & Badge
  const score = data.summary.risk_score;
  const scoreEl = document.getElementById("risk-score");
  const badgeEl = document.getElementById("risk-badge");
  scoreEl.textContent = score;

  if (score >= 70) {
    scoreEl.className = "text-5xl font-black font-mono text-rose-500";
    badgeEl.textContent = "CRITICAL RISK";
    badgeEl.className = "inline-block text-xs font-semibold px-2.5 py-1 rounded bg-rose-950 text-rose-300 border border-rose-800";
  } else if (score >= 35) {
    scoreEl.className = "text-5xl font-black font-mono text-amber-400";
    badgeEl.textContent = "SUSPICIOUS";
    badgeEl.className = "inline-block text-xs font-semibold px-2.5 py-1 rounded bg-amber-950 text-amber-300 border border-amber-800";
  } else {
    scoreEl.className = "text-5xl font-black font-mono text-emerald-400";
    badgeEl.textContent = "SAFE / CLEAN";
    badgeEl.className = "inline-block text-xs font-semibold px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-800";
  }

  // 3. Authentication Status Badges
  const renderAuth = (elementId, value) => {
    const el = document.getElementById(elementId);
    const pass = (value || "").toLowerCase() === "pass";
    el.textContent = pass ? "PASS" : "FAIL";
    el.className = `font-bold text-xs mt-1 ${pass ? "text-emerald-400" : "text-rose-400"}`;
  };
  renderAuth("auth-spf", data.authentication.spf);
  renderAuth("auth-dkim", data.authentication.dkim);
  renderAuth("auth-dmarc", data.authentication.dmarc);

  // 4. Groq NLP Semantic Insights
  const nlp = data.intelligence.nlp || {};
  document.getElementById("bec-score").textContent = `BEC Risk: ${nlp.overall_bec_risk || 0}/100`;

  const urgencyEl = document.getElementById("ai-urgency");
  urgencyEl.textContent = nlp.urgency_flag ? "TRUE (Urgency Pressure)" : "FALSE (Normal)";
  urgencyEl.className = `font-bold mt-1 ${nlp.urgency_flag ? "text-rose-400" : "text-slate-400"}`;

  const financialEl = document.getElementById("ai-financial");
  financialEl.textContent = nlp.financial_request ? "TRUE (Payment / Transfer)" : "FALSE (Normal)";
  financialEl.className = `font-bold mt-1 ${nlp.financial_request ? "text-rose-400" : "text-slate-400"}`;

  const phraseList = document.getElementById("flagged-phrases-list");
  phraseList.innerHTML = "";
  if (nlp.suspicious_phrases && nlp.suspicious_phrases.length > 0) {
    nlp.suspicious_phrases.forEach((phrase) => {
      const li = document.createElement("li");
      li.className = "bg-rose-950/40 border border-rose-900/60 p-2 rounded";
      li.textContent = `• "${phrase}"`;
      phraseList.appendChild(li);
    });
  } else {
    phraseList.innerHTML = `<li class="italic text-slate-500">None (Clean body text)</li>`;
  }

  // 5. Score Logic Breakdown List
  const logicList = document.getElementById("score-logic-list");
  logicList.innerHTML = "";
  const addLogic = (text, impactClass = "text-rose-400") => {
    const li = document.createElement("li");
    li.className = "flex justify-between items-center py-1 border-b border-slate-800/40";
    li.innerHTML = `<span>${text}</span>`;
    logicList.appendChild(li);
  };

  if (data.authentication.spf !== "pass") addLogic("+20 (SPF Authentication Failed)");
  if (data.authentication.dkim !== "pass") addLogic("+20 (DKIM Verification Failed)");
  if (data.authentication.dmarc !== "pass") addLogic("+25 (DMARC Verification Failed)");
  if (data.intelligence.ip?.is_hosting_provider) addLogic("+15 (Origin is Datacenter / Cloud IP)");
  if (data.intelligence.ip?.is_proxy_or_vpn) addLogic("+10 (Origin is VPN / Anonymous Proxy)");
  if (nlp.overall_bec_risk > 0) addLogic(`+${Math.round(nlp.overall_bec_risk * 0.4)} (Groq NLP BEC Risk Weight)`);
  if (nlp.financial_request) addLogic("+15 (Groq NLP: Payment Diversion Request)");

  if (logicList.children.length === 0) {
    logicList.innerHTML = `<li class="text-emerald-400 py-1">+0 (All checks passed. Trusted infrastructure & clean body)</li>`;
  }

  // 6. Map & Geolocation OSINT
  const ipInfo = data.intelligence.ip || {};
  const originIP = data.routing.origin_ip;
  document.getElementById("map-ip-label").textContent = `${originIP} (${ipInfo.city || ""}, ${ipInfo.country || ""})`;
  document.getElementById("origin-location").textContent = `${ipInfo.city || "Unknown"}, ${ipInfo.country || "Unknown"}`;
  document.getElementById("origin-isp").textContent = ipInfo.isp || "Unknown";
  document.getElementById("infra-hosting").textContent = ipInfo.is_hosting_provider ? "TRUE (Cloud Host)" : "FALSE";
  document.getElementById("infra-proxy").textContent = ipInfo.is_proxy_or_vpn ? "TRUE (Proxy/VPN)" : "FALSE";

  if (ipInfo.lat && ipInfo.lon) {
    updateMapLocation(ipInfo.lat, ipInfo.lon, `${originIP} - ${ipInfo.city}`);
  }

  // 7. Hop-by-Hop Relay Chain Table
  const relayBody = document.getElementById("relay-table-body");
  relayBody.innerHTML = "";
  if (data.routing.relay_chain) {
    data.routing.relay_chain.forEach((hop) => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-800/40";
      tr.innerHTML = `
        <td class="px-4 py-2.5 text-slate-400">#${hop.hop}</td>
        <td class="px-4 py-2.5 text-emerald-400/90">${hop.from_server}</td>
        <td class="px-4 py-2.5 text-cyan-400/90">${hop.by_server}</td>
        <td class="px-4 py-2.5 text-slate-300 font-mono">${hop.ip}</td>
      `;
      relayBody.appendChild(tr);
    });
  }
};
