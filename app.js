
// ===== Estado global/UI =====
const $ = (sel) => document.querySelector(sel);
const logEl = $("#log");
const dnsEl = $("#dnsResults");
const rdapEl = $("#rdapResults");
const summaryEl = $("#summary");
const extraEl = $("#extraResults");
const obsEl = $("#obsResults");
const btn = $("#scanBtn");
const dnsBtn = $("#dnsBtn");
const input = $("#domain");
const fastModeEl = $("#fastMode");

let dnsMode = "auto"; // auto (race), google, cloudflare

// Heurística de móvil: ajustar timeouts si red es lenta
let DEFAULT_TIMEOUT = 9000;
if (navigator.connection) {
  const et = navigator.connection.effectiveType || "";
  const slow = et.includes("2g") || et.includes("3g") || navigator.connection.saveData;
  if (slow) DEFAULT_TIMEOUT = 7000;
}

// ===== Log robusto (mobile/web): buffer + RAF + fragment append =====
const logBuffer = [];
let rafScheduled = false;
function flushLog() {
  if (!logBuffer.length) return;
  const frag = document.createDocumentFragment();
  for (const {level, text} of logBuffer.splice(0)) {
    const div = document.createElement("div");
    div.className = `line ${level}`;
    div.textContent = `[${new Date().toLocaleTimeString()}] ${level}: ${text}`;
    frag.appendChild(div);
  }
  logEl.appendChild(frag);
  // auto-scroll para iOS/Safari
  setTimeout(() => { logEl.scrollTop = logEl.scrollHeight; }, 0);
  rafScheduled = false;
}
function log(level, text) {
  logBuffer.push({level, text});
  if (!rafScheduled) {
    rafScheduled = true;
    requestAnimationFrame(flushLog);
  }
}

const badge = (txt, type = "info") => `<span class="badge ${type}">${txt}</span>`;
const safeText = (v) => String(v ?? "").replace(/[<>&]/g, s => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[s]));

// ===== Fetch helpers (AbortController + timeout) =====
function fetchWithTimeout(url, opts={}, ms=DEFAULT_TIMEOUT) {
  const ctrl = new AbortController();
  const signal = ctrl.signal;
  const timer = setTimeout(() => ctrl.abort(`timeout ${ms}ms`), ms);
  return fetch(url, { ...opts, signal }).finally(() => clearTimeout(timer));
}

// ===== DoH providers =====
function dohGoogle(name, type="A") {
  return fetchWithTimeout(
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
    { headers:{ "accept":"application/dns-json" }, mode:"cors", cache:"no-store" }
  ).then(r=>{
    if(!r.ok) throw new Error(`dns.google ${type} -> HTTP ${r.status}`);
    return r.json();
  });
}
function dohCloudflare(name, type="A") {
  return fetchWithTimeout(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&ct=application/dns-json`,
    { headers:{ "accept":"application/dns-json" }, mode:"cors", cache:"no-store" }
  ).then(r=>{
    if(!r.ok) throw new Error(`cloudflare-dns ${type} -> HTTP ${r.status}`);
    return r.json();
  });
}

// **RACE**: correr ambos proveedores en paralelo y tomar el primero
function dohRace(name, type="A") {
  const p1 = dohGoogle(name, type);
  const p2 = dohCloudflare(name, type);
  return Promise.race([
    p1.then(v=>({ok:true,v})).catch(e=>({ok:false,e})),
    p2.then(v=>({ok:true,v})).catch(e=>({ok:false,e}))
  ]).then(first => {
    if (first.ok) return first.v;
    return dohGoogle(name, type).catch(()=>dohCloudflare(name, type));
  });
}

async function doh(name, type="A") {
  try {
    if (dnsMode === "google") return await dohGoogle(name, type);
    if (dnsMode === "cloudflare") return await dohCloudflare(name, type);
    return await dohRace(name, type);
  } catch (e) {
    log("INFO", `DoH fallo (${type}): ${e.message}`);
    try { return await dohCloudflare(name, type); }
    catch (e2) { log("WARN", `DoH fallback también falló: ${e2.message}`); throw e; }
  }
}

function parseAnswers(obj) {
  const ans = obj?.Answer || [];
  return ans.map(a => ({ name: a.name, type: a.type, data: a.data, TTL: a.TTL }));
}

// ===== RDAP + Extras =====
function fetchJson(url) { return fetchWithTimeout(url, {mode:"cors", cache:"no-store"}).then(r=>{ if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }); }
const rdapDomain = (d) => fetchJson(`https://rdap.org/domain/${encodeURIComponent(d)}`);
const hstsPreload = (d) => fetchJson(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(d)}`);

// Observatory v2 (MDN): POST /api/v2/scan?host=domain
async function observatoryV2(domain) {
  const url = `https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(domain)}`;
  const r = await fetchWithTimeout(url, {
    method: "POST",
    mode: "cors",
    cache: "no-store",
    headers: { "accept": "application/json" }
  }, DEFAULT_TIMEOUT);
  if (!r.ok) throw new Error(`Observatory v2 HTTP ${r.status}`);
  const j = await r.json();
  return j; // { id, details_url, algorithm_version, scanned_at, grade, score, tests_* }
}

// MTA-STS / TLS-RPT / security.txt
async function fetchText(url) {
  const r = await fetchWithTimeout(url, {mode:"cors", cache:"no-store"});
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.text();
}
async function checkMtaSts(domain) {
  let txt = null;
  try {
    const r = await doh(`_mta-sts.${domain}`, "TXT");
    const ans = parseAnswers(r);
    txt = ans.map(x=>x.data.replace(/^"|"$/g,"")).join("");
  } catch(e) {}
  let policy = null;
  for (const host of [`mta-sts.${domain}`, domain]) {
    try { policy = await fetchText(`https://${host}/.well-known/mta-sts.txt`); break; } catch(_){}
  }
  return { dns: txt, policy };
}
async function checkTlsRpt(domain) {
  try {
    const r = await doh(`_smtp._tls.${domain}`, "TXT");
    const ans = parseAnswers(r);
    const val = ans.map(x=>x.data.replace(/^"|"$/g,"")).join("");
    return val || null;
  } catch(e) { return null; }
}
async function checkSecurityTxt(domain) {
  for (const host of [domain, `www.${domain}`]) {
    try { const t = await fetchText(`https://${host}/.well-known/security.txt`); return { host, text: t }; }
    catch(_){}
  }
  return null;
}

// ===== DNS checks (paralelos) =====
async function checkDNS(domain) {
  const results = {};
  const types = ["A","AAAA","NS","MX","SOA","CAA","TXT","DS"];
  const tasks = types.map(t => doh(domain, t).then(json => ({t, data: parseAnswers(json)})).catch(e => ({t, error: e.message})));
  const settled = await Promise.all(tasks);

  for (const r of settled) {
    if (r.error) { log(/A|AAAA/.test(r.t) ? "WARN":"INFO", `${r.t}: ${r.error}`); continue; }
    results[r.t] = r.data;
    const joined = r.data.map(x=>x.data).join(r.t==="MX"?" | ":", ");
    log("OK", `${r.t}: ${joined || "—"}`);
  }

  // TXT → SPF
  const txtVals = (results.TXT||[]).map(x => String(x.data).replace(/^"|"$/g,""));
  const spf = txtVals.find(v => v.toLowerCase().includes("v=spf1"));
  if (spf) {
    results.SPF = spf;
    log("OK", `SPF: ${spf}`);
    if (/\+all\b/.test(spf)) log("WARN", "SPF muy permisivo (+all)");
    if (!/(~all|-all)\b/.test(spf)) log("WARN", "SPF sin política final (~all o -all)");
  } else {
    log("WARN", "SPF: no encontrado");
  }

  // DMARC
  try {
    const d = await doh(`_dmarc.${domain}`, "TXT");
    const ans = parseAnswers(d);
    if (ans.length) {
      const val = ans.map(x => x.data.replace(/^"|"$/g, "")).join("");
      results.DMARC = val;
      const pol = /;?\s*p=(none|quarantine|reject)\s*;?/i.exec(val)?.[1]?.toLowerCase() || "none?";
      const rua = /rua=([^;]+)/i.exec(val)?.[1] || "";
      const pct = /pct=([0-9]{1,3})/i.exec(val)?.[1] || "100";
      const aspf = /aspf=([rs])/i.exec(val)?.[1] || "?";
      const adkim = /adkim=([rs])/i.exec(val)?.[1] || "?";
      log("OK", `DMARC: p=${pol}, pct=${pct}${rua ? `, rua=${rua}` : ""}, aspf=${aspf}, adkim=${adkim}`);
      if (pol === "none") log("WARN", "DMARC en p=none — considerar quarantine/reject");
    } else {
      log("WARN", "DMARC: no encontrado");
    }
  } catch (e) { log("INFO", `DMARC: ${e.message}`); }

  // DNSSEC quick
  const hasDS = (results.DS||[]).length>0;
  results.DNSSEC = hasDS;
  log(hasDS ? "OK" : "WARN", hasDS ? "DNSSEC: DS presente" : "DNSSEC: no detectado");

  return results;
}

// ===== Render helpers =====
function list(items) { return `<ul>${items.map(i => `<li>${i}</li>`).join("")}</ul>`; }

function renderDNS(domain, data) {
  const rows = [];
  const joinData = (arr) => arr?.map(x => safeText(x.data)).join("<br>") || "—";

  rows.push(`<h3>${safeText(domain)}</h3>`);
  rows.push(`<p>${
    [
      data.DNSSEC ? "DNSSEC (detectado)" : "DNSSEC (no detectado)",
      data.CAA?.length ? "CAA presente" : "CAA ausente",
      data.SPF ? "SPF" : "SPF ausente",
      data.DMARC ? "DMARC" : "DMARC ausente"
    ].map(t => badge(t, /no|ausente/i.test(t) ? "warn" : "ok")).join(" ")
  }</p>`);

  rows.push(`<h4>Registros</h4>
    <div><strong>A</strong><br><code>${joinData(data.A)}</code></div>
    <div><strong>AAAA</strong><br><code>${joinData(data.AAAA)}</code></div>
    <div><strong>NS</strong><br><code>${joinData(data.NS)}</code></div>
    <div><strong>MX</strong><br><code>${joinData(data.MX)}</code></div>
    <div><strong>SOA</strong><br><code>${joinData(data.SOA)}</code></div>
    <div><strong>CAA</strong><br><code>${joinData(data.CAA)}</code></div>
    <div><strong>TXT</strong><br><code>${joinData(data.TXT)}</code></div>
  `);

  dnsEl.innerHTML = rows.join("\n");
}

function renderRDAP(domain, rdap) {
  if (!rdap) {
    rdapEl.innerHTML = `<p>${badge("RDAP no disponible (CORS)", "info")} <a href="https://rdap.org/domain/${encodeURIComponent(domain)}" target="_blank" rel="noreferrer">Abrir RDAP</a></p>`;
    return;
  }
  const s = {};
  try {
    s.ldhName = rdap.ldhName || rdap.handle || null;
    const registrar = (rdap.entities || []).find(e => (e.roles||[]).includes("registrar"));
    s.registrar = registrar?.vcardArray?.[1]?.find(x => x[0] === "fn")?.[3] || registrar?.handle || null;
    const ev = {};
    for (const e of (rdap.events || [])) ev[e.eventAction] = e.eventDate;
    s.registered = ev.registration || ev.registered || null;
    s.expires = ev.expiration || ev.expire || null;
    s.updated = ev.lastchanged || ev.lastupdate || ev.lastchangeddate || null;
    s.nameservers = (rdap.nameservers || []).map(ns => ns.ldhName || ns.handle).filter(Boolean);
  } catch {}
  const rows = [];
  rows.push(`<div><strong>Dominio:</strong> ${safeText(s.ldhName || domain)}</div>`);
  rows.push(`<div><strong>Registrar:</strong> ${safeText(s.registrar || "—")}</div>`);
  rows.push(`<div><strong>Registrado:</strong> ${safeText(s.registered || "—")}</div>`);
  rows.push(`<div><strong>Expira:</strong> ${safeText(s.expires || "—")}</div>`);
  rows.push(`<div><strong>Actualizado:</strong> ${safeText(s.updated || "—")}</div>`);
  rows.push(`<div><strong>Nameservers:</strong><br><code>${(s.nameservers||[]).map(safeText).join("<br>") || "—"}</code></div>`);
  rdapEl.innerHTML = rows.join("\n") + `<details style="margin-top:8px;"><summary>Ver JSON RDAP</summary><code>${safeText(JSON.stringify(rdap, null, 2))}</code></details>`;
}

function renderObservatory(domain, obs) {
  if (!obs) {
    obsEl.innerHTML = `<p>${badge("Observatory no disponible (CORS o error temporal)", "info")} <a target="_blank" rel="noreferrer" href="https://developer.mozilla.org/en-US/observatory/analyze?host=${encodeURIComponent(domain)}">Abrir reporte</a></p>`;
    return;
  }
  const rows = [];
  const grade = safeText(obs.grade || "?");
  const score = typeof obs.score === "number" ? obs.score : "?";
  const tf = obs.tests_failed ?? "?";
  const tp = obs.tests_passed ?? "?";
  const tq = obs.tests_quantity ?? "?";
  const algo = obs.algorithm_version ?? "?";
  const scannedAt = obs.scanned_at ? new Date(obs.scanned_at).toLocaleString() : "—";
  const details = obs.details_url || `https://developer.mozilla.org/en-US/observatory/analyze?host=${encodeURIComponent(domain)}`;

  const type = score >= 90 ? "ok" : (score >= 60 ? "warn" : "err");
  rows.push(`<div><strong>Grade:</strong> ${badge(grade, type)} &nbsp; <strong>Score:</strong> ${badge(String(score), type)}</div>`);
  rows.push(`<div><strong>Tests:</strong> ${tp}/${tq} pasados, ${tf} fallidos</div>`);
  rows.push(`<div><strong>Algoritmo:</strong> v${safeText(String(algo))} &nbsp; <strong>Escaneado:</strong> ${safeText(scannedAt)}</div>`);
  rows.push(`<div><a target="_blank" rel="noreferrer" href="${safeText(details)}">Ver reporte completo en MDN</a></div>`);
  obsEl.innerHTML = rows.join("\n");
}

function renderExtra(domain, dnsData, hsts, mta, tlsrpt, secTxt) {
  const rows = [];
  if (hsts) {
    const st = safeText(hsts.status || "unknown");
    rows.push(`<div><strong>HSTS Preload:</strong> ${badge(st, st==="preloaded"?"ok":(st==="unknown"?"info":"warn"))}</div>`);
  } else {
    rows.push(`<div>${badge("HSTS preload no disponible", "info")} <a target="_blank" rel="noreferrer" href="https://hstspreload.org/">Ver sitio</a></div>`);
  }
  if (mta?.dns || mta?.policy) {
    rows.push(`<div><strong>MTA-STS:</strong> ${mta.dns?badge("TXT","ok"):badge("TXT ausente","warn")} ${mta.policy?badge("policy","ok"):badge("policy ausente","warn")}</div>`);
    if (mta.policy) rows.push(`<details><summary>Ver política</summary><code>${safeText(mta.policy)}</code></details>`);
  } else {
    rows.push(`<div>${badge("MTA-STS no disponible", "info")}</div>`);
  }
  if (tlsrpt) rows.push(`<div><strong>TLS-RPT:</strong> <code>${safeText(tlsrpt)}</code></div>`);
  else rows.push(`<div>${badge("TLS-RPT no encontrado", "info")}</div>`);
  if (secTxt) rows.push(`<div><strong>security.txt:</strong> en ${safeText(secTxt.host)} <details><summary>Ver</summary><code>${safeText(secTxt.text)}</code></details></div>`);
  else rows.push(`<div>${badge("security.txt no encontrado", "info")} <a target="_blank" rel="noreferrer" href="https://${safeText(domain)}/.well-known/security.txt">probar</a></div>`);
  extraEl.innerHTML = rows.join("\n");
}

function summarize(domain, dnsData, rdapOk, obs) {
  const items = [];
  if (dnsData.DNSSEC) items.push("✅ DNSSEC detectado"); else items.push("⚠️ DNSSEC no detectado");
  if (dnsData.CAA?.length) items.push("✅ CAA presente"); else items.push("⚠️ CAA ausente (recomendado)");
  if (dnsData.SPF) items.push("✅ SPF presente"); else items.push("⚠️ SPF ausente");
  if (dnsData.DMARC) {
    const pol = /p=(none|quarantine|reject)/i.exec(dnsData.DMARC)?.[1] || "none?";
    items.push(`✅ DMARC presente (p=${pol})${pol.toLowerCase()==="none"?" ⚠️ considerar quarantine/reject":""}`);
  } else items.push("⚠️ DMARC ausente");
  if (!rdapOk) items.push("ℹ️ RDAP no disponible por CORS (link manual).");
  if (obs?.grade) items.push(`🧪 Observatory: ${obs.grade} (${obs.score})`);
  summaryEl.innerHTML = list(items);
}

// ===== Controlador principal (progresivo + rápido) =====
async function runScan() {
  const domain = input.value.trim().toLowerCase();
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
    alert("Ingresá un dominio válido, ej: example.com");
    return;
  }

  btn.disabled = true; dnsBtn.disabled = true; fastModeEl.disabled = true;
  logEl.textContent = ""; dnsEl.innerHTML = ""; rdapEl.innerHTML = ""; extraEl.innerHTML = ""; summaryEl.innerHTML = ""; obsEl.innerHTML = "";
  log("INFO", `Iniciando auditoría para ${domain} (DNS ${dnsMode}, timeout ${DEFAULT_TIMEOUT}ms, modo ${fastModeEl.checked?"rápido":"completo"})`);

  try {
    // 1) DNS en paralelo
    const dnsData = await checkDNS(domain);
    renderDNS(domain, dnsData);

    // 2) RDAP en paralelo
    let rdapJson = null;
    const rdapTask = rdapDomain(domain).then(j=>{rdapJson=j; log("OK","RDAP obtenido");}).catch(e=>log("INFO",`RDAP no disponible — ${e.message}`));

    // 3) Observatory v2 (no bloqueante en modo rápido)
    const obsTask = observatoryV2(domain).then(j=>{ log("OK", `Observatory: ${j.grade} (${j.score})`); return j; })
      .catch(e=>{ log("INFO", `Observatory v2 ND — ${e.message}`); return null; });

    // 4) Extras (HSTS/MTA-STS/TLS-RPT/security.txt)
    const extraTasks = [
      hstsPreload(domain).catch(e=>{log("INFO",`HSTS preload ND — ${e.message}`); return null;}),
      checkMtaSts(domain).catch(_=>null),
      checkTlsRpt(domain).catch(_=>null),
      checkSecurityTxt(domain).catch(_=>null)
    ];

    let obsResult = null;
    let extraResults = null;

    if (fastModeEl.checked) {
      // esperar poco; render parcial si se demora
      [obsResult] = await Promise.race([
        Promise.all([obsTask]),
        new Promise(res => setTimeout(()=>res([null]), 2500))
      ]);
      renderObservatory(domain, obsResult);
      extraResults = await Promise.race([
        Promise.all(extraTasks),
        new Promise(res => setTimeout(()=>res([null,null,null,null]), 3000))
      ]);
    } else {
      obsResult = await obsTask;
      renderObservatory(domain, obsResult);
      extraResults = await Promise.all(extraTasks);
    }

    const [hsts, mta, tlsrpt, sectxt] = extraResults;
    await rdapTask;
    renderRDAP(domain, rdapJson); // puede ser null (CORS)
    renderExtra(domain, dnsData, hsts, mta, tlsrpt, sectxt);
    summarize(domain, dnsData, !!rdapJson, obsResult);

    log("INFO", "Listo. Fuentes: DoH, RDAP, HSTS, Observatory v2, MTA-STS/TLS-RPT, security.txt.");
  } catch (e) {
    log("ERROR", e.message || String(e));
  } finally {
    btn.disabled = false; dnsBtn.disabled = false; fastModeEl.disabled = false;
  }
}

btn.addEventListener("click", runScan);
input.addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });

dnsBtn.addEventListener("click", () => {
  if (dnsMode === "auto") { dnsMode = "google"; dnsBtn.textContent = "DNS: Google"; }
  else if (dnsMode === "google") { dnsMode = "cloudflare"; dnsBtn.textContent = "DNS: Cloudflare"; }
  else { dnsMode = "auto"; dnsBtn.textContent = "DNS: Auto (race)"; }
  log("INFO", `Proveedor DoH cambiado a: ${dnsMode}`);
});
