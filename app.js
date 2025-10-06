
// ===== Estado global/UI =====
const $ = (sel) => document.querySelector(sel);
const logEl = $("#log");
const dnsEl = $("#dnsResults");
const rdapEl = $("#rdapResults");
const summaryEl = $("#summary");
const obsEl = $("#obsResults");
const hstsEl = $("#hstsResults");
const emailEl = $("#emailSecResults");
const secTxtEl = $("#secTxtResults");
const infraEl = $("#infraResults");
const btn = $("#scanBtn");
const dnsBtn = $("#dnsBtn");
const input = $("#domain");
const fastModeEl = $("#fastMode");

let dnsMode = "auto"; // auto (race), google, cloudflare, quad9, dnssb

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
const dohProviders = {
  google: (name, type="A") =>
    fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      { headers:{ "accept":"application/dns-json" }, mode:"cors", cache:"no-store" })
      .then(r=>{ if(!r.ok) throw new Error(`dns.google ${type} -> HTTP ${r.status}`); return r.json(); }),

  cloudflare: (name, type="A") =>
    fetchWithTimeout(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&ct=application/dns-json`,
      { headers:{ "accept":"application/dns-json" }, mode:"cors", cache:"no-store" })
      .then(r=>{ if(!r.ok) throw new Error(`cloudflare-dns ${type} -> HTTP ${r.status}`); return r.json(); }),

  quad9: (name, type="A") =>
    fetchWithTimeout(`https://dns.quad9.net/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&ct=application/dns-json`,
      { headers:{ "accept":"application/dns-json" }, mode:"cors", cache:"no-store" })
      .then(r=>{ if(!r.ok) throw new Error(`quad9 ${type} -> HTTP ${r.status}`); return r.json(); }),

  dnssb: (name, type="A") =>
    fetchWithTimeout(`https://doh.dns.sb/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&ct=application/dns-json`,
      { headers:{ "accept":"application/dns-json" }, mode:"cors", cache:"no-store" })
      .then(r=>{ if(!r.ok) throw new Error(`dns.sb ${type} -> HTTP ${r.status}`); return r.json(); }),
};

function dohRace(name, type="A", providers=["google","cloudflare","quad9","dnssb"]) {
  const racers = providers.map(p =>
    dohProviders[p](name, type).then(v=>({ok:true,v, p})).catch(e=>({ok:false,e, p}))
  );
  return Promise.race(racers).then(first => {
    if (first.ok) { log("INFO", `DoH respondió primero: ${first.p}`); return first.v; }
    for (const p of providers) { return dohProviders[p](name, type).catch(()=>{}); }
  });
}

async function doh(name, type="A") {
  try {
    if (dnsMode in dohProviders) return await dohProviders[dnsMode](name, type);
    return await dohRace(name, type);
  } catch (e) {
    for (const p of ["google","cloudflare","quad9","dnssb"]) {
      try { return await dohProviders[p](name, type); } catch(_){}
    }
    log("WARN", `DoH total fail (${type}): ${e.message}`);
    throw e;
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

// Observatory v2 (MDN) con robustez: POST preferente; si falla por CORS/5xx, intento GET
async function observatoryV2(domain) {
  const url = `https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(domain)}`;
  try {
    const r = await fetchWithTimeout(url, { method: "POST", mode: "cors", cache: "no-store", headers: { "accept": "application/json" } });
    if (!r.ok) throw new Error(`Observatory v2 HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    log("INFO", `Observatory POST falló (${e.message}). Intento GET (cache)…`);
    try {
      const r2 = await fetchWithTimeout(url, { method: "GET", mode: "cors", cache: "no-store", headers: { "accept": "application/json" } });
      if (!r2.ok) throw new Error(`Observatory v2 GET HTTP ${r2.status}`);
      return await r2.json();
    } catch (e2) {
      log("WARN", `Observatory GET falló (${e2.message}). Mostrando enlace al reporte.`);
      return null;
    }
  }
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
  let policy = null, policyUrl = null;
  for (const host of [`mta-sts.${domain}`, domain]) {
    try { policyUrl = `https://${host}/.well-known/mta-sts.txt`; policy = await fetchText(policyUrl); break; } catch(_){}
  }
  return { dns: txt, policy, policyUrl };
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
    try { const url = `https://${host}/.well-known/security.txt`; const t = await fetchText(url); return { host, text: t, url }; }
    catch(_){}
  }
  return null;
}

// Infra (ipwho.is) para la primera IPv4 A
async function fetchInfraFromA(dnsData) {
  const firstA = dnsData?.A?.find(x => /^\d+\.\d+\.\d+\.\d+$/.test(x.data))?.data;
  if (!firstA) return null;
  try {
    const j = await fetchJson(`https://ipwho.is/${encodeURIComponent(firstA)}`);
    return { ip: firstA, data: j };
  } catch(e) { return { ip: firstA, error: e.message }; }
}

// ===== DNS checks (paralelos) con fallback por proveedor =====
async function queryTypeWithFallback(domain, type) {
  try {
    return parseAnswers(await doh(domain, type));
  } catch (_) {
    for (const p of ["google","cloudflare","quad9","dnssb"]) {
      try { return parseAnswers(await dohProviders[p](domain, type)); } catch(__){}
    }
    return [];
  }
}

async function checkDNS(domain) {
  const results = {};
  const types = ["A","AAAA","NS","MX","SOA","CAA","TXT","DS"];
  const tasks = types.map(async (t) => {
    const data = await queryTypeWithFallback(domain, t);
    if (data.length) log("OK", `${t}: ${data.map(x=>x.data).join(t==="MX"?" | ":", ")}`);
    else log("INFO", `${t}: sin datos (posible bloqueo/CORS)`);
    return { t, data };
  });
  const settled = await Promise.all(tasks);
  for (const r of settled) results[r.t] = r.data;

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

  try {
    const d = await queryTypeWithFallback(`_dmarc.${domain}`, "TXT");
    if (d.length) {
      const val = d.map(x => x.data.replace(/^"|"$/g, "")).join("");
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
    obsEl.innerHTML = `<p>${badge("Observatory no disponible (CORS/limits)", "info")} <a target="_blank" rel="noreferrer" href="https://developer.mozilla.org/en-US/observatory/analyze?host=${encodeURIComponent(domain)}">Abrir reporte</a></p>`;
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

function renderHSTS(domain, hsts) {
  if (!hsts) {
    hstsEl.innerHTML = `<p>${badge("No disponible", "info")} <a target="_blank" rel="noreferrer" href="https://hstspreload.org/?domain=${encodeURIComponent(domain)}">Abrir HSTS Preload</a></p>`;
    return;
  }
  const st = safeText(hsts.status || "unknown");
  const type = st==="preloaded" ? "ok" : (st==="unknown" ? "info" : "warn");
  const rows = [];
  rows.push(`<div><strong>Estado:</strong> ${badge(st, type)}</div>`);
  if (Array.isArray(hsts.errors) && hsts.errors.length) {
    rows.push(`<details><summary>Errores</summary><code>${safeText(hsts.errors.join("\\n"))}</code></details>`);
  }
  rows.push(`<div><a target="_blank" rel="noreferrer" href="https://hstspreload.org/?domain=${encodeURIComponent(domain)}">Ver detalle</a></div>`);
  hstsEl.innerHTML = rows.join("\n");
}

function renderEmailSec(domain, mta, tlsrpt) {
  const rows = [];
  // MTA-STS
  const mtaTxt = mta?.dns ? badge("TXT", "ok") : badge("TXT ausente", "warn");
  const mtaPol = mta?.policy ? badge("policy", "ok") : badge("policy ausente", "warn");
  rows.push(`<div><strong>MTA-STS:</strong> ${mtaTxt} ${mtaPol}${mta?.policyUrl?` — <a target="_blank" rel="noreferrer" href="${safeText(mta.policyUrl)}">ver policy</a>`:""}</div>`);
  if (mta?.policy) {
    const mode = /mode\s*:\s*(enforce|testing|none)/i.exec(mta.policy)?.[1] || "?";
    const mx = /mx\s*:\s*([^\n]+)/i.exec(mta.policy)?.[1] || "?";
    const maxAge = /max_age\s*:\s*(\d+)/i.exec(mta.policy)?.[1] || "?";
    rows.push(`<div>Modo: <code>${safeText(mode)}</code> · MX: <code>${safeText(mx)}</code> · max_age: <code>${safeText(maxAge)}</code></div>`);
  }
  // TLS-RPT
  if (tlsrpt) {
    const rua = /rua=mailto:([^;]+)/i.exec(tlsrpt)?.[1] || "?";
    rows.push(`<div><strong>TLS-RPT:</strong> ${badge("TXT", "ok")} · Reportes a: <code>${safeText(rua)}</code></div>`);
  } else {
    rows.push(`<div><strong>TLS-RPT:</strong> ${badge("no encontrado","info")}</div>`);
  }
  emailEl.innerHTML = rows.join("\n");
}

function renderSecurityTxt(domain, sec) {
  if (!sec) {
    secTxtEl.innerHTML = `<p>${badge("No encontrado", "info")} <a target="_blank" rel="noreferrer" href="https://${safeText(domain)}/.well-known/security.txt">probar</a></p>`;
    return;
  }
  const rows = [];
  rows.push(`<div>Host: <code>${safeText(sec.host)}</code> — <a target="_blank" rel="noreferrer" href="${safeText(sec.url)}">ver archivo</a></div>`);
  // parse campos interesantes (Contact, Expires, Policy, Acknowledgments)
  const contact = (sec.text.match(/^Contact:\s*(.+)$/gmi)||[]).map(x=>x.split(":").slice(1).join(":").trim());
  const policy = (sec.text.match(/^Policy:\s*(.+)$/gmi)||[]).map(x=>x.split(":").slice(1).join(":").trim());
  const expires = (sec.text.match(/^Expires:\s*(.+)$/gmi)||[]).map(x=>x.split(":").slice(1).join(":").trim());
  if (contact.length) rows.push(`<div>Contact: ${contact.map(x=>`<code>${safeText(x)}</code>`).join(", ")}</div>`);
  if (policy.length) rows.push(`<div>Policy: ${policy.map(x=>`<a target="_blank" rel="noreferrer" href="${safeText(x)}">link</a>`).join(", ")}</div>`);
  if (expires.length) rows.push(`<div>Expires: ${expires.map(x=>`<code>${safeText(x)}</code>`).join(", ")}</div>`);
  secTxtEl.innerHTML = rows.join("\n") + `<details style="margin-top:8px;"><summary>Ver contenido</summary><code>${safeText(sec.text)}</code></details>`;
}

function renderInfra(domain, infra) {
  if (!infra) {
    infraEl.innerHTML = `<p>${badge("Sin datos (no hay A IPv4)", "info")}</p>`;
    return;
  }
  if (infra.error) {
    infraEl.innerHTML = `<p>${badge("No disponible", "info")} (ipwho.is) · IP: <code>${safeText(infra.ip)}</code></p>`;
    return;
  }
  const j = infra.data || {};
  const rows = [];
  rows.push(`<div>IP: <code>${safeText(infra.ip)}</code> · País: <code>${safeText(j.country || "?")}</code> · Ciudad: <code>${safeText(j.city || "?")}</code></div>`);
  rows.push(`<div>ASN: <code>${safeText(j.connection?.asn || "?")}</code> · Org: <code>${safeText(j.connection?.org || "?")}</code> · ISP: <code>${safeText(j.connection?.isp || "?")}</code></div>`);
  rows.push(`<div><a target="_blank" rel="noreferrer" href="https://ipwho.is/${encodeURIComponent(infra.ip)}">Ver detalle ipwho.is</a></div>`);
  infraEl.innerHTML = rows.join("\n");
}

function summarize(domain, dnsData, rdapOk, obs, hsts, mta, tlsrpt, sec) {
  const items = [];
  if (dnsData.DNSSEC) items.push("✅ DNSSEC detectado"); else items.push("⚠️ DNSSEC no detectado");
  if (dnsData.CAA?.length) items.push("✅ CAA presente"); else items.push("⚠️ CAA ausente (recomendado)");
  if (dnsData.SPF) items.push("✅ SPF presente"); else items.push("⚠️ SPF ausente");
  if (dnsData.DMARC) {
    const pol = /p=(none|quarantine|reject)/i.exec(dnsData.DMARC)?.[1] || "none?";
    items.push(`✅ DMARC presente (p=${pol})${pol.toLowerCase()==="none"?" ⚠️ considerar quarantine/reject":""}`);
  } else items.push("⚠️ DMARC ausente");
  if (hsts?.status) items.push(`🌐 HSTS preload: ${hsts.status}`);
  if (mta?.policy || mta?.dns) items.push("✉️ MTA-STS presente");
  if (tlsrpt) items.push("📊 TLS-RPT presente");
  if (sec) items.push("🛡️ security.txt presente");
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

  btn.disabled = true; dnsBtn.disabled = true; fastModeEl.disabled = false;
  logEl.textContent = ""; dnsEl.innerHTML = ""; rdapEl.innerHTML = ""; summaryEl.innerHTML = "";
  obsEl.innerHTML = ""; hstsEl.innerHTML = ""; emailEl.innerHTML = ""; secTxtEl.innerHTML = ""; infraEl.innerHTML = "";
  log("INFO", `Iniciando auditoría para ${domain} (DNS ${dnsMode}, timeout ${DEFAULT_TIMEOUT}ms, modo ${fastModeEl.checked?"rápido":"completo"})`);

  try {
    // 1) DNS
    const dnsData = await checkDNS(domain);
    renderDNS(domain, dnsData);

    // 2) Infra (depende de A)
    const infraTask = fetchInfraFromA(dnsData).then(x=>{ renderInfra(domain, x); return x; });

    // 3) RDAP
    let rdapJson = null;
    const rdapTask = rdapDomain(domain).then(j=>{rdapJson=j; log("OK","RDAP obtenido");}).catch(e=>log("INFO",`RDAP no disponible — ${e.message}`));

    // 4) Observatory
    const obsTask = observatoryV2(domain).then(j=>{ if(j){ log("OK", `Observatory: ${j.grade} (${j.score})`);} renderObservatory(domain, j); return j; })
      .catch(e=>{ log("INFO", `Observatory v2 ND — ${e.message}`); renderObservatory(domain, null); return null; });

    // 5) HSTS / EmailSec / security.txt
    const hstsTask = hstsPreload(domain).then(j=>{ renderHSTS(domain, j); return j; }).catch(_=>{ renderHSTS(domain, null); return null; });
    const mtaTask = checkMtaSts(domain).then(j=>{ return j; }).catch(_=>null);
    const tlsTask = checkTlsRpt(domain).then(j=>{ return j; }).catch(_=>null);
    const secTask = checkSecurityTxt(domain).then(j=>{ renderSecurityTxt(domain, j); return j; }).catch(_=>{ renderSecurityTxt(domain, null); return null; });

    let obsResult, hstsResult, mtaResult, tlsResult, secResult;
    if (fastModeEl.checked) {
      // Mostrar rápido Observatory y HSTS si llegan, sin bloquear
      [obsResult] = await Promise.race([Promise.all([obsTask]), new Promise(res=>setTimeout(()=>res([null]), 2500))]);
      [hstsResult] = await Promise.race([Promise.all([hstsTask]), new Promise(res=>setTimeout(()=>res([null]), 2000))]);
      [mtaResult, tlsResult, secResult] = await Promise.race([
        Promise.all([mtaTask, tlsTask, secTask]), new Promise(res=>setTimeout(()=>res([null,null,null]), 2500))
      ]);
    } else {
      obsResult = await obsTask;
      hstsResult = await hstsTask;
      mtaResult = await mtaTask;
      tlsResult = await tlsTask;
      secResult = await secTask;
    }
    renderEmailSec(domain, mtaResult, tlsResult);

    await rdapTask;
    renderRDAP(domain, rdapJson);

    const infraResult = await infraTask;

    summarize(domain, dnsData, !!rdapJson, obsResult, hstsResult, mtaResult, tlsResult, secResult);

    log("INFO", "Listo. Fuentes: DoH (Google/Cloudflare/Quad9/DNS.SB), RDAP, Observatory v2, HSTS preload, MTA-STS/TLS-RPT, security.txt, ipwho.is.");
  } catch (e) {
    log("ERROR", e.message || String(e));
  } finally {
    btn.disabled = false; dnsBtn.disabled = false; fastModeEl.disabled = false;
  }
}

btn.addEventListener("click", runScan);
input.addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });

dnsBtn.addEventListener("click", () => {
  const order = ["auto","google","cloudflare","quad9","dnssb"];
  const i = order.indexOf(dnsMode);
  const next = order[(i+1)%order.length];
  dnsMode = next;
  const label = next==="auto" ? "DNS: Auto (race)" : `DNS: ${next[0].toUpperCase()+next.slice(1)}`;
  dnsBtn.textContent = label;
  log("INFO", `Proveedor DoH cambiado a: ${dnsMode}`);
});
