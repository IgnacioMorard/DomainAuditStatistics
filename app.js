
// ===== Estado global/UI =====
const $ = (sel) => document.querySelector(sel);
const logEl = $("#log");
const dnsEl = $("#dnsResults");
const rdapEl = $("#rdapResults");
const summaryEl = $("#summary");
const obsEl = $("#obsResults");
const emailEl = $("#emailSecResults");
const secTxtEl = $("#secTxtResults");
const mxtLinksEl = $("#mxtLinks");
const btn = $("#scanBtn");
const dnsBtn = $("#dnsBtn");
const input = $("#domain");
const fastModeEl = $("#fastMode");
const directDnsEl = $("#directDNS");

let dnsMode = "auto"; // auto (race), google, cloudflare, quad9, dnssb

// Heurística de móvil: ajustar timeouts si red es lenta
let DEFAULT_TIMEOUT = 9000;
if (navigator.connection) {
  const et = navigator.connection.effectiveType || "";
  const slow = et.includes("2g") || et.includes("3g") || navigator.connection.saveData;
  if (slow) DEFAULT_TIMEOUT = 7000;
}

// ===== Log buffer =====
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
  if (!rafScheduled) { rafScheduled = true; requestAnimationFrame(flushLog); }
}

const badge = (txt, type = "info") => `<span class="badge ${type}">${txt}</span>`;
const safeText = (v) => String(v ?? "").replace(/[<>&]/g, s => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[s]));

// ===== Fetch helpers =====
function fetchWithTimeout(url, opts={}, ms=DEFAULT_TIMEOUT) {
  const ctrl = new AbortController();
  const signal = ctrl.signal;
  const timer = setTimeout(() => ctrl.abort(`timeout ${ms}ms`), ms);
  return fetch(url, { ...opts, signal }).finally(() => clearTimeout(timer));
}

// ===== DoH providers (para modo "Consultar DoH directo") =====
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
function parseAnswers(obj) { const ans = obj?.Answer || []; return ans.map(a => ({ name: a.name, type: a.type, data: a.data, TTL: a.TTL })); }

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
    throw e;
  }
}

// ===== RDAP / Observatory / EmailSec / security.txt =====
function fetchJson(url) { return fetchWithTimeout(url, {mode:"cors", cache:"no-store"}).then(r=>{ if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }); }
const rdapDomain = (d) => fetchJson(`https://rdap.org/domain/${encodeURIComponent(d)}`);
async function observatoryV2(domain) {
  const url = `https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(domain)}`;
  try {
    const r = await fetchWithTimeout(url, { method: "POST", mode: "cors", cache: "no-store", headers: { "accept": "application/json" } });
    if (!r.ok) throw new Error(`Observatory v2 HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    try {
      const r2 = await fetchWithTimeout(url, { method: "GET", mode: "cors", cache: "no-store", headers: { "accept": "application/json" } });
      if (!r2.ok) throw new Error(`Observatory v2 GET HTTP ${r2.status}`);
      return await r2.json();
    } catch (e2) { return null; }
  }
}
async function fetchText(url) {
  const r = await fetchWithTimeout(url, {mode:"cors", cache:"no-store"});
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.text();
}
async function checkMtaSts(domain) {
  // TXT via DoH si el usuario lo habilita
  let txt = null, policy = null, policyUrl = null;
  if (directDnsEl.checked) {
    try {
      const r = await doh(`_mta-sts.${domain}`, "TXT");
      const ans = parseAnswers(r);
      txt = ans.map(x=>x.data.replace(/^"|"$/g,"")).join("");
    } catch(e) {}
  }
  for (const host of [`mta-sts.${domain}`, domain]) {
    try { policyUrl = `https://${host}/.well-known/mta-sts.txt`; policy = await fetchText(policyUrl); break; } catch(_){}
  }
  return { dns: txt, policy, policyUrl };
}
async function checkTlsRpt(domain) {
  if (!directDnsEl.checked) return null;
  try {
    const r = await doh(`_smtp._tls.${domain}`, "TXT");
    const ans = parseAnswers(r);
    const val = ans.map(x=>x.data.replace(/^"|"$/g,"")).join("");
    return val || null;
  } catch(e) { return null; }
}
async function checkSecurityTxt(domain) {
  // 1) try fetch (CORS)
  for (const host of [domain, `www.${domain}`]) {
    const url = `https://${host}/.well-known/security.txt`;
    try {
      const t = await fetchText(url);
      return { host, text: t, url, rendered: null };
    } catch(e) {
      // 2) fallback: <object> embebido (no necesitamos CORS para mostrar)
      const rendered = `<object data="${url}" type="text/plain" style="width:100%;min-height:160px;border:1px solid var(--border);border-radius:8px;"></object>`;
      return { host, text: null, url, rendered };
    }
  }
  return null;
}

// ===== DNS (opcional) =====
async function queryType(domain, type) {
  try { return parseAnswers(await doh(domain, type)); }
  catch (_) { return []; }
}
async function checkDNS(domain) {
  const res = {};
  if (!directDnsEl.checked) {
    log("INFO", "Consulta DoH deshabilitada; usá los enlaces de MXToolbox para ver registros.");
    return res;
  }
  const types = ["A","AAAA","NS","MX","SOA","CAA","TXT","DS"];
  const tasks = types.map(async (t) => {
    const data = await queryType(domain, t);
    if (data.length) log("OK", `${t}: ${data.map(x=>x.data).join(t==="MX"?" | ":", ")}`);
    else log("INFO", `${t}: sin datos (bloqueo/CORS)`);
    return { t, data };
  });
  const settled = await Promise.all(tasks);
  for (const r of settled) res[r.t] = r.data;

  const txtVals = (res.TXT||[]).map(x => String(x.data).replace(/^"|"$/g,""));
  const spf = txtVals.find(v => v.toLowerCase().includes("v=spf1"));
  if (spf) { res.SPF = spf; }
  try {
    const d = await queryType(`_dmarc.${domain}`, "TXT");
    if (d.length) res.DMARC = d.map(x => x.data.replace(/^"|"$/g, "")).join("");
  } catch(_){}
  res.DNSSEC = (res.DS||[]).length>0;
  return res;
}

// ===== Render =====
function list(items) { return `<ul>${items.map(i => `<li>${i}</li>`).join("")}</ul>`; }
function renderDNS(domain, data) {
  const joinData = (arr) => arr?.map(x => safeText(x.data)).join("<br>") || "—";
  if (Object.keys(data).length===0) {
    dnsEl.innerHTML = `<p>${badge("DoH deshabilitado", "info")} Activá “Consultar DoH directo” o usá los enlaces de MXToolbox de abajo.</p>`;
  } else {
    dnsEl.innerHTML = `
      <h3>${safeText(domain)}</h3>
      <p>${
        [
          data.DNSSEC ? "DNSSEC (detectado)" : "DNSSEC (no detectado)",
          data.CAA?.length ? "CAA presente" : "CAA ausente",
          data.SPF ? "SPF" : "SPF ausente",
          data.DMARC ? "DMARC" : "DMARC ausente"
        ].map(t => badge(t, /no|ausente/i.test(t) ? "warn" : "ok")).join(" ")
      }</p>
      <h4>Registros</h4>
      <div><strong>A</strong><br><code>${joinData(data.A)}</code></div>
      <div><strong>AAAA</strong><br><code>${joinData(data.AAAA)}</code></div>
      <div><strong>NS</strong><br><code>${joinData(data.NS)}</code></div>
      <div><strong>MX</strong><br><code>${joinData(data.MX)}</code></div>
      <div><strong>SOA</strong><br><code>${joinData(data.SOA)}</code></div>
      <div><strong>CAA</strong><br><code>${joinData(data.CAA)}</code></div>
      <div><strong>TXT</strong><br><code>${joinData(data.TXT)}</code></div>
    `;
  }

  // Enlaces MXToolbox
  const enc = encodeURIComponent(domain);
  const links = [
    ["A", `https://mxtoolbox.com/SuperTool.aspx?action=a%3a${enc}&run=toolpage`],
    ["AAAA", `https://mxtoolbox.com/SuperTool.aspx?action=aaaa%3a${enc}&run=toolpage`],
    ["NS", `https://mxtoolbox.com/SuperTool.aspx?action=ns%3a${enc}&run=toolpage`],
    ["MX", `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${enc}&run=toolpage`],
    ["SOA", `https://mxtoolbox.com/SuperTool.aspx?action=soa%3a${enc}&run=toolpage`],
    ["CAA", `https://mxtoolbox.com/SuperTool.aspx?action=caa%3a${enc}&run=toolpage`],
    ["TXT", `https://mxtoolbox.com/SuperTool.aspx?action=txt%3a${enc}&run=toolpage`],
    ["DMARC", `https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a${enc}&run=toolpage`],
    ["SPF", `https://mxtoolbox.com/SuperTool.aspx?action=spf%3a${enc}&run=toolpage`],
    ["DNSSEC", `https://mxtoolbox.com/SuperTool.aspx?action=dnssec%3a${enc}&run=toolpage`],
  ];
  mxtLinksEl.innerHTML = `<h4>Abrir en MXToolbox</h4>
    <ul>${links.map(([k,u])=>`<li><a target="_blank" rel="noreferrer" href="${u}">${k}</a></li>`).join("")}</ul>`;
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
    obsEl.innerHTML = `<p>${badge("Observatory no disponible (CORS/limits)", "info")} <a target="_blank" rel="noreferrer" href="https://developer.mozilla.org/en-US/observatory/analyze?host=${encodeURIComponent(domain)}">Ver reporte</a></p>`;
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
  rows.push(`<div><a target="_blank" rel="noreferrer" href="${safeText(details)}">Reporte completo MDN</a></div>`);
  obsEl.innerHTML = rows.join("\n");
}

function renderEmailSec(domain, mta, tlsrpt) {
  const rows = [];
  const mtaTxt = mta?.dns ? badge("TXT", "ok") : badge("TXT ausente", "warn");
  const mtaPol = mta?.policy ? badge("policy", "ok") : badge("policy ausente", "warn");
  rows.push(`<div><strong>MTA-STS:</strong> ${mtaTxt} ${mtaPol}${mta?.policyUrl?` — <a target="_blank" rel="noreferrer" href="${safeText(mta.policyUrl)}">ver policy</a>`:""}</div>`);
  if (mta?.policy) {
    const mode = /mode\s*:\s*(enforce|testing|none)/i.exec(mta.policy)?.[1] || "?";
    const mx = /mx\s*:\s*([^\n]+)/i.exec(mta.policy)?.[1] || "?";
    const maxAge = /max_age\s*:\s*(\d+)/i.exec(mta.policy)?.[1] || "?";
    rows.push(`<div>Modo: <code>${safeText(mode)}</code> · MX: <code>${safeText(mx)}</code> · max_age: <code>${safeText(maxAge)}</code></div>`);
  }
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
    secTxtEl.innerHTML = `<p>${badge("No encontrado", "info")} <a target="_blank" rel="noreferrer" href="https://${safeText(domain)}/.well-known/security.txt">abrir</a></p>`;
    return;
  }
  const rows = [];
  rows.push(`<div>Host: <code>${safeText(sec.host)}</code> — <a target="_blank" rel="noreferrer" href="${safeText(sec.url)}">ver archivo</a></div>`);
  if (sec.text) {
    const contact = (sec.text.match(/^Contact:\s*(.+)$/gmi)||[]).map(x=>x.split(":").slice(1).join(":").trim());
    const policy = (sec.text.match(/^Policy:\s*(.+)$/gmi)||[]).map(x=>x.split(":").slice(1).join(":").trim());
    const expires = (sec.text.match(/^Expires:\s*(.+)$/gmi)||[]).map(x=>x.split(":").slice(1).join(":").trim());
    if (contact.length) rows.push(`<div>Contact: ${contact.map(x=>`<code>${safeText(x)}</code>`).join(", ")}</div>`);
    if (policy.length) rows.push(`<div>Policy: ${policy.map(x=>`<a target="_blank" rel="noreferrer" href="${safeText(x)}">link</a>`).join(", ")}</div>`);
    if (expires.length) rows.push(`<div>Expires: ${expires.map(x=>`<code>${safeText(x)}</code>`).join(", ")}</div>`);
    rows.push(`<details style="margin-top:8px;"><summary>Ver contenido</summary><code>${safeText(sec.text)}</code></details>`);
  } else if (sec.rendered) {
    rows.push(`<div>${badge("CORS bloquea la lectura — vista embebida", "info")}</div>`);
    rows.push(sec.rendered);
  }
  secTxtEl.innerHTML = rows.join("\n");
}

function summarize(domain, dnsData, rdapOk, obs, mta, tlsrpt, sec) {
  const items = [];
  if (dnsData.DNSSEC) items.push("✅ DNSSEC detectado"); else items.push("⚠️ DNSSEC no detectado");
  if (dnsData.CAA?.length) items.push("✅ CAA presente"); else items.push("⚠️ CAA ausente (recomendado)");
  if (dnsData.SPF) items.push("✅ SPF presente"); else items.push("⚠️ SPF ausente");
  if (dnsData.DMARC) items.push("✅ DMARC presente"); else items.push("⚠️ DMARC ausente");
  if (!rdapOk) items.push("ℹ️ RDAP no disponible (CORS).");
  if (mta?.policy || mta?.dns) items.push("✉️ MTA-STS presente");
  if (tlsrpt) items.push("📊 TLS-RPT presente");
  if (sec) items.push("🛡️ security.txt accesible");
  if (obs?.grade) items.push(`🧪 Observatory: ${obs.grade} (${obs.score})`);
  summaryEl.innerHTML = list(items);
}

// ===== Controlador principal =====
async function runScan() {
  const domain = input.value.trim().toLowerCase();
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
    alert("Ingresá un dominio válido, ej: example.com");
    return;
  }

  btn.disabled = true; dnsBtn.disabled = true; fastModeEl.disabled = false;
  logEl.textContent = ""; dnsEl.innerHTML = ""; rdapEl.innerHTML = ""; summaryEl.innerHTML = "";
  obsEl.innerHTML = ""; emailEl.innerHTML = ""; secTxtEl.innerHTML = ""; mxtLinksEl.innerHTML = "";
  log("INFO", `Auditoría para ${domain} — DoH ${directDnsEl.checked?"ON":"OFF"} (DNS ${dnsMode})`);

  try {
    const dnsData = await checkDNS(domain);
    renderDNS(domain, dnsData);

    let rdapJson = null;
    const rdapTask = rdapDomain(domain).then(j=>{rdapJson=j;}).catch(_=>{});

    const obsTask = observatoryV2(domain).then(j=>{ renderObservatory(domain, j); return j; }).catch(_=>null);

    const mtaTask = checkMtaSts(domain).catch(_=>null);
    const tlsTask = checkTlsRpt(domain).catch(_=>null);
    const secTask = checkSecurityTxt(domain).then(j=>{ renderSecurityTxt(domain, j); return j; }).catch(_=>{ renderSecurityTxt(domain, null); return null; });

    let obsResult = null, mtaResult = null, tlsResult = null, secResult = null;
    if (fastModeEl.checked) {
      [obsResult] = await Promise.race([Promise.all([obsTask]), new Promise(res=>setTimeout(()=>res([null]), 2500))]);
      [mtaResult, tlsResult, secResult] = await Promise.race([
        Promise.all([mtaTask, tlsTask, secTask]), new Promise(res=>setTimeout(()=>res([null,null,null]), 2500))
      ]);
    } else {
      obsResult = await obsTask;
      [mtaResult, tlsResult, secResult] = await Promise.all([mtaTask, tlsTask, secTask]);
    }

    await rdapTask;
    renderRDAP(domain, rdapJson);
    renderEmailSec(domain, mtaResult, tlsResult);

    summarize(domain, dnsData, !!rdapJson, obsResult, mtaResult, tlsResult, secResult);
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
