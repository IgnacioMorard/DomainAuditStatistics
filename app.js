
// ===== Utilidades base =====
const $ = (sel) => document.querySelector(sel);
const logEl = $("#log");
const dnsEl = $("#dnsResults");
const rdapEl = $("#rdapResults");
const summaryEl = $("#summary");
const infraEl = $("#infraResults");
const btn = $("#scanBtn");
const providerBtn = $("#providerBtn");
const input = $("#domain");

let providerMode = "auto"; // auto | google | cloudflare

const log = (level, msg) => {
  const line = `[${new Date().toLocaleTimeString()}] ${level}: ${msg}`;
  logEl.textContent += line + "\n";
  logEl.scrollTop = logEl.scrollHeight;
};

const badge = (txt, type = "info") => `<span class="badge ${type}">${txt}</span>`;
const safeText = (v) => String(v ?? "").replace(/[<>&]/g, s => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[s]));

function withTimeout(promise, ms, label="operación") {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(`${label} timeout ${ms}ms`), ms);
  return Promise.race([
    promise(ctrl.signal),
    new Promise((_, rej) => ctrl.signal.addEventListener("abort", () => rej(new Error(ctrl.signal.reason || "timeout"))))
  ]).finally(() => clearTimeout(t));
}

// ===== DNS over HTTPS: Google -> fallback Cloudflare (o elección manual) =====
async function dohGoogle(name, type = "A", signal) {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { headers: { "accept": "application/dns-json" }, mode: "cors", cache: "no-store", signal });
  if (!res.ok) throw new Error(`dns.google ${type} -> HTTP ${res.status}`);
  return res.json();
}
async function dohCloudflare(name, type = "A", signal) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&ct=application/dns-json`;
  const res = await fetch(url, { headers: { "accept": "application/dns-json" }, mode: "cors", cache: "no-store", signal });
  if (!res.ok) throw new Error(`cloudflare-dns ${type} -> HTTP ${res.status}`);
  return res.json();
}
async function doh(name, type = "A") {
  const tryGoogle = (signal) => dohGoogle(name, type, signal);
  const tryCloudflare = (signal) => dohCloudflare(name, type, signal);

  if (providerMode === "google") return withTimeout(tryGoogle, 9000, `DoH Google ${type}`);
  if (providerMode === "cloudflare") return withTimeout(tryCloudflare, 9000, `DoH Cloudflare ${type}`);

  // auto: google -> cloudflare
  try {
    return await withTimeout(tryGoogle, 9000, `DoH Google ${type}`);
  } catch (e1) {
    log("INFO", `Fallo dns.google (${type}): ${e1.message} — usando fallback Cloudflare`);
    return await withTimeout(tryCloudflare, 9000, `DoH Cloudflare ${type}`);
  }
}

function parseAnswers(obj) {
  const ans = obj?.Answer || [];
  return ans.map(a => ({ name: a.name, type: a.type, data: a.data, TTL: a.TTL }));
}

// ===== RDAP via rdap.org (si CORS falla, mostramos link) =====
async function rdapDomain(domain) {
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const res = await fetch(url, { mode: "cors", cache: "no-store" });
  if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
  return res.json();
}

function extractRdapSummary(rdap) {
  const out = {};
  try {
    out.ldhName = rdap.ldhName || rdap.handle || null;
    const registrar = (rdap.entities || []).find(e => (e.roles||[]).includes("registrar"));
    out.registrar = registrar?.vcardArray?.[1]?.find(x => x[0] === "fn")?.[3] || registrar?.handle || null;
    const ev = {};
    for (const e of (rdap.events || [])) ev[e.eventAction] = e.eventDate;
    out.registered = ev.registration || ev.registered || null;
    out.expires = ev.expiration || ev.expire || null;
    out.updated = ev.lastchanged || ev.lastupdate || ev.lastchangeddate || null;
    out.nameservers = (rdap.nameservers || []).map(ns => ns.ldhName || ns.handle).filter(Boolean);
  } catch {}
  return out;
}

// ===== Infra: ISP/ASN via ipwho.is y SSL Labs (opcional) =====
async function ipInfo(ip) {
  const url = `https://ipwho.is/${encodeURIComponent(ip)}`;
  const res = await fetch(url, { mode: "cors", cache: "no-store" });
  if (!res.ok) throw new Error(`ipwho.is HTTP ${res.status}`);
  return res.json();
}

async function sslLabs(domain) {
  // fromCache=on para evitar scans largos; si no hay cache, probablemente error o "IN_PROGRESS"
  const url = `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(domain)}&all=done&fromCache=on&ignoreMismatch=on`;
  const res = await fetch(url, { mode: "cors", cache: "no-store" });
  if (!res.ok) throw new Error(`SSL Labs HTTP ${res.status}`);
  return res.json();
}

// ===== Chequeos DNS =====
async function checkDNS(domain) {
  const results = {};
  // A / AAAA
  try {
    const a = await doh(domain, "A");
    results.A = parseAnswers(a);
    log("OK", `A: ${results.A.map(x => x.data).join(", ") || "—"}`);
  } catch (e) { log("WARN", `A: ${e.message}`); }
  try {
    const aaaa = await doh(domain, "AAAA");
    results.AAAA = parseAnswers(aaaa);
    log("OK", `AAAA: ${results.AAAA.map(x => x.data).join(", ") || "—"}`);
  } catch (e) { log("INFO", `AAAA: ${e.message}`); }

  // NS
  try {
    const ns = await doh(domain, "NS");
    results.NS = parseAnswers(ns);
    log("OK", `NS: ${results.NS.map(x => x.data).join(", ")}`);
  } catch (e) { log("WARN", `NS: ${e.message}`); }

  // MX
  try {
    const mx = await doh(domain, "MX");
    results.MX = parseAnswers(mx);
    log("OK", `MX: ${results.MX.map(x => x.data).join(" | ") || "—"}`);
  } catch (e) { log("INFO", `MX: ${e.message}`); }

  // SOA
  try {
    const soa = await doh(domain, "SOA");
    results.SOA = parseAnswers(soa);
    log("OK", `SOA: ${results.SOA[0]?.data || "—"}`);
  } catch (e) { log("INFO", `SOA: ${e.message}`); }

  // CAA
  try {
    const caa = await doh(domain, "CAA");
    results.CAA = parseAnswers(caa);
    if (results.CAA.length) {
      log("OK", `CAA: ${results.CAA.map(x => x.data).join(" | ")}`);
    } else {
      log("WARN", "CAA: no hay registros — considera añadir CAA para limitar emisores de certificados");
    }
  } catch (e) { log("INFO", `CAA: ${e.message}`); }

  // TXT -> SPF
  try {
    const txt = await doh(domain, "TXT");
    results.TXT = parseAnswers(txt);
    const txtVals = results.TXT.map(x => x.data.replace(/^"|"$/g, ""));
    const spf = txtVals.find(v => v.toLowerCase().includes("v=spf1"));
    if (spf) {
      log("OK", `SPF: ${spf}`);
      results.SPF = spf;
    } else {
      log("WARN", "SPF: no encontrado");
    }
  } catch (e) { log("INFO", `TXT/SPF: ${e.message}`); }

  // DMARC
  try {
    const dmarc = await doh(`_dmarc.${domain}`, "TXT");
    const ans = parseAnswers(dmarc);
    if (ans.length) {
      const val = ans.map(x => x.data.replace(/^"|"$/g, "")).join("");
      results.DMARC = val;
      const pol = /;?\s*p=(none|quarantine|reject)\s*;?/i.exec(val)?.[1]?.toLowerCase() || "none?";
      const rua = /rua=([^;]+)/i.exec(val)?.[1] || "";
      log("OK", `DMARC: p=${pol}${rua ? `, rua=${rua}` : ""}`);
      if (pol === "none") log("WARN", "DMARC en p=none — considera quarantine/reject");
    } else {
      log("WARN", "DMARC: no encontrado");
    }
  } catch (e) { log("INFO", `DMARC: ${e.message}`); }

  // DNSSEC (DS + AD bit)
  try {
    const ds = await doh(domain, "DS");
    results.DS = parseAnswers(ds);
    const hasDS = results.DS.length > 0;
    const ad = !!ds.AD;
    if (hasDS || ad) {
      log("OK", `DNSSEC: ${hasDS ? "DS presente" : ""} ${ad ? "(AD=true)" : ""}`.trim());
      results.DNSSEC = true;
    } else {
      log("WARN", "DNSSEC: no se detecta firma/validación");
      results.DNSSEC = false;
    }
  } catch (e) { log("INFO", `DNSSEC: ${e.message}`); }

  return results;
}

// ===== Render helpers =====
function list(items) {
  return `<ul>${items.map(i => `<li>${i}</li>`).join("")}</ul>`;
}

function renderDNS(domain, data) {
  const rows = [];
  const joinData = (arr) => arr?.map(x => safeText(x.data)).join("<br>") || "—";

  rows.push(`<h3>${safeText(domain)}</h3>`);
  rows.push(`<p>${badge(data.DNSSEC ? "DNSSEC (detectado)" : "DNSSEC (no detectado)", data.DNSSEC ? "ok" : "warn")}
     ${data.CAA?.length ? badge("CAA presente", "ok") : badge("CAA ausente", "warn")}
     ${data.SPF ? badge("SPF", "ok") : badge("SPF ausente", "warn")}
     ${data.DMARC ? badge("DMARC", "ok") : badge("DMARC ausente", "warn")}</p>`);

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
    rdapEl.innerHTML = `<p>${badge("RDAP no disponible (CORS) — abrir manualmente", "warn")} <a href="https://rdap.org/domain/${encodeURIComponent(domain)}" target="_blank" rel="noreferrer">Ver RDAP</a></p>`;
    return;
  }
  const s = extractRdapSummary(rdap);
  const rows = [];
  rows.push(`<div><strong>Dominio:</strong> ${safeText(s.ldhName || domain)}</div>`);
  rows.push(`<div><strong>Registrar:</strong> ${safeText(s.registrar || "—")}</div>`);
  rows.push(`<div><strong>Registrado:</strong> ${safeText(s.registered || "—")}</div>`);
  rows.push(`<div><strong>Expira:</strong> ${safeText(s.expires || "—")}</div>`);
  rows.push(`<div><strong>Actualizado:</strong> ${safeText(s.updated || "—")}</div>`);
  rows.push(`<div><strong>Nameservers:</strong><br><code>${(s.nameservers||[]).map(safeText).join("<br>") || "—"}</code></div>`);

  rdapEl.innerHTML = rows.join("\n") + `<details style="margin-top:8px;"><summary>Ver JSON RDAP completo</summary><code>${safeText(JSON.stringify(rdap, null, 2))}</code></details>`;
}

function renderInfra(domain, dnsData, ipInfoData, sslData) {
  const rows = [];
  // IP/ASN/ISP
  if (ipInfoData) {
    rows.push(`<div><strong>IP:</strong> ${safeText(ipInfoData.ip)} — <strong>ASN:</strong> ${safeText(ipInfoData.connection?.asn || ipInfoData.asn || "—")}</div>`);
    rows.push(`<div><strong>Org/ISP:</strong> ${safeText(ipInfoData.connection?.org || ipInfoData.org || ipInfoData.isp || "—")}</div>`);
    rows.push(`<div><strong>País:</strong> ${safeText(ipInfoData.country || ipInfoData.country_code || "—")}</div>`);
  } else {
    rows.push(`<div>${badge("No se pudo obtener info de IP (ipwho.is)", "warn")}</div>`);
  }

  // SSL Labs (si hay)
  if (sslData?.endpoints?.length) {
    const ep = sslData.endpoints[0];
    const grade = ep.grade || ep.gradeTrustIgnored || "N/A";
    rows.push(`<div><strong>SSL Labs (cache):</strong> Grade ${safeText(grade)} — <a href="https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(domain)}" target="_blank" rel="noreferrer">ver detalle</a></div>`);
  } else {
    rows.push(`<div>${badge("SSL Labs (cache) no disponible", "info")} <a href="https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(domain)}" target="_blank" rel="noreferrer">Abrir análisis</a></div>`);
  }

  infraEl.innerHTML = rows.join("\n");
}

function summarize(domain, dnsData, rdapSummaryOk) {
  const items = [];
  if (dnsData.DNSSEC) items.push("✅ DNSSEC detectado");
  else items.push("⚠️ DNSSEC no detectado");

  if (dnsData.CAA?.length) items.push("✅ CAA presente");
  else items.push("⚠️ CAA ausente (recomendado)");

  if (dnsData.SPF) items.push("✅ SPF presente");
  else items.push("⚠️ SPF ausente");

  if (dnsData.DMARC) {
    const pol = /p=(none|quarantine|reject)/i.exec(dnsData.DMARC)?.[1] || "none?";
    items.push(`✅ DMARC presente (p=${pol})${pol.toLowerCase()==="none" ? " ⚠️ considerar quarantine/reject" : ""}`);
  } else items.push("⚠️ DMARC ausente");

  if (!rdapSummaryOk) items.push("ℹ️ RDAP no disponible por CORS (link manual).");

  summaryEl.innerHTML = list(items);
}

// ===== Controlador principal =====
async function runScan() {
  const domain = input.value.trim().toLowerCase();
  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
    alert("Ingresá un dominio válido, ej: example.com");
    return;
  }

  btn.disabled = true;
  providerBtn.disabled = true;
  logEl.textContent = "";
  dnsEl.innerHTML = "";
  rdapEl.innerHTML = "";
  infraEl.innerHTML = "";
  summaryEl.innerHTML = "";
  log("INFO", `Iniciando auditoría para ${domain} (provider: ${providerMode})`);

  try {
    const dnsData = await checkDNS(domain);
    renderDNS(domain, dnsData);

    // IP info (first A record)
    let ipInfoData = null;
    const firstA = dnsData?.A?.[0]?.data?.replace(/\.$/, "");
    if (firstA && /^[0-9.]+$/.test(firstA)) {
      try {
        ipInfoData = await ipInfo(firstA);
        log("OK", `ipwho.is: ${firstA} -> ${ipInfoData.connection?.org || ipInfoData.org || ipInfoData.isp || "?"}`);
      } catch (e) {
        log("WARN", `ipwho.is error: ${e.message}`);
      }
    } else {
      log("INFO", "No se encontró IP A para consultar proveedor/ASN");
    }

    // RDAP
    let rdapJson = null;
    try {
      rdapJson = await rdapDomain(domain);
      log("OK", "RDAP obtenido");
    } catch (e) {
      log("WARN", `RDAP no disponible — ${e.message}`);
    }
    renderRDAP(domain, rdapJson);

    // SSL Labs (desde cache si CORS lo permite)
    let sslData = null;
    try {
      sslData = await sslLabs(domain);
      if (sslData?.status === "READY" || sslData?.status === "ERROR" || sslData?.status === "DNS") {
        log("OK", "SSL Labs (fromCache) consultado");
      } else {
        log("INFO", `SSL Labs status: ${sslData?.status}`);
      }
    } catch (e) {
      log("INFO", `SSL Labs no disponible desde el navegador — se mostrará enlace`);
    }

    renderInfra(domain, dnsData, ipInfoData, sslData);
    summarize(domain, dnsData, !!rdapJson);

    log("INFO", "Listo. Solo se consultaron fuentes públicas (DoH + RDAP + ipwho.is + SSL Labs cache).");
  } catch (e) {
    log("ERROR", e.message || String(e));
  } finally {
    btn.disabled = false;
    providerBtn.disabled = false;
  }
}

btn.addEventListener("click", runScan);
input.addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });

providerBtn.addEventListener("click", () => {
  if (providerMode === "auto") { providerMode = "google"; providerBtn.textContent = "DNS: Google"; }
  else if (providerMode === "google") { providerMode = "cloudflare"; providerBtn.textContent = "DNS: Cloudflare"; }
  else { providerMode = "auto"; providerBtn.textContent = "DNS: Auto"; }
  log("INFO", `Proveedor DoH cambiado a: ${providerMode}`);
});
