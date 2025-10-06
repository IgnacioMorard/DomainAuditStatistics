# v3.1 — Sin proxy, con MXToolbox y security.txt visible

- **DNS**: se muestran **enlaces directos a MXToolbox** (A, AAAA, NS, MX, SOA, CAA, TXT, DMARC, SPF, DNSSEC).  
  Si activás el toggle **“Consultar DoH directo”**, intenta DoH (Google/Cloudflare/Quad9/DNS.SB) y muestra lo que consiga. Si tu red bloquea DoH, usá los enlaces.
- **security.txt**: primero intenta `fetch`. Si CORS bloquea, **embebe** el archivo con `<object>` (se ve el contenido aunque no podamos leerlo). Si el servidor bloquea framing, queda el enlace.
- **Quitado**: HSTS e Infra, como pediste.
- Mantiene: **RDAP** y **MDN Observatory v2**, y el panel **Email Transport Security** (MTA-STS / TLS-RPT).

Subí `index.html`, `styles.css`, `app.js` a GitHub Pages.
