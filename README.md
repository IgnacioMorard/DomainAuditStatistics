# Auditoría Pública de Dominio (DNS + RDAP + Infra)

Sitio estático (HTML/JS/CSS) listo para GitHub Pages que consulta **parámetros públicos**:

- DNS sobre HTTPS (dns.google + fallback cloudflare-dns) — configurable
- RDAP (whois moderno) vía rdap.org (si CORS lo permite)
- Infra: IP → ISP/ORG/ASN con ipwho.is
- SSL: intento de lectura de **SSL Labs** desde caché (si CORS lo permite); si no, muestra **enlace directo** al informe

## En móviles
- Botón para cambiar proveedor DoH (Auto/Google/Cloudflare) por si la red/bloqueador restringe uno de ellos.
- `AbortController` + timeouts para evitar “cuelgues” del fetch.
- UI táctil con inputs grandes y log scrollable.

## Deploy en GitHub Pages
1. Subí `index.html`, `app.js`, `styles.css` al repo.
2. Settings → Pages → Deploy from a branch (main, root).
3. Abre `https://<usuario>.github.io/<repo>/`

## Desarrollo local
```bash
python -m http.server 8080
# http://localhost:8080
```

## Fuentes
- DoH Google: `https://dns.google/resolve?name=...&type=...`
- DoH Cloudflare: `https://cloudflare-dns.com/dns-query?ct=application/dns-json&name=...&type=...`
- RDAP: `https://rdap.org/domain/<dominio>`
- IP info: `https://ipwho.is/<ip>`
- SSL Labs: `https://api.ssllabs.com/api/v3/analyze?host=<dominio>&fromCache=on` (si CORS disponible)
