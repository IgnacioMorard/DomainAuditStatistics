# Auditoría Pública de Dominio (DNS + RDAP) — v2.5

Sitio estático (HTML/JS/CSS) listo para GitHub Pages que consulta **parámetros públicos**:

- DNS sobre HTTPS (dns.google -> fallback cloudflare-dns)
- RDAP (whois moderno) vía rdap.org (si CORS lo permite)
- HSTS Preload API (hstspreload.org)
- Mozilla HTTP Observatory (mejor esfuerzo; si CORS/cache no permite, se muestra enlace)
- Enriquecimientos: PTR (reverse DNS) de la IP A, intento de DANE/TLSA, parsing SPF/DMARC

## Pensado para mobile + web
- Log visual robusto: buffer + `requestAnimationFrame`, auto-scroll con fix para iOS.
- Altura del log adaptable, scroll táctil (`-webkit-overflow-scrolling: touch`).
- Timeouts con `AbortController` para evitar cuelgues.

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
- HSTS preload: `https://hstspreload.org/api/v2/status?domain=<dominio>`
- Mozilla Observatory: `https://http-observatory.security.mozilla.org/api/v1/*`
