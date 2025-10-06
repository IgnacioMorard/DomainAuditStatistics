# Auditoría Pública de Dominio (DNS + RDAP)

Sitio estático (HTML/JS/CSS) listo para GitHub Pages que consulta **parámetros públicos** de un dominio:

- DNS sobre HTTPS (dns.google): A, AAAA, NS, MX, SOA, TXT (SPF), CAA, DS (DNSSEC), DMARC (`_dmarc`)
- RDAP (whois moderno) vía rdap.org (si el endpoint permite CORS en tu navegador; si no, se muestra link para abrir manualmente)

**No** hace port scanning ni requests intrusivos. Es ideal para un portfolio o check rápido de configuración.

## Deploy en GitHub Pages

1. Subí estos archivos (`index.html`, `app.js`, `styles.css`) a un repo nuevo.
2. En el repo, Settings → Pages → **Source: Deploy from a branch**, **Branch: main**, carpeta `/root`.
3. Accedé a `https://<tu-usuario>.github.io/<tu-repo>/`

## Desarrollo local
Basta con abrir `index.html` en el navegador. (Sugerido: usar un server simple para evitar problemas de CORS locales.)

```bash
python -m http.server 8080
# luego visita http://localhost:8080
```

## Notas técnicas
- DNS via DoH: `https://dns.google/resolve?name=<dominio>&type=<TYPE>` (CORS friendly).
- RDAP: `https://rdap.org/domain/<dominio>` (si CORS del registry lo permite; si no, ver enlace en la sección RDAP de la app).
- DMARC: consultando `TXT` en `_dmarc.<dominio>` y parseando `p=` (`none|quarantine|reject`).
- CAA: restringe emisores de certificados. Recomendado añadir.
- DNSSEC: detección via existencia de `DS` y/o `AD=true` en la respuesta.

---

Hecho para uso educativo. Escanea solo parámetros públicos.
