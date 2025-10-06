# Auditoría Pública de Dominio — v2.8

### Cambios clave
- **Botones con más espacio**: grupo con `gap`, layout responsive — ya no se apretan en web/mobile.
- **Observatory v2 robusto**: usa `POST` y si falla por CORS/5xx intenta un **`GET`** (para cache). Siempre muestra **link** al reporte.
- **DNS multi-proveedor**: **Google**, **Cloudflare**, **Quad9**, **DNS.SB** — carrera y fallback por tipo.
- **Chequeos extra ampliados**: muestra errores de HSTS preload, `security.txt`, MTA-STS/TLS-RPT, etc.
- **“Modo rápido”**: reduce esperas en móvil.
- **Logs**: más verbosos si hay CORS/bloqueos.

### Nota Observatory v2
La API pública es `https://observatory-api.mdn.mozilla.net/api/v2/scan?host=<dominio>` (preferir **POST**). En algunos entornos/CDNs pueden verse respuestas cacheadas con `GET`. Si el servidor devuelve 5xx, los navegadores no exponen headers CORS — la app te lo indica y deja enlace al reporte.

### DNS alternativo
Algunos bloqueadores filtran `dns.google`/`cloudflare-dns.com`. Agregamos **Quad9** y **DNS.SB** para aumentar la probabilidad de éxito.

### Deploy
Subí `index.html`, `app.js`, `styles.css` a GitHub Pages. Si algo no responde en móvil, probá alternar proveedor con el botón DNS o activar **Modo rápido**.
