# Auditoría Pública de Dominio — v2.6 (mobile optimizada)

**Qué trae esta versión**
- **Logs fluidos en mobile y web**: buffer + `requestAnimationFrame`, auto-scroll con fix iOS.
- **Fetch API “bien usada”**: timeouts con `AbortController`, `mode:"cors"`, `cache:"no-store"`.
- **DNS más rápido**: consultas DoH **en paralelo** y estrategia **race** (Google ↔ Cloudflare).
- **Modo rápido** (móvil): limita espera para “extras” (HSTS/Observatory/MTA-STS/TLS-RPT/security.txt) para entregar resultados visibles antes.
- **Extras públicos**: HSTS Preload, Mozilla Observatory (best-effort), MTA-STS, TLS-RPT, `security.txt`.

## Deploy en GitHub Pages
1. Subí `index.html`, `app.js`, `styles.css` a tu repo.
2. Settings → Pages → Deploy from a branch (main, root).
3. Abrí `https://<usuario>.github.io/<repo>/`

## Dev local
```bash
python -m http.server 8080
# http://localhost:8080
```

## Notas
- Algunas APIs pueden no permitir CORS en tu navegador. La app no se rompe y muestra enlaces directos.
- En redes móviles lentas, activá **Modo rápido** para sentir la mejora.
