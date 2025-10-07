# v3.2 — Observatory detallado + resumen simple de DNS

- **Observatory**: barra de puntuación (0–145), banda/grade dinámica, % de tests pasados, `algorithm_version`, `scanned_at`, y links a **Reporte completo** + **Cómo se calcula**.
- **Resumen**: menos cargado de DNS (solo indicadores clave: DNSSEC / SPF / DMARC / MTA-STS / TLS-RPT / security.txt / RDAP).
- **DNS**: igual que v3.1 (DoH opcional).  
- **MXToolbox**: sin scraping (CORS/X-Frame-Options). Queda un panel con accesos rápidos. Si querés integrar su API oficial, hay que usar un backend para resguardar la API key.

## Subir a GitHub Pages
Publicá `index.html`, `styles.css`, `app.js`.
