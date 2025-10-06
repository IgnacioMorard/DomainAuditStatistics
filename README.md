# Auditoría Pública de Dominio — v2.7

**Novedad clave:** integración con **MDN HTTP Observatory API v2** (v1 está deprecado/cerrado).

- Endpoint usado: `POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=<dominio>`
- Respuesta: JSON con `grade`, `score`, `tests_passed`, `tests_failed`, `tests_quantity`, `algorithm_version`, `scanned_at`, `details_url` (para abrir el reporte completo).  
- Rate-limit: 1 escaneo por host por minuto (si se excede, devuelve **cache**) — ver README oficial.

### Referencias
- API v2 y formato de respuesta (README del backend MDN): contiene ejemplo de JSON y nota de migración desde v1.  
- Puntuación y rangos de calificación (A+, A, ...): ver **Tests & Scoring**.

## Deploy
Subí `index.html`, `app.js`, `styles.css` a GitHub Pages.

## Notas
- Si `Observatory v2` da 500 temporales, reintentar más tarde; hay issues reportados.
- En navegadores móviles, activá **Modo rápido** para mejores tiempos percibidos.
