# Auditoría Pública de Dominio — v2.9

## Qué cambia
- Reemplacé “Checks extra” por **tarjetas separadas** con métricas y **enlaces**:
  - **HSTS Preload**: estado + errores + link a hstspreload.
  - **Email Transport Security**: **MTA-STS** (TXT + policy con mode/mx/max_age) y **TLS-RPT** (rua).
  - **security.txt**: host, links, campos (Contact/Policy/Expires) + ver contenido.
  - **Infra (IP/ASN/ISP)**: vía ipwho.is para la primera A IPv4.
- Mantengo **Observatory (MDN) v2** con POST/GET fallback, **DNS multi-proveedor** (Google/Cloudflare/Quad9/DNS.SB), **RDAP**, logs móviles y **Modo rápido**.

## Deploy
Subí `index.html`, `styles.css`, `app.js` a GitHub Pages. Si una API bloquea CORS, el panel muestra enlace directo. Si tu red bloquea DoH, alterná con el botón DNS.

## Notas
- `ipwho.is` es público y soporta CORS; se consulta solo si hay A IPv4.
- En móvil, `Modo rápido` reduce esperas de extras para mostrar paneles antes.
