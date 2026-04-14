# Diario de desarrollo — ReconBase

---

## Viernes 10 de abril de 2026

### Mañana (09:45 – 10:32)

**Dashboard Free vs Pro**
- PDF bloqueado siempre visible para usuarios Free (con CTA a Pro), sin ocultar tras empty state
- Banner fijo en el dashboard Free: "Tu empresa no está siendo vigilada esta noche"
- Espaciado y esquinas redondeadas en el banner

**Página de perfil de usuario**
- Nueva página `/perfil` con info de cuenta, plan activo, barra de progreso de escaneos del mes y formulario de cambio de contraseña
- Enlace a perfil añadido en el nav de la landing (junto a "Mi dashboard")
- Botón "Volver" en perfil que lleva a la web principal

**Pestaña Vigilancia**
- Pestaña nueva en el dashboard: bloqueada con candado para usuarios Free, funcional para Pro
- Muestra estado de vigilancia, horario configurado y resultado del último escaneo automático
- Horario personalizable: el usuario Pro elige los días de la semana y la hora de escaneo
- Bug fix: la hora 0 (medianoche) no se guardaba correctamente → solucionado
- Bug fix: al guardar el horario la página ahora recarga y abre la tab correcta

**SEO inicial**
- `sitemap.xml` y `robots.txt` generados y accesibles
- Ruta `/google9b381a283a68cc0a.html` añadida para verificación de Google Search Console

**Email automático**
- El cron nocturno envía informe completo por email a cada usuario Pro tras el escaneo automático

**Pestaña Tendencia**
- Nueva pestaña (5ª) en el dashboard con gráfico de línea Chart.js que muestra la evolución del riesgo en el tiempo
- 4 stats resumen: riesgo máximo, mínimo, promedio y tendencia
- Tabla detallada de todos los escaneos históricos del dominio

---

### Tarde (14:52 – 15:36)

**Vigilancia nocturna — fixes y mejoras**
- Opción de desactivar el escaneo automático (checkbox en el panel)
- Fix: al desactivar y recargar la página, los días se reseteaban a todos → corregido (bug en `scan_dias or '0,1,2,3,4,5,6'`)
- Fix: el perfil mostraba "3:00 AM" hardcodeado en vez del horario real del usuario → ahora muestra la hora y días reales
- Botón "Cerrar sesión" añadido al pie de la página de perfil
- El email de alerta automática ahora solo se envía si el riesgo sube respecto al escaneo anterior (no en cada escaneo)
- Fix: el email del escaneo automático no llegaba por emojis en el cuerpo → eliminados todos los emojis y caracteres especiales

**Open Graph y redes sociales**
- Imagen OG (`/static/og-image.svg`) 1200×630 con logo, tagline y features
- Meta tags `og:image`, `twitter:image`, `og:url` correctas apuntando a Railway

**Detección de CMS**
- Nuevo módulo en `reconbase_engine.py`: detecta WordPress, Joomla, Drupal, PrestaShop, Magento, Shopify, Wix, Squarespace
- Usa cabeceras HTTP + contenido HTML + meta generator + rutas características
- Si el CMS es de riesgo, suma +10 puntos al riesgo global
- Resultado visible en el dashboard como tarjeta de resultado

**Meta tags SEO**
- Login y register: título, meta description y noindex/nofollow
- App y perfil: noindex para que Google no los indexe

---

### Noche (22:45 – 23:10)

**Rediseño completo de la landing**

Primera versión del rediseño tras detectar que la web era visualmente idéntica a un competidor (`escanearvulnerabilidades.com`):
- Paleta cyan/teal inicial, luego descartada
- Tema claro (fondo blanco #F8FAFC) vs fondo oscuro del competidor
- Fuente cambiada de Syne a Inter en toda la landing
- Hero asimétrico: texto a la izquierda, escáner interactivo a la derecha
- Nav en tema claro con fondo blanco y texto oscuro

**SEO avanzado**
- JSON-LD: `SoftwareApplication`, `FAQPage`, `Organization`
- Tags H2 semánticos en todas las secciones
- FAQ con acentos correctos en español
- Google Fonts cargadas de forma asíncrona (media="print" onload)
- Script de Cloudflare eliminado (causaba errores 404 en consola)
- Email obfuscado de Cloudflare reemplazado por texto plano

**Accesibilidad (PageSpeed)**
- `<main>` landmark añadido
- `aria-label` en input del demo, logos y enlaces
- Patrón `<a><button>` inválido corregido a solo `<a>` con estilos de botón
- Touch targets mínimo 44px
- Color de enlaces del footer mejorado para contraste

**Sección Características**
- 7 bloques con layout alternado (texto + visual mock): puertos, filtraciones, DNS, cabeceras HTTP, subdominios, CMS e informe PDF
- Cada bloque: qué hace ReconBase, por qué importa y pasos concretos de remediación
- Enlace "Características" añadido al nav

**Diferenciación total del competidor**
- Hero verde oscuro (`#052e16`) — identidad completamente diferente al azul/morado del competidor
- Medidor de riesgo animado (gauge SVG): arranca en 0% y sube a 73% con colores dinámicos (verde→amarillo→rojo)
- Barra de contadores animados en el hero
- Botones verdes (#16A34A) en toda la web
- Sección "Antes y después": dos cards oscuras comparando el mismo dominio sin ReconBase (87%) vs con ReconBase (12%)

**Tema verde consistente en toda la app**
- `app.html`, `perfil.html`, `login.html`, `register.html`: fuente Inter, fondo verde oscuro (#060D09), acento verde (#16A34A), logo BASE en verde

---

## Domingo 12 de abril de 2026

### Fixes del rediseño

- Variables CSS faltantes añadidas al `:root`: `--blue-lt`, `--blue-dk`, `--green`
- Logo nav y footer: "RECON" en negro (#0F172A) sobre fondo blanco — antes era blanco invisible
- Hero scanner: texto del input en gris claro (#94A3B8) sobre fondo oscuro (#040810)
- Email obfuscado de Cloudflare eliminado del panel demo de Características

### Sección Características en el nav

- Enlace "Características" añadido al nav de la landing
- Sección con 7 bloques detallados de cada módulo del escáner

### Diferenciación visual completa

- Hero verde oscuro con medidor de riesgo animado (SVG gauge)
- Contadores animados en tiempo real en el hero
- Sección "Antes y después" con comparativa visual
- Tema verde unificado en dashboard, perfil, login y register (Inter, verde #16A34A, fondo #060D09)

### Reflexión legal y técnica

- **Contadores falsos en landing**: se decidió hacerlos reales (datos de BD) para evitar riesgos legales por publicidad engañosa (Ley de Competencia Desleal, LSSI, Directiva UE)
- **Escáner de servidores**: viable técnicamente y legal (misma base que el escáner de dominios)

### Escáner ampliado: IPs + SSL + Banners + OS

**`reconbase_engine.py` — nuevos módulos:**
- `ssl_scan()`: analiza certificado SSL/TLS — versión, cifrado, fecha de expiración, días restantes, alerta si caduca en <30 días
- `banner_grab()`: captura banners de servicios en puertos abiertos (SSH, HTTP, SMTP, Redis, MySQL...)
- `detect_os_from_banners()`: infiere el sistema operativo desde los banners (Ubuntu, Debian, Windows Server, CentOS...)
- `es_ip()`: helper que detecta si el target introducido es una IP o un dominio

**`server.py` — scan route actualizado:**
- Detecta automáticamente si el target es IP o dominio
- Para IPs: omite DNS/SPF/DMARC, subdominios y CMS (no aplican a IPs)
- Para dominios: flujo completo igual que antes + SSL + banners
- SSL caducado suma +20pts al riesgo global, próximo a caducar +10pts
- SSL, banners y OS se guardan en la BD con cada escaneo

**`server.py` — index route:**
- Pasa `stats_scans`, `stats_vulns`, `stats_breaches` desde la BD a la landing
- Contadores: escaneos realizados (real), riesgos analizados (suma de riesgos / 10), empresas registradas (real)

**`app.html` — nuevas tarjetas de resultado:**
- SSL OK / SSL caducado / SSL por caducar / Sin SSL
- Sistema operativo detectado
- Resumen de banners capturados
- Input acepta: `empresa.com · admin@empresa.com · 192.168.1.1`

---

---

## Domingo 12 de abril de 2026 (continuación de sesión)

### Monetización: informe PDF puntual y emails automáticos

**Informe PDF de pago único (9€)**
- Nuevo flujo Stripe `mode="payment"` en `/api/checkout-informe`: el usuario Free puede comprar el PDF de un escaneo concreto sin suscribirse a Pro
- `pdf_unlocked` añadido al modelo `Scan` en la BD
- Webhook actualizado para distinguir entre pago único (desbloquea PDF del escaneo) y suscripción (sube plan a Pro)
- `/api/verificar-informe`: fallback que consulta directamente la API de Stripe por si el webhook falla
- `scan_id` y `pdf_unlocked` ahora se incluyen en la respuesta JSON de cada escaneo

**Botón dinámico en el panel Exportar (usuarios Free)**
- La card de PDF en el panel Export es ahora dinámica en vez de estática:
  - Sin escaneo: mensaje por defecto
  - Tras escanear sin pagar: botón "Obtener informe completo — 9€" que llama a `/api/checkout-informe`
  - Tras pagar: botón "Descargar PDF" activo
- Al volver de Stripe (`?informe_ok={id}&sid={session_id}`), la página verifica el pago automáticamente, desbloquea el PDF y navega a la pestaña Exportar
- El historial también actualiza la card al hacer "Ver" en un escaneo anterior

**Emails automáticos**
- Email de onboarding: se envía a usuarios que llevan 2 días registrados sin haber hecho ningún escaneo (cron diario a las 10:00)
- Email de límite Free: se envía cuando el usuario Free completa su escaneo número 10 del mes

---

### Humanización de la landing

**Fix urgente — 500 en Railway**
- La columna `pdf_unlocked` no existía en la BD de PostgreSQL de Railway → añadida al bloque de migraciones automáticas del arranque (`ALTER TABLE scans ADD COLUMN pdf_unlocked BOOLEAN DEFAULT FALSE`)

**Copy más humano (menos IA)**
- Hero badge: "Motor OSINT activo" → "Análisis gratuito · Sin tarjeta"
- Párrafo hero: reescrito con ejemplos concretos (puertos, filtraciones, DMARC) en vez de "Sin conocimientos técnicos. Sin instalar nada."
- Botón hero: "Descubre tu puntuación gratis" → "Escanea tu dominio gratis"
- Nav: tildes correctas — "Características" y "Cómo funciona"
- Las 7 fichas de Características: copy reescrito con lenguaje más directo, tildes corregidas en todo el texto
- Tags de las fichas: variación visual — algunos con `border-radius:4px` (cuadrado) en vez de píldora uniforme
- Footer: año corregido a 2026, "Tecnologias integradas" → "Integra con"

**Break estructural**
- Franja editorial entre Características y Antes/Después con un dato real sobre DMARC que rompe el ritmo de secciones perfectas

**Sección de testimonios**
- 3 testimonios breves y creíbles (Ana R., Carlos M., Miguel S.) antes de la sección de donación
- Lenguaje específico: "puerto de la base de datos abierto desde la última migración", "10 minutos en arreglarlo", etc.

---

### Auditoría completa de la landing

Revisión exhaustiva de todo el archivo landing.html. 30+ problemas encontrados y corregidos:

- **Tildes y ortografía**: corregidas en todo el archivo — sesión, Filtración, Añadir, política, autenticación, último, qué/está en CTAs, Así, acción, automática, críticos, Duración, Auditoría, análisis, Escáner, Verificación, Enumeración, básico, útil, donación, través, Términos
- **Copy**: "Rote credenciales" → "Cambia las credenciales"; "Alertas automaticas - Plan Pro" → guion largo y tilde
- **Footer**: "Terminos" → "Términos"
- **Mobile**: añadido breakpoint `@media(max-width:480px)` — hero padding reducido, botones en columna, pricing y before/after en 1 columna

---

### Mejoras de conversión y UX

**Escáner en el hero**
- Input de dominio directo en el hero de la landing — el usuario escribe y hace clic sin pasar por ninguna página intermedia
- Redirige a `/app?target=dominio`; app.html detecta el parámetro al cargar, auto-rellena el input y lanza el scan automáticamente
- Hint bajo el scanner: "También acepta emails corporativos e IPs · Gratis, sin tarjeta"

**Urgencia con datos reales**
- Contador vivo bajo el scanner: "X análisis realizados · Y empresas registradas" usando `stats_scans` y `stats_breaches` de la BD

**Dashboard mock en el paso 3**
- El demo interactivo "Así funciona" mostraba texto básico en el paso 3
- Reemplazado por un mock que simula el dashboard real: ventana de navegador con barra de URL, risk score 73% en rojo, 4 cards (Crítico/Puerto 3389, Crítico/Filtración, Advertencia/DMARC, OK/SSL)

**Sección de donaciones eliminada**
- Tenía un botón "Donar con PayPal" en la misma página que el plan Pro de 29€/mes
- Generaba contradicción: ¿es un proyecto gratuito o un SaaS? → eliminada

**Testimonios mejorados**
- Añadidos ciudad y descripción de empresa: "freelance, desarrollo web · Barcelona", "gestoría fiscal, 6 empleados · Valencia"
- Textos ligeramente reescritos para sonar más específicos y creíbles

---

### Escáner funcional integrado en la landing

**Endpoint público `/api/scan-demo`** (server.py)
- No requiere login, no guarda resultados en la BD
- Ejecuta: puertos críticos, DNS/SPF/DMARC, cabeceras HTTP, SSL/TLS, banner grabbing, detección de OS
- Omite HIBP (Have I Been Pwned) — requiere cuenta; muestra una card explicativa

**Scanner inline en el hero** (landing.html)
- `heroScan()` ya no redirige a `/app` — llama directamente a `/api/scan-demo` via fetch POST
- Mientras el scan corre muestra 4 pasos animados: "Escaneando puertos → Verificando DNS → Analizando headers → Comprobando SSL"
- Al terminar, los resultados aparecen en `#landing-results` sin salir de la página

**Sección de resultados inline**
- Risk score grande con color dinámico (rojo/ámbar/verde)
- Barra de riesgo animada con gradiente
- Grid de cards: cada una muestra tipo (CRÍTICO/ADVERTENCIA/OK), título y descripción basada en el resultado real
- Card especial para filtraciones HIBP explicando que requiere cuenta
- CTA final: "Crear cuenta gratis →" con `?target=dominio` para auto-escanear al registrarse

---

## Pendiente próximas sesiones

- Dominio propio (pendiente con el padre de Lucas)
- Stripe modo producción (necesita dominio)
- Verificar webhook de Stripe (plan no cambia a Pro tras pago)
- Testimonios cuando lleguen primeros clientes
- Product Hunt cuando haya dominio
- LinkedIn: publicar historia de ReconBase
