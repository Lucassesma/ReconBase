<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-3.1-000000?style=flat-square&logo=flask" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/Stripe-Integrado-635BFF?style=flat-square&logo=stripe&logoColor=white" />
  <img src="https://img.shields.io/badge/Deploy-Railway-0B0D0E?style=flat-square&logo=railway" />
</p>

<h1 align="center">RECON<span style="color:#22C55E">BASE</span></h1>

<p align="center">
  <strong>Plataforma OSINT de análisis de seguridad externa para PYMEs</strong><br>
  Escanea dominios, IPs y emails — detecta vulnerabilidades antes de que lo haga un atacante.
</p>

<p align="center">
  <a href="#-instalación-local">🌐 Demo en vivo</a> ·
  <a href="#-módulos-de-análisis">📡 Módulos</a> ·
  <a href="#-stack-técnico">🛠 Stack</a> ·
  <a href="#-instalación-local">⚙️ Instalación</a>
</p>

---

## 🔍 Qué es ReconBase

ReconBase es una herramienta de reconocimiento y análisis de seguridad externa que permite a cualquier empresa —sin conocimientos técnicos— evaluar su superficie de ataque pública.

Introduce un dominio, una IP o un email corporativo y obtén un informe completo con:
- Puertos expuestos y servicios identificados
- Filtraciones de datos (Have I Been Pwned)
- Configuración DNS (SPF, DMARC)
- Cabeceras HTTP de seguridad
- Subdominios descubiertos
- Certificado SSL/TLS y caducidad
- CMS detectado y versión expuesta
- Banner grabbing y detección de sistema operativo
- Puntuación de riesgo global (0–100)

---

## 📡 Módulos de análisis

| Módulo | Qué analiza | Riesgo que detecta |
|--------|-------------|-------------------|
| **Escáner de puertos** | 24 puertos críticos (RDP, SSH, MySQL, MongoDB, Redis, Docker API…) | Servicios expuestos a Internet sin necesidad |
| **Filtraciones** | API de Have I Been Pwned | Credenciales filtradas en brechas de datos |
| **DNS / SPF / DMARC** | Registros TXT del dominio | Suplantación de identidad por email (spoofing) |
| **Cabeceras HTTP** | HSTS, CSP, X-Frame-Options, Referrer-Policy… | Ataques clickjacking, MIME-sniffing, XSS |
| **Subdominios** | 50+ prefijos comunes (admin, dev, staging, db, jenkins…) | Entornos expuestos olvidados |
| **SSL/TLS** | Certificado, cifrado, caducidad | Certificados caducados o débiles |
| **CMS** | WordPress, Joomla, Drupal, PrestaShop, Shopify, Wix… | CMS desactualizados (vector #1 en PYMEs) |
| **Banner grabbing** | Banners de servicios en puertos abiertos | Versiones de software expuestas |
| **Detección de OS** | Inferencia desde banners | Sistema operativo del servidor identificable |

---

## 🛠 Stack técnico

```
Backend:    Python 3.12 · Flask 3.1 · SQLAlchemy · Gunicorn
Base datos: PostgreSQL (Railway)
Frontend:   HTML5 · CSS3 · JavaScript vanilla · Chart.js
Pagos:      Stripe (suscripción Pro + PDF puntual)
Email:      Resend (HTTPS) con fallback a SMTP/Gmail
Auth:       Flask-Login · 2FA con TOTP (pyotp) · Verificación por email
Seguridad:  CSRF (Flask-WTF) · Rate limiting · HSTS · CSP · Sentry
Deploy:     Railway · GitHub Actions
PDF:        fpdf2 (informes ejecutivos exportables)
Monitoring: Sentry · APScheduler (vigilancia nocturna)
```

---

## ✨ Funcionalidades principales

- **Escaneo público desde la landing** — Sin registro, resultados en segundos
- **Dashboard completo** — Historial, tendencias, gráficos de evolución del riesgo
- **Vigilancia nocturna automatizada** — Escaneos programados con alertas por email
- **Informes PDF ejecutivos** — Exportables, compartibles con firma y puntuación
- **Multi-dominio** — Gestiona varios dominios desde una sola cuenta
- **API pública** — Endpoints autenticados con API key para integraciones
- **2FA (TOTP)** — Autenticación en dos pasos con Google Authenticator
- **Webhooks** — Slack y webhooks personalizados para alertas en tiempo real
- **Sistema de notificaciones** — In-app con tipos: SSL, uptime, DNS, scan, sistema
- **Blog integrado** — CMS interno con SEO (sitemap, JSON-LD, Open Graph)
- **Panel de administración** — Gestión de usuarios, escaneos y métricas
- **Monetización** — Plan Free (10 escaneos/mes) + Plan Pro (29€/mes) + PDF puntual (9€)

---

## ⚙️ Instalación local

### Requisitos previos
- Python 3.10+
- PostgreSQL (o SQLite para desarrollo rápido)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/Lucassesma/ReconBase.git
cd ReconBase

# 2. Crear entorno virtual
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar variables de entorno
copy .env.example .env
# Editar .env con tus credenciales (ver sección siguiente)

# 5. Ejecutar
python server.py
```

### Variables de entorno

```env
# Base de datos
DATABASE_URL=postgresql://user:pass@localhost:5432/reconbase

# Clave secreta de Flask
SECRET_KEY=genera-una-clave-segura-aqui

# Have I Been Pwned (opcional)
RECONBASE_API_KEY=tu_api_key_hibp

# Stripe (opcional — para pagos)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PRICE_PRO=price_...

# Email — opción 1: Resend (recomendado)
RESEND_API_KEY=re_...
RESEND_FROM=ReconBase <noreply@tudominio.com>

# Email — opción 2: Gmail SMTP (fallback)
MAIL_USER=tu@gmail.com
MAIL_PASS=contraseña-de-aplicacion

# Monitoring (opcional)
SENTRY_DSN=https://...@sentry.io/...
```

---

## 📁 Estructura del proyecto

```
ReconBase/
├── server.py              # App Flask — rutas, API, webhooks, crons
├── reconbase_engine.py    # Motor de escaneo (puertos, DNS, SSL, banners, CMS...)
├── models.py              # Modelos SQLAlchemy (User, Scan, Domain, SSLCheck...)
├── requirements.txt       # Dependencias Python
├── Procfile               # Configuración de deploy (Railway/Heroku)
├── runtime.txt            # Versión de Python
├── templates/
│   ├── landing.html       # Landing page con escáner inline
│   ├── app.html           # Dashboard principal
│   ├── perfil.html        # Perfil de usuario
│   ├── pricing.html       # Página de precios
│   ├── login.html         # Login con 2FA
│   ├── register.html      # Registro
│   ├── blog.html          # Blog
│   └── ...
├── static/
│   └── js/                # Scripts del cliente
├── tests/
│   ├── conftest.py        # Fixtures de pytest
│   └── test_api.py        # Tests de endpoints
└── DIARIO.md              # Diario de desarrollo (cronológico)
```

---

## 🧪 Tests

```bash
pytest tests/ -v
```

---

## 🚀 Deploy

ReconBase está configurado para Railway con un solo click:

1. Conecta tu repo de GitHub a Railway
2. Configura las variables de entorno en el dashboard
3. Railway detecta el `Procfile` (`web: gunicorn server:app`) y despliega automáticamente

---

## 📊 Modelo de negocio

| Plan | Precio | Límite | Funcionalidades |
|------|--------|--------|-----------------|
| **Free** | 0€ | 10 escaneos/mes | Escaneo completo, historial, exportar datos |
| **Pro** | 29€/mes | Ilimitado | Vigilancia nocturna, alertas por email, multi-dominio, PDF ejecutivo, API, webhooks |
| **PDF puntual** | 9€ | Por escaneo | Informe PDF sin suscripción |

---

## 🗺 Roadmap

- [ ] Dominio propio
- [ ] Stripe en modo producción
- [ ] Lanzamiento en Product Hunt
- [ ] App móvil (PWA)
- [ ] Integración con plataformas de ticketing (Jira, TheHive)

---

## 👤 Autor

Desarrollado por **Lucas** como proyecto real de ciberseguridad durante ASIR + Máster en Ciberseguridad.

---

<p align="center">
  <sub>Hecho con 🔒 en España</sub>
</p>
