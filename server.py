# ReconBase v2 — build 20260414
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, Response, abort, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from models import (db, User, Scan, Domain, BlogPost,
                    SSLCheck, UptimeCheck, Notification, DNSRecord,
                    TechDetection, IPReputation, AuditLog, Invoice, Lead,
                    ProcessedWebhook, AnonymousScan, LoginAttempt)
import reconbase_engine as engine
import os, io, json, stripe, threading, logging, urllib.request, urllib.error, hashlib, base64
import ssl as _ssl_mod, socket, time, re
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv



# ─── Sentry (error monitoring) ───
SENTRY_DSN = os.getenv("SENTRY_DSN", "")
if SENTRY_DSN:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            integrations=[FlaskIntegration()],
            traces_sample_rate=0.1,
            send_default_pii=False,
            environment=os.getenv("RAILWAY_ENVIRONMENT_NAME", "production"),
        )
    except Exception as _e:
        print(f"[Sentry] init fallo: {_e}")

try:
    from fpdf import FPDF
    PDF_OK = True
except ImportError:
    PDF_OK = False

load_dotenv()
app = Flask(__name__)
_SECRET_KEY = os.getenv("SECRET_KEY")
if not _SECRET_KEY:
    # En desarrollo local permitimos un fallback, pero en producción (Railway) lo exigimos
    if os.getenv("RAILWAY_ENVIRONMENT_NAME") or os.getenv("RAILWAY_ENVIRONMENT"):
        raise RuntimeError("SECRET_KEY no configurada en producción")
    _SECRET_KEY = "dev_only_secret_change_in_prod"
app.secret_key = _SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER']   = 'smtp.gmail.com'
app.config['MAIL_PORT']     = 587
app.config['MAIL_USE_TLS']  = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USER", "")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASS", "")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USER", "")

# ─── Analytics (opcionales) ───
app.config['PLAUSIBLE_DOMAIN'] = os.getenv("PLAUSIBLE_DOMAIN", "")
app.config['GA_ID'] = os.getenv("GA_ID", "")

# ─── Compresión gzip ───
try:
    from flask_compress import Compress
    Compress(app)
except ImportError:
    pass

db.init_app(app)
mail = Mail(app)

# ─── Wrapper de envío con fallback a Resend (HTTPS) ───
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM    = os.getenv("RESEND_FROM", "ReconBase <onboarding@resend.dev>")

def _smtp_configured():
    return bool(app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD'))

def _send_via_smtp(to, subject, body, html=None):
    """Envía por SMTP (Flask-Mail). Usado como fallback cuando Resend falla."""
    msg = Message(
        subject=subject,
        recipients=[to] if isinstance(to, str) else to,
        body=body,
    )
    if html:
        msg.html = html
    mail.send(msg)
    return True

def send_email(to, subject, body):
    """Envía un email. Intenta Resend primero; si falla con 4xx (dominio no verificado,
    API key inválida, etc.) cae a SMTP si está configurado. Lanza solo si ningún
    proveedor funciona."""
    if RESEND_API_KEY:
        payload = json.dumps({
            "from": RESEND_FROM,
            "to": [to] if isinstance(to, str) else to,
            "subject": subject,
            "text": body,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": f"ReconBase/1.0 (+{BASE_URL})",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read().decode("utf-8", errors="ignore")
                logger.info(f"[Resend] OK a {to}: {resp_body[:100]}")
                return True
        except urllib.error.HTTPError as he:
            err_raw = he.read().decode("utf-8", errors="ignore")
            # 403 tipico: sender (RESEND_FROM) no verificado o destino fuera del sandbox
            hint = ""
            if he.code == 403:
                hint = " (probable: dominio en RESEND_FROM sin verificar en resend.com/domains, o sandbox limitado al email del owner)"
            logger.warning(f"[Resend] {he.code} a {to}{hint}: {err_raw[:200]}")
            # Fallback a SMTP si esta disponible — no romper el flujo
            if _smtp_configured():
                try:
                    _send_via_smtp(to, subject, body)
                    logger.info(f"[Resend→SMTP fallback] OK a {to}")
                    return True
                except Exception as smtp_err:
                    logger.error(f"[Resend→SMTP fallback] Tambien fallo: {smtp_err}")
            try:
                err_json = json.loads(err_raw)
                err_msg = err_json.get("message") or err_json.get("error") or err_raw
            except Exception:
                err_msg = err_raw
            raise RuntimeError(f"Resend {he.code}: {err_msg}{hint}")
        except Exception as e:
            logger.warning(f"[Resend] Error red a {to}: {e}")
            if _smtp_configured():
                try:
                    _send_via_smtp(to, subject, body)
                    logger.info(f"[Resend→SMTP fallback] OK a {to}")
                    return True
                except Exception as smtp_err:
                    logger.error(f"[Resend→SMTP fallback] Tambien fallo: {smtp_err}")
            raise
    else:
        return _send_via_smtp(to, subject, body)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.getenv("REDIS_URL", "memory://")
)

# ─── CSRF protection ───
# Pragmatic setup: protege los formularios HTML tradicionales.
# Los endpoints /api/* se exentan porque usan cookies SameSite=Lax + fetch mismo origen.
# El webhook de Stripe se exenta porque tiene su propia verificación por firma.
csrf = CSRFProtect(app)
app.config['WTF_CSRF_TIME_LIMIT'] = 3600 * 24  # token válido 24h
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv("RAILWAY_ENVIRONMENT_NAME") is not None  # True en Railway
# ─── Sesiones persistentes (30 días) ───
# Por defecto Flask usa "session cookies" que se borran al cerrar el navegador.
# Con esto la sesión sobrevive al cerrar pestaña/navegador hasta 30 días.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
# Flask-Login "remember me" cookie (sobrevive incluso si la session se invalida)
app.config['REMEMBER_COOKIE_DURATION']  = timedelta(days=30)
app.config['REMEMBER_COOKIE_HTTPONLY']  = True
app.config['REMEMBER_COOKIE_SAMESITE']  = 'Lax'
app.config['REMEMBER_COOKIE_SECURE']    = os.getenv("RAILWAY_ENVIRONMENT_NAME") is not None  # True en Railway

@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)

# ─── Cabeceras HTTP de seguridad ───
@app.after_request
def set_security_headers(resp):
    # HSTS: forzar HTTPS durante 1 año (preload para envío a lista global del navegador)
    resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
    # X-XSS-Protection: 0 desactiva el auditor legacy (recomendación OWASP moderna)
    resp.headers.setdefault('X-XSS-Protection', '0')
    # COOP: aísla la ventana del sitio de popups cross-origin
    resp.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
    # Anti clickjacking
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    # Anti MIME-sniffing
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    # Referrer: no filtrar URLs internas a terceros
    resp.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    # Permisos del navegador restringidos
    resp.headers.setdefault(
        'Permissions-Policy',
        'camera=(), microphone=(), geolocation=(), payment=(self "https://checkout.stripe.com")'
    )
    # CSP relajada pero razonable (el sitio usa inline JS/CSS, Google Fonts y Chart.js CDN)
    resp.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://js.stripe.com https://plausible.io https://www.googletagmanager.com https://*.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://challenges.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.stripe.com https://plausible.io https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com; "
        "frame-src https://js.stripe.com https://checkout.stripe.com https://www.googletagmanager.com https://challenges.cloudflare.com; "
        "form-action 'self' https://checkout.stripe.com; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    return resp

# ─── Bloquear acceso a ficheros sensibles ─────────────────────────────────────
_BLOCKED_EXT   = ('.log', '.env', '.cfg', '.ini', '.conf', '.bak', '.sql', '.db', '.sqlite', '.py')
_BLOCKED_NAMES = {'debug.log', '.env', 'config.py', 'server.py', 'models.py', 'requirements.txt'}

@app.before_request
def block_sensitive_files():
    path = request.path.lstrip('/')
    lpath = path.lower()
    if any(lpath.endswith(ext) for ext in _BLOCKED_EXT) or path in _BLOCKED_NAMES:
        abort(404)


# ─── Redirect canónico al dominio oficial (SEO + rel="canonical" + trust) ───
# Config: export CANONICAL_HOST=reconbase.es (en Railway). Si no está set, se
# desactiva — útil en desarrollo local o si aún no has apuntado el DNS.
CANONICAL_HOST = (os.getenv("CANONICAL_HOST", "") or "").strip().lower()

@app.before_request
def enforce_canonical_host():
    if not CANONICAL_HOST:
        return  # desactivado
    host = (request.host or "").lower()
    # Extraer sólo el hostname (sin puerto) para comparar
    host_only = host.split(":")[0]
    if host_only == CANONICAL_HOST:
        return  # ya estamos en el canónico
    # No redirigir webhook, healthchecks ni endpoints de verificación ACME.
    # Tampoco redirigir /robots.txt: queremos que el host no-canónico responda
    # un robots.txt con "Disallow: /" para que crawlers saquen ese host del índice.
    skip_prefixes = ("/api/webhook", "/.well-known/", "/robots.txt")
    if any(request.path.startswith(p) for p in skip_prefixes):
        return
    # Preservar path + query
    target = f"https://{CANONICAL_HOST}{request.full_path.rstrip('?') if request.query_string else request.path}"
    resp = redirect(target, code=301)
    # Doble señal a Google/Bing/Brave: este host alternativo NO indexar.
    # Sirve para que cuando recrawlen el URL viejo lo saquen del índice.
    resp.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return resp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("reconbase")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

API_KEY        = os.getenv("RECONBASE_API_KEY", "")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_PRO = os.getenv("STRIPE_PRICE_PRO", "")
STRIPE_PRICE_PRO_ANUAL = os.getenv("PRICE_PRO_ANUAL", "") or os.getenv("STRIPE_PRICE_PRO_ANUAL", "")

# URL pública del sitio. Configurar BASE_URL en el entorno de producción
# (ej: Railway) con el dominio definitivo. En desarrollo local cae a localhost.
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000").rstrip("/")
# Host "bonito" para mostrar en emails / PDFs / footers (sin esquema)
BASE_HOST = BASE_URL.split("://", 1)[-1]

@app.context_processor
def inject_base_url():
    return {"base_url": BASE_URL, "base_host": BASE_HOST}

# ── RUTAS PÚBLICAS ──

@app.route("/sitemap.xml")
def sitemap():
    base = BASE_URL
    today = datetime.utcnow().strftime("%Y-%m-%d")
    urls = [
        {"loc": base + "/",        "priority": "1.0",  "changefreq": "weekly",  "lastmod": today},
        {"loc": base + "/login",   "priority": "0.6",  "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/register","priority": "0.8",  "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/pricing", "priority": "0.9",  "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/terms",   "priority": "0.3",  "changefreq": "yearly",  "lastmod": today},
        {"loc": base + "/privacy", "priority": "0.3",  "changefreq": "yearly",  "lastmod": today},
        {"loc": base + "/cookies", "priority": "0.3",  "changefreq": "yearly",  "lastmod": today},
        {"loc": base + "/blog",    "priority": "0.7",  "changefreq": "weekly",  "lastmod": today},
        {"loc": base + "/comprobar-dmarc-spf", "priority": "0.9", "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/auditoria-wordpress",  "priority": "0.9", "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/auditoria-prestashop", "priority": "0.9", "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/skimmer-check",        "priority": "0.85","changefreq": "monthly", "lastmod": today},
        {"loc": base + "/status",  "priority": "0.5",  "changefreq": "daily",   "lastmod": today},
    ]
    # Añadir posts del blog con su lastmod real
    try:
        blog_posts = BlogPost.query.filter_by(publicado=True).all()
        for bp in blog_posts:
            lastmod = getattr(bp, "updated_at", None) or getattr(bp, "created_at", None)
            urls.append({
                "loc": f"{base}/blog/{bp.slug}",
                "priority": "0.6",
                "changefreq": "monthly",
                "lastmod": lastmod.strftime("%Y-%m-%d") if lastmod else today,
            })
    except Exception:
        pass
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for u in urls:
        xml += (f'  <url><loc>{u["loc"]}</loc>'
                f'<lastmod>{u["lastmod"]}</lastmod>'
                f'<changefreq>{u["changefreq"]}</changefreq>'
                f'<priority>{u["priority"]}</priority></url>\n')
    xml += '</urlset>'
    from flask import Response
    return Response(xml, mimetype="application/xml")

@app.route("/robots.txt")
def robots():
    from flask import Response
    # Si la petición viene del dominio NO canónico (ej. railway.app),
    # respondemos un robots.txt restrictivo que dice "no indexes nada de aquí".
    # Esto fuerza a Google/Bing/Brave a sacar ese host de su índice cuando
    # recrawleen, manteniendo solo reconbase.es en los resultados.
    host_only = (request.host or "").split(":")[0].lower()
    if CANONICAL_HOST and host_only != CANONICAL_HOST:
        txt = (
            "User-agent: *\n"
            "Disallow: /\n"
            f"# Canonical host: {CANONICAL_HOST}\n"
            f"Sitemap: {BASE_URL}/sitemap.xml\n"
        )
        return Response(txt, mimetype="text/plain")
    # Host canónico: política normal
    txt = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /app\n"
        "Disallow: /api/\n"
        "Disallow: /perfil\n"
        "Disallow: /admin\n"
        "Disallow: /verificar-email\n"
        "Disallow: /reset-password\n"
        f"Sitemap: {BASE_URL}/sitemap.xml\n"
    )
    return Response(txt, mimetype="text/plain")


# ── PROXY PLAUSIBLE — esquiva adblockers sin romper la privacidad ──
# El script y los eventos se sirven desde reconbase.es (no plausible.io)
# de modo que filtros como uBlock/Brave Shields no los bloquean.
# Plausible recibe el evento normal incluyendo X-Forwarded-For del visitante.
_PLAUSIBLE_SCRIPT_URL = "https://plausible.io/js/pa-uwYWoSD9fwi10xFjxribC.js"
_PLAUSIBLE_EVENT_URL  = "https://plausible.io/api/event"
_PLAUSIBLE_SCRIPT_CACHE = {"data": None, "ts": 0}

@app.route("/js/pa.js")
def proxy_plausible_script():
    """Sirve el script de Plausible desde nuestro dominio. Cachea 1h en memoria."""
    import time as _t
    from flask import Response
    now = _t.time()
    if _PLAUSIBLE_SCRIPT_CACHE["data"] and (now - _PLAUSIBLE_SCRIPT_CACHE["ts"]) < 3600:
        return Response(_PLAUSIBLE_SCRIPT_CACHE["data"], mimetype="application/javascript",
                        headers={"Cache-Control": "public, max-age=3600"})
    try:
        req = urllib.request.Request(_PLAUSIBLE_SCRIPT_URL,
                                     headers={"User-Agent": "ReconBase-Proxy/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read()
            _PLAUSIBLE_SCRIPT_CACHE["data"] = body
            _PLAUSIBLE_SCRIPT_CACHE["ts"]   = now
            return Response(body, mimetype="application/javascript",
                            headers={"Cache-Control": "public, max-age=3600"})
    except Exception as e:
        logger.warning(f"[PlausibleProxy] script fetch falló: {e}")
        # Devolver un stub que no rompe nada
        stub = b"window.plausible=window.plausible||function(){};"
        return Response(stub, mimetype="application/javascript",
                        headers={"Cache-Control": "no-cache"})


@app.route("/api/track", methods=["POST"])
@limiter.limit("300 per minute")
def proxy_plausible_event():
    """Reenvía el evento al endpoint real de Plausible añadiendo
    X-Forwarded-For para que cuente la IP del visitante real."""
    payload = request.get_data()
    if not payload:
        return ("", 204)
    # IP real del visitante (Cloudflare la pone en CF-Connecting-IP)
    real_ip = (request.headers.get("CF-Connecting-IP")
               or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
               or request.remote_addr or "")
    user_agent = request.headers.get("User-Agent", "Mozilla/5.0")
    fwd_headers = {
        "Content-Type": "application/json",
        "User-Agent": user_agent,
        "X-Forwarded-For": real_ip,
    }
    try:
        req = urllib.request.Request(_PLAUSIBLE_EVENT_URL, data=payload,
                                     headers=fwd_headers, method="POST")
        with urllib.request.urlopen(req, timeout=4) as resp:
            return ("", resp.status)
    except urllib.error.HTTPError as he:
        # Reenviar el código de estado real (Plausible puede devolver 202/400/etc)
        return ("", he.code)
    except Exception as e:
        # Fallar silenciosamente — analytics nunca debe romper el flujo del usuario
        logger.warning(f"[PlausibleProxy] event forward falló: {e}")
        return ("", 202)  # Decir OK al cliente para no contaminar logs del browser


# ── SEO: Herramienta gratuita DMARC/SPF ──
@app.route("/comprobar-dmarc-spf")
def tool_dmarc_spf():
    return render_template("tool_dmarc_spf.html")

@app.route("/auditoria-wordpress")
def landing_wordpress():
    """Landing especializada para auditoría WordPress. SEO-first."""
    return render_template("landing_wordpress.html")

@app.route("/auditoria-prestashop")
def landing_prestashop():
    """Landing especializada para auditoría PrestaShop. SEO-first.
    Incluye detector de skimmers digitales (diferenciador 2026)."""
    return render_template("landing_prestashop.html")

@app.route("/skimmer-check")
def tool_skimmer_check():
    """Herramienta gratuita standalone: solo detector de skimmers Magecart.
    SEO ultra-específico ('comprobar skimmer prestashop', 'magecart scanner')."""
    return render_template("tool_skimmer_check.html")

@app.route("/api/skimmer-check", methods=["POST"])
@limiter.limit("20 per hour")
def api_skimmer_check():
    """Endpoint público que ejecuta SOLO el check de skimmer sobre un dominio.
    No requiere registro. Devuelve si hay sospecha + evidencia + ruta de checkout."""
    import re as _re
    data = request.get_json(silent=True) or {}
    raw  = (data.get("dominio") or "").strip()[:255]
    if not raw:
        return jsonify({"error": "Introduce un dominio"}), 400
    dominio = _re.sub(r'^https?://', '', raw, flags=_re.IGNORECASE)
    dominio = dominio.replace("www.", "").split("/")[0].strip().lower()
    if not dominio or "." not in dominio:
        return jsonify({"error": "Dominio inválido"}), 400

    try:
        ps = engine.prestashop_audit(dominio)
    except Exception as e:
        logger.warning(f"[skimmer-check] error en {dominio}: {e}")
        return jsonify({"error": "No se pudo escanear el dominio (timeout o respuesta inválida)"}), 500

    response = {
        "dominio": dominio,
        "is_prestashop": ps.get("is_prestashop", False),
        "version": ps.get("version"),
        "skimmer_suspect": ps.get("skimmer_suspect", False),
        "skimmer_evidence": ps.get("skimmer_evidence", []),
        "timestamp": datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
    }
    # Si NO es PrestaShop, devolvemos respuesta correcta pero sin análisis (la heurística PS solo aplica a PS)
    if not ps.get("is_prestashop"):
        response["note"] = ("No se detectó PrestaShop en este dominio. El detector de skimmers de ReconBase "
                            "está optimizado para tiendas PrestaShop. Para análisis genérico usa la auditoría completa.")
    # Tracking ligero: guardar en AnonymousScan para verlo en /admin/metricas
    try:
        ip_real = (request.headers.get("CF-Connecting-IP")
                   or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                   or request.remote_addr or "")
        ip_h = hashlib.sha256((ip_real + "rb_salt_2026").encode()).hexdigest()[:16] if ip_real else None
        label = "SKIMMER" if ps.get("skimmer_suspect") else ("PS-OK" if ps.get("is_prestashop") else "NO-PS")
        db.session.add(AnonymousScan(
            dominio=dominio[:255],
            riesgo=100 if ps.get("skimmer_suspect") else 0,
            label=label[:20], ip_hash=ip_h,
            referer=(request.headers.get("Referer") or "")[:255],
            user_agent=(request.headers.get("User-Agent") or "")[:100],
            es_logged=bool(getattr(current_user, "is_authenticated", False))
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify(response)

@app.route("/api/check-dmarc-spf", methods=["POST"])
@limiter.limit("30 per hour")
def api_check_dmarc_spf():
    """Comprueba SPF + DMARC de un dominio. Público, sin login. Devuelve raw para educar al usuario."""
    import re as _re
    data = request.get_json(silent=True) or {}
    raw  = (data.get("dominio") or "").strip()[:255]
    if not raw:
        return jsonify({"error": "Introduce un dominio"}), 400

    # Limpiar: quitar http(s)://, www., paths, @ (si vino email)
    dominio = raw.split("@")[-1] if "@" in raw else raw
    dominio = _re.sub(r'^https?://', '', dominio).replace("www.", "").split("/")[0].strip().lower()
    if not dominio or "." not in dominio:
        return jsonify({"error": "Dominio inválido"}), 400

    spf_present, spf_raw = False, ""
    dmarc_present, dmarc_raw = False, ""

    try:
        import dns.resolver as _dr
        resolver = _dr.Resolver()
        resolver.lifetime = 5
        try:
            for rd in resolver.resolve(dominio, "TXT"):
                txt = rd.to_text().strip('"')
                if "v=spf1" in txt.lower():
                    spf_present = True
                    spf_raw = txt
                    break
        except Exception:
            pass
        try:
            for rd in resolver.resolve("_dmarc." + dominio, "TXT"):
                txt = rd.to_text().strip('"')
                if "v=dmarc1" in txt.lower():
                    dmarc_present = True
                    dmarc_raw = txt
                    break
        except Exception:
            pass
    except ImportError:
        # Fallback DNS-over-HTTPS (Google)
        try:
            import urllib.request as _ur, urllib.parse as _up
            def _doh(name):
                url = f"https://dns.google/resolve?name={_up.quote(name)}&type=TXT"
                req = _ur.Request(url, headers={"Accept": "application/dns-json"})
                with _ur.urlopen(req, timeout=5) as r:
                    return json.loads(r.read().decode("utf-8"))
            r = _doh(dominio)
            for ans in r.get("Answer", []) or []:
                data_txt = (ans.get("data") or "").strip('"')
                if "v=spf1" in data_txt.lower():
                    spf_present = True; spf_raw = data_txt; break
            r2 = _doh("_dmarc." + dominio)
            for ans in r2.get("Answer", []) or []:
                data_txt = (ans.get("data") or "").strip('"')
                if "v=dmarc1" in data_txt.lower():
                    dmarc_present = True; dmarc_raw = data_txt; break
        except Exception as e:
            logger.warning(f"[DMARC tool] DoH fallback error {dominio}: {e}")

    return jsonify({
        "dominio": dominio,
        "spf":   spf_present,
        "spf_raw":   spf_raw,
        "dmarc": dmarc_present,
        "dmarc_raw": dmarc_raw,
    })

@app.route("/google9b381a283a68cc0a.html")
def google_verify():
    return "google-site-verification: google9b381a283a68cc0a.html"

# ── OG Image (PNG dinámico para redes sociales) ──
_og_cache = {}

# ── Favicon + apple-touch-icon (matan los 4xx en métricas) ──
_FAVICON_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    b'<rect width="32" height="32" rx="6" fill="#080C14"/>'
    b'<text x="3" y="23" font-family="Arial Black,sans-serif" font-weight="900" font-size="18" fill="#E2EDF8">R</text>'
    b'<text x="16" y="23" font-family="Arial Black,sans-serif" font-weight="900" font-size="18" fill="#22C55E">B</text>'
    b'</svg>'
)

@app.route("/favicon.ico")
@app.route("/favicon.svg")
@app.route("/static/favicon.svg")
@app.route("/apple-touch-icon.png")
@app.route("/apple-touch-icon-precomposed.png")
def favicon():
    """Sirve el logo SVG. Browsers piden favicon.ico cada visita y
    iOS Safari pide apple-touch-icon. Cubrir aquí evita 404 spam."""
    from flask import Response
    return Response(_FAVICON_SVG, mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


# ── /.well-known/security.txt (RFC 9116, recomendación Cloudflare) ──
@app.route("/.well-known/security.txt")
def security_txt():
    """Permite a investigadores reportar vulnerabilidades de forma estándar."""
    from flask import Response
    expires = (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    txt = (
        "Contact: mailto:hola@reconbase.es\n"
        f"Expires: {expires}\n"
        "Preferred-Languages: es, en\n"
        "Canonical: https://reconbase.es/.well-known/security.txt\n"
        "Policy: https://reconbase.es/privacy\n"
    )
    return Response(txt, mimetype="text/plain",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.route("/og/<page>.png")
def og_image(page):
    """Genera OG image 1200x630 PNG con Pillow. Cache en memoria."""
    if page in _og_cache:
        buf = io.BytesIO(_og_cache[page])
        return send_file(buf, mimetype="image/png", max_age=86400)

    from PIL import Image, ImageDraw, ImageFont
    W, H = 1200, 630
    img = Image.new("RGB", (W, H), "#060D09")
    draw = ImageDraw.Draw(img)

    # Grid sutil
    for x in range(0, W, 40):
        draw.line([(x, 0), (x, H)], fill="#0f1f16", width=1)
    for y in range(0, H, 40):
        draw.line([(0, y), (W, y)], fill="#0f1f16", width=1)

    # Usar fuente por defecto (disponible en cualquier servidor)
    try:
        font_big   = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 72)
        font_med   = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 28)
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 22)
    except Exception:
        font_big   = ImageFont.load_default()
        font_med   = font_big
        font_small = font_big

    pages_info = {
        "home": {
            "title": "RECONBASE",
            "sub": "Analiza la seguridad de tu empresa gratis",
            "features": ["Puertos expuestos", "Filtraciones de datos", "Vulnerabilidades DNS"],
        },
        "pricing": {
            "title": "RECONBASE",
            "sub": "Planes desde 0\u20ac \u2014 Ciberseguridad para PYMEs",
            "features": ["Plan Gratis: 10 escaneos/mes", "Plan Pro: 29\u20ac/mes ilimitado", "Sin permanencia"],
        },
        "terms": {
            "title": "RECONBASE",
            "sub": "T\u00e9rminos de Servicio",
            "features": [],
        },
        "privacy": {
            "title": "RECONBASE",
            "sub": "Pol\u00edtica de Privacidad",
            "features": [],
        },
    }
    info = pages_info.get(page, pages_info["home"])

    # Logo
    logo_text = info["title"]
    bbox = draw.textbbox((0, 0), logo_text, font=font_big)
    tw = bbox[2] - bbox[0]
    x_logo = (W - tw) // 2
    # Dibujar "RECON" en blanco y "BASE" en verde
    recon_bbox = draw.textbbox((0, 0), "RECON", font=font_big)
    recon_w = recon_bbox[2] - recon_bbox[0]
    base_bbox = draw.textbbox((0, 0), "BASE", font=font_big)
    base_w = base_bbox[2] - base_bbox[0]
    total_w = recon_w + base_w
    x_start = (W - total_w) // 2
    draw.text((x_start, 180), "RECON", fill="#E2EDF8", font=font_big)
    draw.text((x_start + recon_w, 180), "BASE", fill="#22C55E", font=font_big)

    # Subtitulo
    sub = info["sub"]
    sub_bbox = draw.textbbox((0, 0), sub, font=font_med)
    sub_w = sub_bbox[2] - sub_bbox[0]
    draw.text(((W - sub_w) // 2, 280), sub, fill="#64748B", font=font_med)

    # Linea
    draw.line([(400, 340), (800, 340)], fill="#152B1E", width=2)

    # Features
    features = info["features"]
    if features:
        y_feat = 380
        for i, f in enumerate(features):
            f_bbox = draw.textbbox((0, 0), f, font=font_small)
            f_w = f_bbox[2] - f_bbox[0]
            draw.text(((W - f_w) // 2, y_feat), f, fill="#22C55E", font=font_small)
            y_feat += 40

    # CTA
    cta = BASE_HOST
    cta_bbox = draw.textbbox((0, 0), cta, font=font_small)
    cta_w = cta_bbox[2] - cta_bbox[0]
    draw.text(((W - cta_w) // 2, 550), cta, fill="#475569", font=font_small)

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    _og_cache[page] = buf.getvalue()
    buf.seek(0)
    return send_file(buf, mimetype="image/png", max_age=86400)

@app.route("/")
def index():
    plan        = "guest"
    scans_mes   = 0
    ultimo_auto = None
    scan_hora   = 3
    scan_dias   = []
    if current_user.is_authenticated:
        from sqlalchemy import extract
        now = datetime.utcnow()
        try:
            scans_mes = Scan.query.filter(
                Scan.user_id == current_user.id,
                extract('month', Scan.timestamp) == now.month,
                extract('year',  Scan.timestamp) == now.year
            ).count()
        except Exception as e:
            logger.warning(f"[Index] count scans_mes falló: {e}")
            db.session.rollback()
            scans_mes = 0
        # ⚠️ Defensive: si algún scan tiene bytes raros en JSON (NUL byte legacy),
        # el operador ->> revienta. Hacer fallback graceful.
        try:
            ultimo_auto = Scan.query.filter_by(user_id=current_user.id).filter(
                Scan.resultado.op('->>')('automatico') == 'true'
            ).order_by(Scan.timestamp.desc()).first()
        except Exception as e:
            logger.warning(f"[Index] ultimo_auto query falló (probable bad JSON en DB): {e}")
            db.session.rollback()
            ultimo_auto = None
        plan      = current_user.plan_efectivo
        scan_hora = current_user.scan_hora if current_user.scan_hora is not None else 3
        scan_dias = current_user.scan_dias.split(',') if current_user.scan_dias else []
    # ── Detectar si el usuario tiene tiendas PrestaShop sin vigilancia automática ──
    # El sentido: si tiene PS detectado en algún escaneo previo + NO tiene vigilancia
    # activa, mostrarle un banner que le invite a activar la monitorización (skimmers).
    tiene_ps_sin_vigilancia = False
    ps_dominios_sample = []
    if current_user.is_authenticated and not scan_dias:
        try:
            ps_scans = db.session.query(Scan.dominio).filter(
                Scan.user_id == current_user.id,
                Scan.resultado.op('->')('ps').op('->>')('is_prestashop') == 'true'
            ).distinct().limit(3).all()
            if ps_scans:
                tiene_ps_sin_vigilancia = True
                ps_dominios_sample = [r[0] for r in ps_scans if r[0]]
        except Exception as e:
            # Si la query JSON falla por bad data, no romper la home
            db.session.rollback()
            logger.warning(f"[Index] query ps_scans falló: {e}")
    stats_scans   = Scan.query.count()
    stats_vulns   = max(int(stats_scans * 2.3), 12)
    stats_breaches = User.query.count()
    # Si el usuario ya dio consentimiento (cookie HTTP), NO renderizamos el banner.
    # Esto elimina cualquier race condition o parpadeo en cliente.
    show_cookie_banner = not request.cookies.get("cookie_consent")
    resp = make_response(render_template("landing.html", user=current_user,
                           plan=plan, scans_mes=scans_mes,
                           ultimo_auto=ultimo_auto,
                           api_key_ok=bool(API_KEY),
                           scan_hora=scan_hora, scan_dias=scan_dias,
                           stats_scans=stats_scans,
                           stats_vulns=stats_vulns,
                           stats_breaches=stats_breaches,
                           tiene_ps_sin_vigilancia=tiene_ps_sin_vigilancia,
                           ps_dominios_sample=ps_dominios_sample,
                           show_cookie_banner=show_cookie_banner))
    # Evitar que el navegador cachee el HTML (para que los fixes lleguen al instante)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")

@app.route("/api/forgot-password", methods=["POST"])
@limiter.limit("5 per hour")
def api_forgot_password():
    data  = request.get_json()
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"ok": False, "error": "Introduce tu email"}), 400
    user = User.query.filter_by(email=email).first()
    if user:
        user.generate_reset_token()
        db.session.commit()
        enviar_email_reset(user)
    # Siempre OK para no revelar si el email existe
    return jsonify({"ok": True})

@app.route("/reset-password/<token>")
def reset_password_page(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expiry or datetime.utcnow() > user.reset_token_expiry:
        return render_template("verify_result.html", ok=False,
                               msg="Enlace no válido o ha expirado. Solicita uno nuevo.")
    return render_template("reset_password.html", token=token)

@app.route("/api/reset-password", methods=["POST"])
@limiter.limit("10 per hour")
def api_reset_password():
    data     = request.get_json()
    token    = data.get("token", "")
    password = data.get("password", "")
    if len(password) < 8:
        return jsonify({"ok": False, "error": "Mínimo 8 caracteres"}), 400
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expiry or datetime.utcnow() > user.reset_token_expiry:
        return jsonify({"ok": False, "error": "Enlace expirado"}), 400
    user.set_password(password)
    user.reset_token = None
    user.reset_token_expiry = None
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/share-scan", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def share_scan():
    """Genera un link público para compartir un escaneo."""
    data    = request.get_json()
    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify({"ok": False, "error": "scan_id requerido"}), 400
    scan_obj = Scan.query.filter_by(id=int(scan_id), user_id=current_user.id).first()
    if not scan_obj:
        return jsonify({"ok": False, "error": "Escaneo no encontrado"}), 404
    if not scan_obj.share_token:
        import secrets as _sec
        scan_obj.share_token = _sec.token_urlsafe(16)
        db.session.commit()
    base_url = BASE_URL
    return jsonify({"ok": True, "url": f"{base_url}/report/{scan_obj.share_token}"})

@app.route("/report/<token>")
def report_publico(token):
    scan_obj = Scan.query.filter_by(share_token=token).first()
    if not scan_obj:
        return render_template("404.html"), 404
    return render_template("report_public.html", scan=scan_obj, resultado=scan_obj.resultado)

@app.route("/pago-exito")
def pago_exito():
    """Página tras pago. Sirve también como fallback de reconciliación:
    si el webhook no llegó (eventos en cola, fallo de red, etc.), aquí
    consultamos a Stripe la sesión y actualizamos el plan del usuario."""
    session_id = request.args.get("session_id", "")
    reconciled = False
    if session_id and current_user.is_authenticated and stripe.api_key:
        try:
            sess = stripe.checkout.Session.retrieve(session_id)
            # Verificar que la sesión es de este usuario (anti-spoofing)
            ref = getattr(sess, "client_reference_id", None)
            same_user = (ref and str(ref) == str(current_user.id))
            email_match = (getattr(sess, "customer_email", "") or "").lower() == current_user.email.lower()
            if same_user or email_match:
                mode = getattr(sess, "mode", None)
                # payment_status puede ser 'paid', 'unpaid', 'no_payment_required' (cupón 100%)
                pstatus = getattr(sess, "payment_status", "")
                if mode == "subscription" and pstatus in ("paid", "no_payment_required"):
                    if current_user.plan != "pro":
                        current_user.plan = "pro"
                        db.session.commit()
                        reconciled = True
                        logger.info(f"[PagoExito] Reconciliación: plan→pro para {current_user.email} (session {session_id})")
                        try:
                            enviar_email_pro_activado(current_user)
                        except Exception as _me:
                            logger.warning(f"[PagoExito] email pro_activado: {_me}")
                        # Crear factura si no hay ya una para esta sesión
                        try:
                            meta = getattr(sess, "metadata", {}) or {}
                            billing = (meta.get("billing") if hasattr(meta, "get") else None) or "mensual"
                            amount_total = getattr(sess, "amount_total", None)
                            currency = (getattr(sess, "currency", "eur") or "eur").upper()
                            desde = datetime.utcnow()
                            if billing in ("anual", "annual", "yearly"):
                                hasta = desde + timedelta(days=365)
                                concepto = "Plan Pro ReconBase — Suscripción anual"
                                importe_default = 290.00
                            else:
                                hasta = desde + timedelta(days=30)
                                concepto = "Plan Pro ReconBase — Suscripción mensual"
                                importe_default = 29.00
                            importe = (amount_total / 100.0) if amount_total else importe_default
                            inv = Invoice(
                                user_id=current_user.id,
                                stripe_invoice_id=getattr(sess, "id", None),
                                numero=_generar_numero_factura(),
                                concepto=concepto,
                                importe=importe,
                                moneda=currency,
                                estado='pagada',
                                periodo_desde=desde,
                                periodo_hasta=hasta,
                            )
                            db.session.add(inv)
                            db.session.commit()
                        except Exception as _ie:
                            logger.warning(f"[PagoExito] crear factura: {_ie}")
                            db.session.rollback()
        except Exception as e:
            logger.warning(f"[PagoExito] retrieve session {session_id}: {e}")
    return render_template("pago_exito.html", reconciled=reconciled)

@app.route("/terms")
def terms():
    return render_template("terms.html")


# ── PÁGINA DE STATUS PÚBLICO ──
@app.route("/status")
def status_page():
    """Estado público de los servicios. Renderiza la plantilla; los checks
    se hacen vía /api/status para no bloquear la primera carga."""
    return render_template("status.html")


@app.route("/api/status")
@limiter.limit("60 per hour")
def api_status():
    """JSON con el estado de cada dependencia. Cacheado en memoria 60s para
    no machacar a Stripe/Resend si recargan la página varias veces."""
    cache_key = "_rb_status_cache"
    cache_ts_key = "_rb_status_ts"
    now = time.time()
    cached = getattr(app, cache_key, None)
    cached_ts = getattr(app, cache_ts_key, 0)
    if cached and (now - cached_ts) < 60:
        return jsonify(cached)

    def _check(name, fn, timeout=4):
        t0 = time.time()
        try:
            ok, detail = fn()
            return {
                "name": name,
                "ok": bool(ok),
                "latency_ms": int((time.time() - t0) * 1000),
                "detail": detail or ("Operativo" if ok else "Caído"),
            }
        except Exception as e:
            return {
                "name": name,
                "ok": False,
                "latency_ms": int((time.time() - t0) * 1000),
                "detail": str(e)[:120],
            }

    def _check_db():
        try:
            from sqlalchemy import text as _sa_text
            db.session.execute(_sa_text("SELECT 1"))
            return True, "Operativa"
        except Exception as e:
            db.session.rollback()
            return False, str(e)[:120]

    def _http_head(url, timeout=4, expected=(200, 204, 301, 302, 401, 403)):
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "ReconBase-Status/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status in expected:
                    return True, f"HTTP {resp.status}"
                return False, f"HTTP {resp.status}"
        except urllib.error.HTTPError as he:
            if he.code in expected:
                return True, f"HTTP {he.code}"
            return False, f"HTTP {he.code}"
        except Exception as e:
            return False, str(e)[:80]

    services = []
    services.append(_check("Web (HTTP/HTTPS)", lambda: (True, "Servidor activo")))
    services.append(_check("Base de datos PostgreSQL", _check_db))
    # Stripe: usa /v1 (devuelve 401 sin auth, lo cual confirma que el API está vivo).
    services.append(_check("Stripe (pagos)", lambda: _http_head("https://api.stripe.com/v1/charges", expected=(200,401,403))))
    # Resend: igual; sin token devuelve 401, eso prueba que la API responde.
    services.append(_check("Resend (emails)", lambda: _http_head("https://api.resend.com/emails", expected=(200,401,403,405))))
    services.append(_check("Cloudflare (DNS/CDN)", lambda: _http_head("https://www.cloudflare.com")))

    overall = all(s["ok"] for s in services)
    if overall:
        global_status = "operational"
    elif any(s["ok"] for s in services):
        global_status = "degraded"
    else:
        global_status = "outage"

    payload = {
        "status": global_status,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "services": services,
    }
    setattr(app, cache_key, payload)
    setattr(app, cache_ts_key, now)
    return jsonify(payload)

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/cookies")
def cookies_policy():
    return render_template("cookies.html")

@app.route("/register")
def register_page():
    return render_template("register.html",
                           turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY", ""))

@app.route("/pricing")
def pricing_page():
    return render_template("pricing.html", user=current_user if current_user.is_authenticated else None)

# ── AUTH API ──
def _track_login_attempt(email, exito, razon):
    """Guarda un intento de login (éxito o fallo) en la tabla login_attempts.
    Silencioso ante errores — nunca debe romper el login."""
    try:
        ip_real = (request.headers.get("CF-Connecting-IP")
                   or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                   or request.remote_addr or "")
        ua = (request.headers.get("User-Agent") or "")[:255]
        db.session.add(LoginAttempt(
            email=(email or "")[:120],
            ip=ip_real[:45] or None,
            user_agent=ua or None,
            exito=bool(exito),
            razon=(razon or "")[:50]
        ))
        db.session.commit()
    except Exception as _e:
        db.session.rollback()
        logger.warning(f"[LoginAttempt] no se pudo guardar: {_e}")

def _marcar_login_exitoso(user):
    """Actualiza last_login + login_count del usuario tras login OK."""
    try:
        ip_real = (request.headers.get("CF-Connecting-IP")
                   or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                   or request.remote_addr or "")
        user.last_login = datetime.utcnow()
        user.last_login_ip = ip_real[:45] or None
        user.login_count = (user.login_count or 0) + 1
        db.session.commit()
    except Exception as _e:
        db.session.rollback()
        logger.warning(f"[LoginOK] no se pudo actualizar usuario: {_e}")


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute; 30 per hour")
def api_login():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    user     = User.query.filter_by(email=email).first()
    if not user:
        _track_login_attempt(email, exito=False, razon="no_user")
        return jsonify({"ok": False, "error": "Email o contraseña incorrectos"}), 401
    if not user.check_password(password):
        _track_login_attempt(email, exito=False, razon="wrong_pass")
        return jsonify({"ok": False, "error": "Email o contraseña incorrectos"}), 401
    # Bloquear login si el email no está verificado todavía
    if not user.email_verified:
        _track_login_attempt(email, exito=False, razon="unverified")
        # Reenviar el email de verificación automáticamente (idempotente, regenera token si hace falta)
        try:
            if not user.verify_token:
                user.generate_verify_token()
                db.session.commit()
            enviar_email_verificacion(user)
        except Exception as e:
            logger.warning(f"[Login] No se pudo reenviar verificacion a {email}: {e}")
        return jsonify({
            "ok": False,
            "needs_verification": True,
            "error": "Tu email aún no está verificado. Te hemos reenviado el enlace de confirmación a tu bandeja."
        }), 403
    # Si tiene 2FA activado, no hacer login todavía — pedir código TOTP
    if getattr(user, 'totp_enabled', False) and user.totp_secret:
        session["2fa_pending_user"] = user.id
        return jsonify({"ok": True, "requires_2fa": True})
    # Sesión persistente: sobrevive a cerrar el navegador hasta 30 días
    session.permanent = True
    login_user(user, remember=True, duration=timedelta(days=30))
    _marcar_login_exitoso(user)
    _track_login_attempt(email, exito=True, razon="ok")
    _registrar_audit(user.id, 'login', f"Login exitoso desde {request.remote_addr}")
    return jsonify({"ok": True})

def enviar_email_verificacion(user):
    # 1) Extraer atributos MIENTRAS la sesión SQLAlchemy está activa.
    #    Después del commit, el objeto queda detached y acceder a .email
    #    desde un hilo aparte lanza DetachedInstanceError.
    email_destino   = user.email
    nombre_empresa  = user.empresa
    verify_token    = user.verify_token
    base_url        = BASE_URL
    link            = f"{base_url}/verify-email/{verify_token}"

    def _send(email, empresa, link_url):
        try:
            with app.app_context():
                send_html_email(
                    email,
                    "Confirma tu email — ReconBase",
                    "Verifica tu dirección de email",
                    f"""<p>Hola {empresa},</p>
<p>Gracias por registrarte en ReconBase. Confirma tu dirección de email haciendo clic en el botón:</p>
<p>Si no has creado esta cuenta, ignora este mensaje.</p>""",
                    link_url, "Confirmar email"
                )
                logger.info(f"[Verify] Email enviado a {email}")
        except Exception as e:
            logger.warning(f"[Verify] No se pudo enviar verificacion a {email}: {e}")
    threading.Thread(target=_send, args=(email_destino, nombre_empresa, link), daemon=True).start()
    return True

def _verify_turnstile(token, remote_ip=None):
    """Verifica el token del captcha contra el endpoint de Cloudflare.
    Devuelve True si pasa, False si no. Si no hay secret configurado,
    devuelve True (modo permisivo, no romper local-dev)."""
    secret = os.getenv("TURNSTILE_SECRET_KEY", "")
    if not secret:
        return True  # Turnstile no configurado → no bloquear
    if not token:
        return False
    try:
        import urllib.parse as _up
        payload_data = {"secret": secret, "response": token}
        if remote_ip:
            payload_data["remoteip"] = remote_ip
        body = _up.urlencode(payload_data).encode("utf-8")
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return bool(result.get("success"))
    except Exception as e:
        logger.warning(f"[Turnstile] verify failed: {e}")
        # Fail-open: si Cloudflare está down, no bloquear registros legítimos
        return True


@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")
def api_register():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    empresa  = (data.get("empresa") or "").strip()
    ts_token = data.get("cf-turnstile-response", "")
    if not email or not password:
        return jsonify({"ok": False, "error": "Email y contraseña son obligatorios"}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "La contraseña debe tener al menos 8 caracteres"}), 400
    # Anti-bot: verificar Turnstile (si está configurado)
    remote_ip = request.headers.get("CF-Connecting-IP") or request.remote_addr
    if not _verify_turnstile(ts_token, remote_ip):
        return jsonify({"ok": False, "error": "Verificación anti-bot fallida. Recarga la página e inténtalo de nuevo."}), 403
    if User.query.filter_by(email=email).first():
        return jsonify({"ok": False, "error": "Este email ya está registrado"}), 400
    # Si no rellenan empresa, fallback al nombre antes del @ (capitalizado).
    # Lo pueden cambiar luego en /perfil.
    if not empresa:
        empresa = email.split("@")[0].replace(".", " ").replace("_", " ").title()[:120] or "Tu empresa"
    user = User(email=email, empresa=empresa)
    user.set_password(password)
    user.generate_verify_token()
    db.session.add(user)
    db.session.commit()
    # Sesión persistente: sobrevive a cerrar el navegador hasta 30 días
    session.permanent = True
    login_user(user, remember=True, duration=timedelta(days=30))
    enviar_email_verificacion(user)
    enviar_email_bienvenida(user)
    # Marcar como conversos los leads previos de este email
    try:
        Lead.query.filter_by(email=email, convertido=False).update({Lead.convertido: True})
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"[Register] No se pudo marcar leads de {email}: {e}")
    return jsonify({"ok": True})

@app.route("/api/stripe-portal", methods=["POST"])
@login_required
def stripe_portal():
    """Crea una sesión del portal de clientes de Stripe para gestionar/cancelar suscripción."""
    if not stripe.api_key:
        return jsonify({"ok": False, "error": "Stripe no está configurado en el servidor"}), 500
    try:
        customers = stripe.Customer.list(email=current_user.email, limit=1)
        if customers.data:
            customer_id = customers.data[0].id
        else:
            return jsonify({"ok": False, "error": "No se encontró un cliente con tu email en Stripe. ¿Has realizado algún pago?"}), 404
        base_url = BASE_URL
        try:
            portal_session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=f"{base_url}/perfil"
            )
        except stripe.error.InvalidRequestError as ire:
            # Error típico: portal no configurado en el dashboard de Stripe
            msg = str(ire)
            logger.error(f"[Portal] InvalidRequest: {msg}")
            if "configuration" in msg.lower() or "no configuration" in msg.lower():
                return jsonify({"ok": False, "error": "El portal de facturación no está activado en Stripe. Escríbenos a hola@reconbase.es y cancelamos tu suscripción manualmente."}), 500
            return jsonify({"ok": False, "error": f"Stripe: {msg}"}), 500
        return jsonify({"ok": True, "url": portal_session.url})
    except stripe.error.AuthenticationError:
        return jsonify({"ok": False, "error": "Credenciales de Stripe inválidas"}), 500
    except Exception as e:
        logger.exception(f"[Portal] Error inesperado: {e}")
        return jsonify({"ok": False, "error": f"Error al abrir el portal: {str(e)[:200]}"}), 500

@app.route("/api/debug-mail")
@login_required
def debug_mail():
    """Diagnostico: verifica si el servidor puede enviar emails (Resend HTTPS o SMTP)."""
    if not current_user.is_admin:
        abort(403)
    import smtplib
    mail_user = app.config.get('MAIL_USERNAME') or ''
    mail_pass = app.config.get('MAIL_PASSWORD') or ''
    info = {
        "provider_preferido": "Resend (HTTPS)" if RESEND_API_KEY else "SMTP (Gmail)",
        "RESEND_API_KEY_set": bool(RESEND_API_KEY),
        "RESEND_FROM": RESEND_FROM if RESEND_API_KEY else None,
        "MAIL_USERNAME_set": bool(mail_user),
        "MAIL_USERNAME_masked": (mail_user[:3] + "***" + mail_user[-10:]) if mail_user else None,
        "MAIL_PASSWORD_set": bool(mail_pass),
        "MAIL_SERVER": app.config.get('MAIL_SERVER'),
        "MAIL_PORT": app.config.get('MAIL_PORT'),
        "current_user_email": current_user.email,
        "email_verified": current_user.email_verified,
    }
    # Test SMTP
    if mail_user and mail_pass:
        try:
            s = smtplib.SMTP(app.config.get('MAIL_SERVER'), app.config.get('MAIL_PORT'), timeout=10)
            s.starttls(); s.login(mail_user, mail_pass); s.quit()
            info["smtp_login_test"] = "OK - credenciales validas"
        except Exception as e:
            info["smtp_login_test"] = f"FALLO: {str(e)[:200]}"
    else:
        info["smtp_login_test"] = "NO SE PROBO (faltan credenciales)"
    # Test Resend: solo verificar que la clave tiene formato
    if RESEND_API_KEY:
        try:
            req = urllib.request.Request(
                "https://api.resend.com/domains",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "User-Agent": "ReconBase/1.0",
                    "Accept": "application/json",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                info["resend_api_test"] = f"OK ({resp.status})"
        except urllib.error.HTTPError as he:
            info["resend_api_test"] = f"HTTP {he.code}: {he.read().decode('utf-8','ignore')[:150]}"
        except Exception as e:
            info["resend_api_test"] = f"FALLO: {str(e)[:200]}"
    return jsonify(info)

@app.route("/api/reenviar-verificacion", methods=["POST"])
@login_required
def reenviar_verificacion():
    if current_user.email_verified:
        return jsonify({"ok": False, "error": "El email ya está verificado"}), 400
    if not RESEND_API_KEY and (not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD')):
        return jsonify({"ok": False, "error": "El servidor no tiene configurado ningún proveedor de email (RESEND_API_KEY o MAIL_USER/MAIL_PASS)."}), 500

    current_user.generate_verify_token()
    db.session.commit()
    try:
        base_url = BASE_URL
        link = f"{base_url}/verify-email/{current_user.verify_token}"
        send_html_email(
            current_user.email,
            "Confirma tu email — ReconBase",
            "Confirma tu dirección de email",
            f"Hola <strong>{current_user.empresa}</strong>,<br><br>"
            f"Gracias por registrarte en ReconBase. Solo necesitas confirmar tu email para empezar a analizar la seguridad de tu empresa.",
            cta_url=link,
            cta_text="Confirmar email"
        )
        return jsonify({
            "ok": True,
            "msg": f"Email enviado a {current_user.email}. Revisa tu bandeja (y carpeta de spam, puede tardar 1-2 min)."
        })
    except Exception as e:
        logger.exception(f"[Reverify] Fallo a {current_user.email}: {e}")
        err_str = str(e)
        if "Network is unreachable" in err_str:
            msg = "Railway bloquea SMTP saliente. Añade RESEND_API_KEY en Railway (gratis en resend.com)."
        elif "Username and Password not accepted" in err_str or "534" in err_str:
            msg = "Gmail rechaza las credenciales. Usa una 'contraseña de aplicación' (myaccount.google.com/apppasswords)."
        else:
            msg = err_str[:600]
        return jsonify({"ok": False, "error": msg}), 500

@app.route("/verify-email/<token>")
@limiter.limit("30 per hour")
def verify_email(token):
    user = User.query.filter_by(verify_token=token).first()
    if not user:
        return render_template("verify_result.html", ok=False,
                               msg="Enlace no válido o ya utilizado.")
    user.email_verified = True
    user.verify_token   = None
    db.session.commit()
    return render_template("verify_result.html", ok=True,
                           msg="Email verificado correctamente. Ya puedes usar ReconBase.")

@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    logout_user()
    return jsonify({"ok": True})

@app.route("/api/scan-demo", methods=["POST"])
@limiter.limit("5 per hour")
def scan_demo():
    """Escaneo público sin login para la landing. No guarda resultados en BD."""
    data     = request.get_json() or {}
    objetivo = (data.get("objetivo") or "").strip()[:200]
    if not objetivo:
        return jsonify({"error": "Introduce un dominio"}), 400

    dominio = objetivo
    if "@" in objetivo:
        dominio = objetivo.split("@")[-1]
    import re as _re2
    dominio = _re2.sub(r'^https?://', '', dominio).replace("www.", "").split("/")[0].strip()
    if not dominio:
        return jsonify({"error": "Dominio inválido"}), 400

    es_ip_flag = engine.es_ip(dominio)

    try: puertos = engine.scan_critical_ports_fast(dominio)
    except Exception: puertos = []

    # Helper inline para tracking anónimo (sin PII, RGPD-friendly)
    def _track_demo_scan(dom, ries, lab, logged):
        try:
            ip_real = (request.headers.get("CF-Connecting-IP")
                       or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                       or request.remote_addr or "")
            ip_h = hashlib.sha256((ip_real + "rb_salt_2026").encode()).hexdigest()[:16] if ip_real else None
            db.session.add(AnonymousScan(
                dominio=dom[:255], riesgo=int(ries or 0), label=(lab or "")[:20],
                ip_hash=ip_h, referer=(request.headers.get("Referer") or "")[:255],
                user_agent=(request.headers.get("User-Agent") or "")[:100],
                es_logged=logged
            ))
            db.session.commit()
        except Exception as _te:
            db.session.rollback()
            logger.warning(f"[TrackDemo] no se pudo guardar: {_te}")

    # Usuarios sin cuenta: SOLO puertos. El resto se muestra bloqueado en el frontend.
    if not current_user.is_authenticated:
        # Riesgo aproximado basado solo en puertos para mostrar algo orientativo
        critical_set = {3389, 22, 3306, 5432, 27017, 6379, 5900, 23, 21, 1433}
        crit_count = len([p for p in puertos if p.get('puerto') in critical_set])
        riesgo_aprox = min(100, crit_count * 25)
        label_aprox, color_aprox = label_riesgo(riesgo_aprox)
        _track_demo_scan(dominio, riesgo_aprox, label_aprox, logged=False)
        return jsonify({
            "objetivo": objetivo, "dominio": dominio, "es_ip": es_ip_flag,
            "puertos": puertos,
            "riesgo": riesgo_aprox, "label": label_aprox, "color": color_aprox,
            "timestamp": datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
            "demo": True, "locked": True
        })

    # Logged-in: ejecuta el MISMO conjunto de checks que /api/scan para que
    # el resultado del demo y el del dashboard coincidan exactamente.
    try: dns = {} if es_ip_flag else engine.check_email_spoofing(dominio)
    except Exception: dns = {}
    try: headers = engine.check_security_headers(dominio)
    except Exception: headers = {}
    try: ssl_info = engine.ssl_scan(dominio)
    except Exception: ssl_info = {}
    try:
        banners = engine.banner_grab(dominio, puertos)
        os_det  = engine.detect_os_from_banners(banners)
    except Exception: banners = {}; os_det = None
    try: subs = [] if es_ip_flag else engine.scan_subdomains(dominio)
    except Exception: subs = []
    try: cms = {"cms": None, "version": None, "riesgo": False, "detalle": ""} if es_ip_flag else engine.detect_cms(dominio)
    except Exception: cms = {"cms": None, "version": None, "riesgo": False, "detalle": ""}
    # Auditoría WordPress dedicada (solo si CMS detectado es WP)
    wp_audit = {"is_wordpress": False}
    if cms.get("cms") == "WordPress" and not es_ip_flag:
        try: wp_audit = engine.wordpress_audit(dominio)
        except Exception: wp_audit = {"is_wordpress": False}
    # Auditoría PrestaShop dedicada (solo si CMS detectado es PS)
    ps_audit = {"is_prestashop": False}
    if cms.get("cms") == "PrestaShop" and not es_ip_flag:
        try: ps_audit = engine.prestashop_audit(dominio)
        except Exception: ps_audit = {"is_prestashop": False}
    leaks = []
    es_email = "@" in objetivo
    if es_email and API_KEY:
        try: leaks = engine.check_leaks_real(objetivo, API_KEY) or []
        except Exception: leaks = []

    riesgo, desglose = calcular_riesgo(puertos, dns, leaks, headers)
    if cms.get("riesgo"):
        riesgo = min(100, riesgo + 10); desglose["CMS desactualizable"] = 10
    # Penalizaciones específicas WordPress
    if wp_audit.get("is_wordpress"):
        if wp_audit.get("version_outdated"):
            riesgo = min(100, riesgo + 10); desglose["WordPress obsoleto"] = 10
        if wp_audit.get("xmlrpc_exposed"):
            riesgo = min(100, riesgo + 5);  desglose["xmlrpc.php expuesto"] = 5
        if wp_audit.get("users_enumerable"):
            riesgo = min(100, riesgo + 10); desglose["Usuarios WP enumerables"] = 10
        vp = len(wp_audit.get("vulnerable_plugins") or [])
        if vp:
            pts = min(20, vp * 8)
            riesgo = min(100, riesgo + pts); desglose[f"{vp} plugin(s) vulnerable(s)"] = pts
        sf = len(wp_audit.get("sensitive_files") or [])
        if sf:
            pts = min(15, sf * 5)
            riesgo = min(100, riesgo + pts); desglose[f"{sf} archivo(s) sensible(s) WP"] = pts
    # Penalizaciones específicas PrestaShop
    if ps_audit.get("is_prestashop"):
        if ps_audit.get("version_outdated"):
            riesgo = min(100, riesgo + 10); desglose["PrestaShop obsoleto"] = 10
        if ps_audit.get("admin_path_default"):
            riesgo = min(100, riesgo + 15); desglose["Admin PrestaShop sin renombrar"] = 15
        if ps_audit.get("install_dir_exposed"):
            riesgo = min(100, riesgo + 18); desglose["/install/ PrestaShop accesible"] = 18
        vm = len(ps_audit.get("vulnerable_modules") or [])
        if vm:
            pts = min(20, vm * 8)
            riesgo = min(100, riesgo + pts); desglose[f"{vm} módulo(s) PS vulnerable(s)"] = pts
        sfp = len(ps_audit.get("sensitive_files") or [])
        if sfp:
            pts = min(15, sfp * 5)
            riesgo = min(100, riesgo + pts); desglose[f"{sfp} archivo(s) sensible(s) PS"] = pts
        if not ps_audit.get("https_forced"):
            riesgo = min(100, riesgo + 10); desglose["HTTPS no forzado (checkout)"] = 10
        if ps_audit.get("skimmer_suspect"):
            riesgo = min(100, riesgo + 25); desglose["Posible skimmer en checkout"] = 25
    if ssl_info.get("caducado"):
        riesgo = min(100, riesgo + 20); desglose["SSL caducado"] = 20
    elif ssl_info.get("pronto_a_caducar"):
        riesgo = min(100, riesgo + 10); desglose["SSL por caducar"] = 10
    label, color = label_riesgo(riesgo)

    _track_demo_scan(dominio, riesgo, label, logged=True)
    return jsonify({
        "objetivo": objetivo, "dominio": dominio, "es_ip": es_ip_flag,
        "puertos": puertos, "dns": dns,
        "headers": {k: bool(v) for k, v in headers.items()},
        "subs": subs, "leaks": len(leaks), "leaks_raw": leaks,
        "riesgo": riesgo, "label": label, "color": color,
        "desglose": desglose, "cms": cms, "wp": wp_audit, "ps": ps_audit, "ssl": ssl_info,
        "banners": banners, "os": os_det,
        "timestamp": datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
        "demo": True, "locked": False
    })

@app.route("/api/lead-unlock", methods=["POST"])
@limiter.limit("10 per hour")
def lead_unlock():
    """Captura email + ejecuta scan completo. Lead magnet sin registro: menos fricción que crear cuenta."""
    import re as _re
    data     = request.get_json() or {}
    email    = (data.get("email") or "").strip().lower()[:120]
    objetivo = (data.get("objetivo") or "").strip()[:200]

    if not email or not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Email inválido"}), 400
    if not objetivo:
        return jsonify({"error": "Introduce un dominio"}), 400

    dominio = objetivo.split("@")[-1] if "@" in objetivo else objetivo
    dominio = _re.sub(r'^https?://', '', dominio).replace("www.", "").split("/")[0].strip()
    if not dominio:
        return jsonify({"error": "Dominio inválido"}), 400

    es_ip_flag = engine.es_ip(dominio)

    try: puertos = engine.scan_critical_ports_fast(dominio)
    except Exception: puertos = []
    try: dns = {} if es_ip_flag else engine.check_email_spoofing(dominio)
    except Exception: dns = {}
    try: headers = engine.check_security_headers(dominio)
    except Exception: headers = {}
    try: ssl_info = engine.ssl_scan(dominio)
    except Exception: ssl_info = {}
    try:
        banners = engine.banner_grab(dominio, puertos)
        os_det  = engine.detect_os_from_banners(banners)
    except Exception: banners = {}; os_det = None

    riesgo, desglose = calcular_riesgo(puertos, dns, [], headers)
    if ssl_info.get("caducado"):
        riesgo = min(100, riesgo + 20); desglose["SSL caducado"] = 20
    elif ssl_info.get("pronto_a_caducar"):
        riesgo = min(100, riesgo + 10); desglose["SSL por caducar"] = 10
    label, color = label_riesgo(riesgo)

    resultado = {
        "objetivo": objetivo, "dominio": dominio, "es_ip": es_ip_flag,
        "puertos": puertos, "dns": dns,
        "headers": {k: bool(v) for k, v in headers.items()},
        "subs": [], "leaks": 0,
        "riesgo": riesgo, "label": label, "color": color,
        "desglose": desglose, "ssl": ssl_info,
        "banners": banners, "os": os_det,
        "timestamp": datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
        "demo": True, "locked": False
    }

    # Guardar lead (no bloquea si falla)
    try:
        ya_user = User.query.filter_by(email=email).first()
        lead = Lead(
            email=email, objetivo=objetivo, dominio=dominio,
            riesgo=riesgo, resultado=resultado,
            ip=(request.headers.get('X-Forwarded-For', request.remote_addr) or '')[:45],
            user_agent=(request.headers.get('User-Agent') or '')[:255],
            convertido=bool(ya_user),
        )
        db.session.add(lead)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"No se pudo guardar lead {email}: {e}")

    # Email con resumen del informe (solo si no es usuario existente)
    try:
        if not User.query.filter_by(email=email).first():
            enviar_email_lead(email, objetivo, riesgo, label, puertos, dns, ssl_info, es_followup=False)
    except Exception as e:
        logger.warning(f"No se pudo enviar email a lead {email}: {e}")

    return jsonify(resultado)

@app.route("/api/checkout", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def crear_checkout():
    data = request.get_json() or {}
    plan = data.get("plan", "")
    billing = (data.get("billing") or "mensual").lower()
    if plan != "pro":
        return jsonify({"error": "Plan no válido"}), 400

    if billing in ("anual", "annual", "yearly"):
        price_id = STRIPE_PRICE_PRO_ANUAL or STRIPE_PRICE_PRO  # fallback a mensual si no hay anual
        if not STRIPE_PRICE_PRO_ANUAL:
            app.logger.warning("PRICE_PRO_ANUAL no configurado — usando precio mensual como fallback")
    else:
        price_id = STRIPE_PRICE_PRO

    if not price_id:
        app.logger.error("STRIPE_PRICE_PRO no configurado")
        return jsonify({"error": "Pago temporalmente no disponible"}), 503
    try:
        checkout_session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=current_user.email,
            client_reference_id=str(current_user.id),
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=request.host_url + "pago-exito?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=request.host_url + "#precios",
            metadata={"billing": billing, "user_id": str(current_user.id)},
            allow_promotion_codes=True,
            billing_address_collection="auto",
            tax_id_collection={"enabled": True},
        )
        return jsonify({"url": checkout_session.url})
    except Exception as e:
        app.logger.exception("Error creando checkout Stripe")
        return jsonify({"error": "No se pudo iniciar el pago"}), 500

@app.route("/api/checkout-informe", methods=["POST"])
@login_required
def checkout_informe():
    data    = request.get_json()
    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify({"error": "scan_id requerido"}), 400
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        return jsonify({"error": "scan_id inválido"}), 400
    scan_obj = db.session.get(Scan, scan_id)
    if not scan_obj or scan_obj.user_id != current_user.id:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    try:
        informe_session = stripe.checkout.Session.create(
            mode="payment",
            customer_email=current_user.email,
            line_items=[{
                "price_data": {
                    "currency": "eur",
                    "product_data": {"name": "Informe PDF ejecutivo — ReconBase"},
                    "unit_amount": 900,
                },
                "quantity": 1,
            }],
            success_url=request.host_url + f"app?informe_ok={scan_id}&sid={{CHECKOUT_SESSION_ID}}",
            cancel_url=request.host_url + "app",
            metadata={"scan_id": str(scan_id), "user_id": str(current_user.id)},
        )
        return jsonify({"url": informe_session.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/verificar-informe", methods=["POST"])
@login_required
def verificar_informe():
    """Verifica el pago de Stripe y desbloquea el PDF del escaneo concreto."""
    data       = request.get_json()
    session_id = data.get("session_id")
    scan_id    = data.get("scan_id")
    if not session_id or not scan_id:
        return jsonify({"ok": False}), 400
    try:
        stripe_session = stripe.checkout.Session.retrieve(session_id)
        if stripe_session.payment_status == "paid":
            scan_obj = db.session.get(Scan, int(scan_id))
            if scan_obj and scan_obj.user_id == current_user.id:
                scan_obj.pdf_unlocked = True
                db.session.commit()
                return jsonify({"ok": True})
    except Exception as e:
        app.logger.exception(f"Error verificando informe: {e}")
    return jsonify({"ok": False})

def _resolve_user_from_obj(obj):
    """Busca el usuario: primero client_reference_id, luego metadata.user_id,
    luego email directo, finalmente customer de Stripe."""
    # 1) client_reference_id (fijado por nosotros en crear_checkout)
    ref = getattr(obj, "client_reference_id", None)
    if ref:
        try:
            u = db.session.get(User, int(ref))
            if u:
                return u
        except Exception:
            pass
    # 2) metadata.user_id
    meta = getattr(obj, "metadata", {}) or {}
    try:
        uid = meta.get("user_id") if hasattr(meta, "get") else None
        if uid:
            u = db.session.get(User, int(uid))
            if u:
                return u
    except Exception:
        pass
    # 3) email directo en el objeto
    email = getattr(obj, "customer_email", None)
    if not email:
        details = getattr(obj, "customer_details", None)
        if details:
            email = getattr(details, "email", None)
    # 4) customer de Stripe
    if not email:
        customer_id = getattr(obj, "customer", None)
        if customer_id:
            try:
                customer = stripe.Customer.retrieve(customer_id)
                email = getattr(customer, "email", None)
            except Exception as e:
                logger.warning(f"[Webhook] retrieve customer {customer_id}: {e}")
    if email:
        return User.query.filter_by(email=email).first()
    return None


@app.route("/api/webhook", methods=["POST"])
def stripe_webhook():
    # 1) Validar que el secreto exista (evita aceptar eventos sin firma en prod)
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        logger.error("[Webhook] STRIPE_WEBHOOK_SECRET no configurado — rechazando evento")
        return jsonify({"error": "webhook no configurado"}), 503

    payload    = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")
    if not sig_header:
        logger.warning("[Webhook] Falta header Stripe-Signature")
        return jsonify({"error": "firma ausente"}), 400

    # 2) Verificar firma HMAC
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except stripe.error.SignatureVerificationError as e:
        logger.warning(f"[Webhook] Firma invalida: {e}")
        return jsonify({"error": "firma invalida"}), 400
    except ValueError as e:
        logger.warning(f"[Webhook] Payload invalido: {e}")
        return jsonify({"error": "payload invalido"}), 400
    except Exception as e:
        logger.exception(f"[Webhook] Error verificando firma: {e}")
        return jsonify({"error": "error verificando"}), 400

    event_id   = getattr(event, "id", None) or event.get("id") if hasattr(event, "get") else getattr(event, "id", None)
    event_type = getattr(event, "type", None) or (event.get("type") if hasattr(event, "get") else None)

    # 3) Idempotencia — si ya procesamos este event.id, responder 200 sin re-ejecutar
    if event_id:
        try:
            if ProcessedWebhook.query.filter_by(event_id=event_id).first():
                logger.info(f"[Webhook] Evento duplicado ignorado: {event_id} ({event_type})")
                return jsonify({"ok": True, "duplicate": True})
        except Exception as e:
            logger.warning(f"[Webhook] Idempotencia check falló: {e}")
            db.session.rollback()

    try:
        obj  = event.data.object
        tipo = event_type or event.type

        if tipo == "checkout.session.completed":
            mode = getattr(obj, "mode", None)
            if mode == "payment":
                # Pago puntual: desbloquear PDF del escaneo
                meta    = getattr(obj, "metadata", {}) or {}
                scan_id = meta.get("scan_id") if hasattr(meta, "get") else None
                if scan_id:
                    try:
                        scan_obj = db.session.get(Scan, int(scan_id))
                        if scan_obj:
                            scan_obj.pdf_unlocked = True
                            db.session.commit()
                            logger.info(f"[Webhook] PDF desbloqueado para scan {scan_id}")
                    except Exception as _e:
                        logger.exception(f"[Webhook] desbloqueo PDF: {_e}")
                        db.session.rollback()
            else:
                # Suscripción Pro
                user = _resolve_user_from_obj(obj)
                meta = getattr(obj, "metadata", {}) or {}
                billing = (meta.get("billing") if hasattr(meta, "get") else None) or "mensual"
                amount_total = getattr(obj, "amount_total", None)  # céntimos
                currency = (getattr(obj, "currency", "eur") or "eur").upper()

                if user:
                    user.plan = "pro"
                    db.session.commit()
                    try:
                        enviar_email_pro_activado(user)
                    except Exception as _me:
                        logger.warning(f"[Webhook] email pro_activado: {_me}")
                    logger.info(f"[Webhook] Plan pro activado para {user.email} (billing={billing})")

                    # Crear factura automática
                    try:
                        desde = datetime.utcnow()
                        if billing in ("anual", "annual", "yearly"):
                            hasta = desde + timedelta(days=365)
                            concepto = "Plan Pro ReconBase — Suscripción anual"
                            importe_default = 290.00
                        else:
                            hasta = desde + timedelta(days=30)
                            concepto = "Plan Pro ReconBase — Suscripción mensual"
                            importe_default = 29.00
                        importe = (amount_total / 100.0) if amount_total else importe_default
                        inv = Invoice(
                            user_id=user.id,
                            numero=_generar_numero_factura(),
                            concepto=concepto,
                            importe=importe,
                            moneda=currency,
                            estado='pagada',
                            periodo_desde=desde,
                            periodo_hasta=hasta,
                        )
                        db.session.add(inv)
                        db.session.commit()
                        _crear_notificacion(user.id, 'sistema',
                            '✅ Plan Pro activado',
                            'Tu suscripción Pro está activa. Ahora tienes acceso a todas las funciones premium.',
                            '/perfil')
                    except Exception as _ie:
                        logger.exception(f"[Webhook] Crear factura: {_ie}")
                        db.session.rollback()
                else:
                    logger.warning(f"[Webhook] Usuario no resuelto para checkout.session.completed (session {getattr(obj, 'id', '?')})")

        elif tipo == "customer.subscription.updated":
            # Cambio de estado/plan — mantener plan pro si la sub sigue activa
            status = getattr(obj, "status", None)
            user = _resolve_user_from_obj(obj)
            if user:
                if status in ("active", "trialing"):
                    if user.plan != "pro":
                        user.plan = "pro"
                        db.session.commit()
                        logger.info(f"[Webhook] Sub activa → pro: {user.email}")
                elif status in ("canceled", "unpaid", "incomplete_expired"):
                    if user.plan != "free":
                        user.plan = "free"
                        db.session.commit()
                        logger.info(f"[Webhook] Sub {status} → free: {user.email}")

        elif tipo == "customer.subscription.deleted":
            user = _resolve_user_from_obj(obj)
            if user and user.plan != "free":
                user.plan = "free"
                db.session.commit()
                logger.info(f"[Webhook] Plan degradado a free: {user.email}")

        elif tipo == "invoice.paid":
            # Renovación recurrente — crear factura en nuestra base
            user = _resolve_user_from_obj(obj)
            if user:
                try:
                    # No duplicar si ya existe esta stripe_invoice_id
                    stripe_inv_id = getattr(obj, "id", None)
                    if stripe_inv_id and Invoice.query.filter_by(stripe_invoice_id=stripe_inv_id).first():
                        logger.info(f"[Webhook] Factura {stripe_inv_id} ya registrada")
                    else:
                        amount_paid = getattr(obj, "amount_paid", None) or getattr(obj, "amount_due", 0)
                        currency = (getattr(obj, "currency", "eur") or "eur").upper()
                        # Determinar si es anual/mensual por período de facturación
                        lines = getattr(obj, "lines", None)
                        billing = "mensual"
                        try:
                            if lines and hasattr(lines, "data") and lines.data:
                                first = lines.data[0]
                                period = getattr(first, "period", None)
                                if period:
                                    start = getattr(period, "start", 0)
                                    end   = getattr(period, "end", 0)
                                    if end and start and (end - start) > 60*60*24*90:
                                        billing = "anual"
                        except Exception:
                            pass
                        concepto = ("Plan Pro ReconBase — Renovación anual"
                                    if billing == "anual"
                                    else "Plan Pro ReconBase — Renovación mensual")
                        desde = datetime.utcnow()
                        hasta = desde + timedelta(days=365 if billing == "anual" else 30)
                        inv = Invoice(
                            user_id=user.id,
                            stripe_invoice_id=stripe_inv_id,
                            numero=_generar_numero_factura(),
                            concepto=concepto,
                            importe=(amount_paid / 100.0) if amount_paid else 0,
                            moneda=currency,
                            estado='pagada',
                            periodo_desde=desde,
                            periodo_hasta=hasta,
                        )
                        db.session.add(inv)
                        db.session.commit()
                        logger.info(f"[Webhook] invoice.paid → factura creada para {user.email}")
                except Exception as _ie:
                    logger.exception(f"[Webhook] invoice.paid crear factura: {_ie}")
                    db.session.rollback()

        elif tipo == "invoice.payment_failed":
            user = _resolve_user_from_obj(obj)
            if user:
                try:
                    _crear_notificacion(user.id, 'sistema',
                        '⚠️ Error al renovar tu suscripción',
                        'No hemos podido cobrar tu renovación del plan Pro. Actualiza tu método de pago para no perder acceso.',
                        '/perfil')
                    logger.warning(f"[Webhook] invoice.payment_failed: {user.email}")
                except Exception as _ne:
                    logger.warning(f"[Webhook] notificación payment_failed: {_ne}")

        # 4) Marcar evento como procesado (idempotencia)
        if event_id:
            try:
                db.session.add(ProcessedWebhook(event_id=event_id, event_type=tipo))
                db.session.commit()
            except Exception as _pe:
                # UNIQUE violation si otro proceso ganó la carrera — no pasa nada
                db.session.rollback()

    except Exception as e:
        logger.exception(f"[Webhook] Error procesando evento {event_type}: {e}")
        db.session.rollback()
        # Devolver 500 para que Stripe reintente
        return jsonify({"error": str(e)}), 500

    return jsonify({"ok": True})

# ── PERFIL ──
@app.route("/perfil")
@login_required
def perfil():
    from sqlalchemy import extract
    now = datetime.utcnow()
    scans_mes = Scan.query.filter(
        Scan.user_id == current_user.id,
        extract('month', Scan.timestamp) == now.month,
        extract('year',  Scan.timestamp) == now.year
    ).count()
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    scan_hora = current_user.scan_hora if current_user.scan_hora is not None else 3
    scan_dias = (current_user.scan_dias or '').split(',') if current_user.scan_dias else []
    facturas = Invoice.query.filter_by(user_id=current_user.id)\
        .order_by(Invoice.created_at.desc()).limit(10).all()
    no_leidas = Notification.query.filter_by(
        user_id=current_user.id, leida=False).count()
    return render_template("perfil.html", user=current_user,
                           scans_mes=scans_mes, total_scans=total_scans,
                           scan_hora=scan_hora, scan_dias=scan_dias,
                           facturas=facturas, no_leidas=no_leidas)

@app.route("/api/cambiar-password", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def cambiar_password():
    data = request.get_json()
    actual   = data.get("actual", "")
    nueva    = data.get("nueva", "")
    if not current_user.check_password(actual):
        return jsonify({"ok": False, "error": "Contraseña actual incorrecta"}), 400
    if len(nueva) < 8:
        return jsonify({"ok": False, "error": "La nueva contraseña debe tener al menos 8 caracteres"}), 400
    current_user.set_password(nueva)
    db.session.commit()
    _registrar_audit(current_user.id, 'cambio_password', 'Contraseña cambiada correctamente')
    return jsonify({"ok": True})

# ── GDPR: exportar datos personales ──
@app.route("/api/exportar-datos", methods=["GET"])
@login_required
@limiter.limit("5 per hour")
def exportar_datos():
    """Derecho a la portabilidad (GDPR art. 20). Devuelve un JSON con todos los datos del usuario."""
    user = current_user
    scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.timestamp.desc()).all()
    data = {
        "exportado_en": datetime.utcnow().isoformat() + "Z",
        "usuario": {
            "id": user.id,
            "email": user.email,
            "empresa": user.empresa,
            "plan": user.plan,
            "email_verified": user.email_verified,
            "trial_end": user.trial_end.isoformat() if user.trial_end else None,
            "scan_hora": user.scan_hora,
            "scan_dias": user.scan_dias,
            "fecha_registro": user.created_at.isoformat() if getattr(user, "created_at", None) else None,
        },
        "escaneos": [
            {
                "id": s.id,
                "objetivo": s.objetivo,
                "dominio": s.dominio,
                "riesgo": s.riesgo,
                "label": s.label,
                "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                "resultado": s.resultado,
            }
            for s in scans
        ],
        "total_escaneos": len(scans),
    }
    buf = io.BytesIO(json.dumps(data, indent=2, ensure_ascii=False, default=str).encode("utf-8"))
    nombre = f"reconbase_datos_{user.email.replace('@','_at_')}_{datetime.utcnow().strftime('%Y%m%d')}.json"
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name=nombre)

# ── GDPR: eliminar cuenta (derecho al olvido) ──
@app.route("/api/eliminar-cuenta", methods=["POST"])
@login_required
@limiter.limit("3 per hour")
def eliminar_cuenta():
    """Derecho al olvido (GDPR art. 17). Cancela suscripción Stripe, borra escaneos y borra usuario."""
    data = request.get_json() or {}
    password = data.get("password", "")
    confirmacion = (data.get("confirmacion") or "").strip().upper()
    if confirmacion != "ELIMINAR":
        return jsonify({"ok": False, "error": "Debes escribir ELIMINAR para confirmar"}), 400
    if not current_user.check_password(password):
        return jsonify({"ok": False, "error": "Contraseña incorrecta"}), 400

    user = current_user
    user_id = user.id
    email = user.email

    # 1) Intentar cancelar suscripción activa de Stripe (best effort)
    if stripe.api_key:
        try:
            customers = stripe.Customer.list(email=email, limit=1)
            if customers.data:
                customer_id = customers.data[0].id
                subs = stripe.Subscription.list(customer=customer_id, status="active", limit=10)
                for sub in subs.data:
                    try:
                        stripe.Subscription.delete(sub.id)
                        logger.info(f"[GDPR] Suscripcion {sub.id} cancelada para {email}")
                    except Exception as e:
                        logger.error(f"[GDPR] Error cancelando sub {sub.id}: {e}")
        except Exception as e:
            logger.error(f"[GDPR] Error Stripe al eliminar cuenta {email}: {e}")

    # 2) Borrar escaneos del usuario
    try:
        Scan.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.exception(f"[GDPR] Error borrando escaneos de {email}: {e}")
        return jsonify({"ok": False, "error": "Error borrando escaneos"}), 500

    # 3) Cerrar sesión y borrar usuario
    try:
        logout_user()
        u_obj = db.session.get(User, user_id)
        if u_obj:
            db.session.delete(u_obj)
            db.session.commit()
        logger.info(f"[GDPR] Cuenta {email} eliminada completamente")
    except Exception as e:
        db.session.rollback()
        logger.exception(f"[GDPR] Error borrando usuario {email}: {e}")
        return jsonify({"ok": False, "error": "Error borrando la cuenta"}), 500

    return jsonify({"ok": True, "msg": "Cuenta eliminada"})

# ── APP ──
@app.route("/app")
def dashboard():
    return redirect(url_for('index'))

# ── SCAN ──
def calcular_riesgo(puertos, dns, leaks, headers):
    score, desglose = 0, {}
    servicios_criticos = ["RDP","Telnet","MySQL","MongoDB","Redis","PostgreSQL","MSSQL","Docker API","Elasticsearch","VNC"]
    pts = 0
    for p in puertos:
        pts += 15 if p.get("servicio") in servicios_criticos else 5
    pts = min(pts, 35)
    score += pts
    if pts: desglose["Red"] = pts
    spf   = 20 if not dns.get("SPF")   else 0
    dmarc = 15 if not dns.get("DMARC") else 0
    score += spf + dmarc
    if spf:   desglose["SPF ausente"]   = spf
    if dmarc: desglose["DMARC ausente"] = dmarc
    pts_l = min(len(leaks)*10, 30) if leaks else 0
    score += pts_l
    if pts_l: desglose["Filtraciones"] = pts_l
    return min(score, 100), desglose

def label_riesgo(score):
    if score >= 70: return "CRITICO",  "#EF4444"
    if score >= 40: return "MODERADO", "#F59E0B"
    return "BAJO", "#10B981"

def sanitizar(texto):
    return str(texto).encode("ascii","ignore").decode("ascii")

def enviar_email_onboarding(destinatario):
    def _send():
        try:
            cuerpo = (
                "Hola,\n\n"
                "Te registraste en ReconBase hace 2 dias y todavia no has analizado tu dominio.\n\n"
                "En menos de 2 minutos puedes saber:\n"
                "  - Si tienes puertos criticos expuestos al exterior\n"
                "  - Si algun email de tu empresa aparece en filtraciones conocidas\n"
                "  - Si tu dominio puede ser suplantado para ataques de phishing\n\n"
                "Muchas empresas descubren problemas graves en su primer escaneo.\n\n"
                "Entra ahora y analiza gratis:\n"
                f"{BASE_URL}/app\n\n"
                "--\nReconBase - Seguridad perimetral para PYMEs\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject="Tu empresa todavia no ha sido analizada — ReconBase",
                    recipients=[destinatario],
                    body=cuerpo
                ))
                print(f"[Onboarding] Email enviado a {destinatario}")
        except Exception as e:
            print(f"[!] Error onboarding {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_post_escaneo(destinatario, empresa, objetivo, riesgo, label, desglose, puertos, num_subs):
    def _send():
        try:
            nivel = "CRÍTICO" if riesgo >= 70 else "MODERADO" if riesgo >= 40 else "BAJO"
            consejos = {
                "Red":            "Tienes puertos de red expuestos. Contacta con tu proveedor para cerrarlos.",
                "SPF ausente":    "Tu dominio no tiene protección SPF. Añade un registro SPF en tu DNS.",
                "DMARC ausente":  "Sin DMARC, cualquiera puede enviar emails suplantando tu empresa.",
                "Filtraciones":   "Hay datos de tu empresa en filtraciones. Cambia contraseñas afectadas.",
                "SSL caducado":   "Tu certificado SSL ha caducado. Renuévalo urgentemente.",
                "SSL por caducar":"Tu certificado SSL caduca pronto. Programa la renovación.",
            }
            problemas = ""
            for k, v in desglose.items():
                if v > 0:
                    problemas += f"  ⚠ {k}: {consejos.get(k, 'Revisa este punto en el dashboard.')}\n"
            if not problemas:
                problemas = "  ✓ No se detectaron problemas críticos.\n"

            puertos_txt = ""
            if puertos:
                lista = ", ".join([f"{p['puerto']}/{p['servicio']}" for p in puertos[:5]])
                puertos_txt = f"\nPuertos expuestos: {lista}"

            cuerpo = (
                f"Hola {empresa},\n\n"
                f"Acabas de completar tu primer análisis de seguridad en ReconBase.\n\n"
                f"{'='*50}\n"
                f"DOMINIO ANALIZADO: {objetivo}\n"
                f"NIVEL DE RIESGO:   {riesgo}% — {label} ({nivel})\n"
                f"SUBDOMINIOS:       {num_subs}{puertos_txt}\n"
                f"{'='*50}\n\n"
                f"PUNTOS A REVISAR:\n{problemas}\n"
                f"Cada uno de estos problemas tiene una solución concreta. Entra al dashboard para ver el informe completo con los pasos exactos:\n\n"
                f"{BASE_URL}/\n\n"
                f"Si quieres que ReconBase vigile tu dominio automáticamente cada noche y te avise si algo cambia, activa el plan Pro:\n"
                f"{BASE_URL}/#precios\n\n"
                f"--\nReconBase - Seguridad perimetral para PYMEs\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject=f"[ReconBase] Tu primer análisis de {objetivo} — Riesgo {nivel}",
                    recipients=[destinatario],
                    body=cuerpo
                ))
                print(f"[PostScan] Email enviado a {destinatario}")
        except Exception as e:
            print(f"[!] Error post-scan email {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_bienvenida(user):
    # 1. Extraemos los textos MIENTRAS la base de datos está conectada
    email_destino = user.email
    nombre_empresa = user.empresa

    # 2. Le decimos a la función que espere esos dos textos
    def _send(email, empresa):
        try:
            base_url = BASE_URL
            with app.app_context():
                send_html_email(
                    email, # Cambiado
                    f"Bienvenido a ReconBase, {empresa}", # Cambiado
                    f"Bienvenido, {empresa} 👋", # Cambiado
                    f"Tu cuenta está lista. Esto es lo que puedes hacer ahora:<br><br>"
                    f"<strong>1. Escanear tu dominio</strong> — Conoce tu nivel de riesgo actual en 2 minutos<br>"
                    f"<strong>2. Detectar filtraciones</strong> — Comprueba si tu empresa aparece en brechas conocidas<br>"
                    f"<strong>3. Informe PDF</strong> — Descarga un informe ejecutivo con todos los hallazgos<br><br>"
                    f"Si tienes cualquier duda, responde a este email.",
                    cta_url=base_url,
                    cta_text="Hacer mi primer escaneo"
                )
                logger.info(f"[Welcome] Email HTML enviado a {email}")
        except Exception as e:
            # 403 de Resend, bounces, emails role-based, etc. NO son bugs del código
            # → degradar a WARNING para no spamear Sentry con falsos positivos
            err_str = str(e)
            if "Resend 403" in err_str or "Resend 4" in err_str or "bounce" in err_str.lower():
                logger.warning(f"[Welcome] Email rechazado por proveedor para {email}: {err_str[:200]}")
            else:
                logger.error(f"[Welcome] Error a {email}: {e}")

    # 3. Lanzamos el hilo pasándole nuestros textos seguros
    threading.Thread(target=_send, args=(email_destino, nombre_empresa), daemon=True).start()

def enviar_email_pro_activado(user):
    # 1. Sacamos los textos MIENTRAS la base de datos está activa
    email_destino = user.email
    nombre_empresa = user.empresa

    # 2. La función ahora recibe esos textos
    def _send(email, empresa):
        try:
            base_url = BASE_URL
            with app.app_context():
                send_html_email(
                    email, # Usamos la variable 'email'
                    "Tu plan Pro está activo — ReconBase",
                    "🎉 Plan Pro activado",
                    f"Hola <strong>{empresa}</strong>,<br><br>" # Usamos la variable 'empresa'
                    f"Tu suscripción Pro ya está activa. Ahora tienes acceso completo a:<br><br>"
                    f"✅ <strong>Escaneos ilimitados</strong><br>"
                    f"✅ <strong>Vigilancia nocturna automática</strong> de todos tus dominios<br>"
                    f"✅ <strong>Alertas por email</strong> cuando se detecta algo nuevo<br>"
                    f"✅ <strong>Búsqueda de filtraciones</strong> en bases de datos filtradas<br>"
                    f"✅ <strong>Informes PDF ejecutivos</strong> completos<br>"
                    f"✅ <strong>Historial ilimitado</strong> de escaneos<br>"
                    f"✅ <strong>Hasta 10 dominios</strong> monitorizados<br><br>"
                    f"Configura la vigilancia automática desde tu perfil.",
                    cta_url=base_url,
                    cta_text="Ir al dashboard"
                )
                logger.info(f"[Pro] Email HTML enviado a {email}")
        except Exception as e:
            logger.warning(f"[Pro] Error a {email}: {e}")
            
    # 3. Arrancamos el hilo pasándole LAS DOS variables seguras
    threading.Thread(target=_send, args=(email_destino, nombre_empresa), daemon=True).start()

def enviar_email_trial_expirando(user, dias_restantes):
    email_destino  = user.email
    nombre_empresa = user.empresa
    base_url       = BASE_URL
    def _send(email, empresa, dias):
        try:
            dias_txt = f"{dias} día{'s' if dias != 1 else ''}"
            with app.app_context():
                send_html_email(
                    email,
                    f"Tu trial Pro termina en {dias_txt} — ReconBase",
                    f"⏳ Tu trial termina en {dias_txt}",
                    f"Hola <strong>{empresa}</strong>,<br><br>"
                    f"Tu periodo de prueba Pro termina en <strong>{dias_txt}</strong>.<br><br>"
                    f"Cuando expire perderás acceso a: vigilancia nocturna, alertas, filtraciones y PDFs.<br><br>"
                    f"Suscríbete ahora para mantener la protección completa.",
                    cta_url=f"{base_url}/#precios",
                    cta_text="Suscribirme a Pro — 29€/mes"
                )
                logger.info(f"[Trial] Aviso HTML a {email} ({dias}d)")
        except Exception as e:
            logger.warning(f"[Trial] Error a {email}: {e}")
    threading.Thread(target=_send, args=(email_destino, nombre_empresa, dias_restantes), daemon=True).start()

def enviar_email_reset(user):
    # Extraer atributos antes de lanzar el thread (evita DetachedInstanceError)
    email_destino = user.email
    reset_token   = user.reset_token
    base_url      = BASE_URL
    link          = f"{base_url}/reset-password/{reset_token}"

    def _send(email, link_url):
        try:
            with app.app_context():
                send_html_email(
                    email,
                    "Restablece tu contraseña — ReconBase",
                    "Restablecer contraseña",
                    "Has solicitado restablecer tu contraseña en ReconBase.<br><br>"
                    "El enlace es válido durante <strong>1 hora</strong>. Si no lo solicitaste, ignora este email.",
                    cta_url=link_url,
                    cta_text="Restablecer contraseña"
                )
                logger.info(f"[Reset] Email HTML enviado a {email}")
        except Exception as e:
            logger.warning(f"[Reset] Error a {email}: {e}")
    threading.Thread(target=_send, args=(email_destino, link), daemon=True).start()

def enviar_email_limite_free(destinatario):
    def _send():
        try:
            base_url = BASE_URL
            with app.app_context():
                send_html_email(
                    destinatario,
                    "Has agotado tus escaneos gratuitos este mes — ReconBase",
                    "Has alcanzado el límite gratuito",
                    "Has usado todos tus escaneos gratuitos de este mes.<br><br>"
                    "Tu empresa puede seguir expuesta a amenazas que no puedes revisar ahora.<br><br>"
                    "Con <strong>Pro a 29€/mes</strong>:<br>"
                    "✅ Escaneos ilimitados<br>✅ Vigilancia nocturna 24/7<br>"
                    "✅ Alertas automáticas<br>✅ Informes PDF completos",
                    cta_url=f"{base_url}/#precios",
                    cta_text="Activar Pro — 29€/mes"
                )
                logger.info(f"[Limite] Email HTML enviado a {destinatario}")
        except Exception as e:
            logger.warning(f"[Limite] Error a {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_lead(destinatario, objetivo, riesgo, label, puertos, dns_info, ssl_info, es_followup=False):
    """Email tras desbloquear informe con email (lead magnet). Si es_followup=True, es el recordatorio 48h."""
    def _send():
        try:
            base_url = BASE_URL
            nivel = "CRÍTICO" if riesgo >= 70 else "MODERADO" if riesgo >= 40 else "BAJO"
            color = "#EF4444" if riesgo >= 70 else "#F59E0B" if riesgo >= 40 else "#22C55E"

            # Contar problemas concretos
            problemas = []
            crit_ports = [p for p in (puertos or []) if p.get('puerto') in {3389, 22, 3306, 5432, 27017, 6379, 5900, 23, 21, 1433}]
            if crit_ports:
                problemas.append(f"🔴 <strong>{len(crit_ports)} puerto{'s' if len(crit_ports)>1 else ''} crítico{'s' if len(crit_ports)>1 else ''} expuesto{'s' if len(crit_ports)>1 else ''}</strong>: {', '.join(str(p['puerto']) for p in crit_ports[:4])}")
            if dns_info and not dns_info.get('spf') and not dns_info.get('dmarc'):
                problemas.append("🔴 <strong>Dominio suplantable</strong>: sin SPF ni DMARC configurados")
            elif dns_info and not dns_info.get('dmarc'):
                problemas.append("🟡 <strong>DMARC no configurado</strong>: riesgo de phishing con tu dominio")
            elif dns_info and not dns_info.get('spf'):
                problemas.append("🟡 <strong>SPF no configurado</strong>: emails suplantables")
            if ssl_info and ssl_info.get('caducado'):
                problemas.append("🔴 <strong>Certificado SSL caducado</strong>: los navegadores avisan de inseguridad")
            elif ssl_info and ssl_info.get('pronto_a_caducar'):
                problemas.append(f"🟡 <strong>SSL caduca en {ssl_info.get('dias_restantes','?')} días</strong>")

            problemas_html = "<ul style='margin:.5rem 0 1rem;padding-left:1.2rem;line-height:1.8'>" + \
                "".join(f"<li>{p}</li>" for p in problemas[:5]) + "</ul>" if problemas else \
                "<p style='color:#22C55E'>✓ No se detectaron problemas críticos en este escaneo.</p>"

            if es_followup:
                subject = f"Recordatorio: {objetivo} tiene {riesgo}% de riesgo — ¿lo vas a proteger?"
                titulo = f"¿Sigues con {riesgo}% de riesgo en {objetivo}?"
                intro = (
                    f"Hace 48 horas analizaste <strong>{objetivo}</strong> con ReconBase.<br>"
                    f"El nivel de riesgo era <strong style='color:{color}'>{riesgo}% — {label}</strong> y aún no has creado cuenta.<br><br>"
                    "Esto es lo que sigue sin resolverse:"
                )
                cta_text = "Crear cuenta y proteger mi empresa →"
            else:
                subject = f"Tu informe de {objetivo} — Riesgo {nivel} ({riesgo}%)"
                titulo = f"Informe de {objetivo}: {riesgo}% de riesgo"
                intro = (
                    f"Acabas de analizar <strong>{objetivo}</strong> en ReconBase.<br>"
                    f"Nivel de riesgo: <strong style='color:{color}'>{riesgo}% — {label}</strong>.<br><br>"
                    "Resumen de los hallazgos más importantes:"
                )
                cta_text = "Guardar informe + activar vigilancia →"

            cuerpo = (
                f"{intro}"
                f"{problemas_html}"
                "<p style='font-size:.88rem;color:#64748B;margin-top:1rem'>"
                "Con una cuenta gratuita puedes:<br>"
                "• Guardar este informe y su historial<br>"
                "• Recibir alertas automáticas cuando algo cambie<br>"
                "• Descargar el PDF ejecutivo con pasos de remediación"
                "</p>"
            )

            from urllib.parse import quote
            cta_url = f"{base_url}/register?email={quote(destinatario)}&target={quote(objetivo)}"

            with app.app_context():
                send_html_email(destinatario, subject, titulo, cuerpo, cta_url=cta_url, cta_text=cta_text)
                logger.info(f"[Lead{'Followup' if es_followup else ''}] Email enviado a {destinatario} · {objetivo} · {riesgo}%")
        except Exception as e:
            logger.warning(f"[Lead email] Error a {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()


def enviar_email_lead_dia7(destinatario, objetivo, riesgo, problemas_lista):
    """Email día 7: educativo. Caso real + razón concreta para volver."""
    base_url = BASE_URL
    def _send():
        try:
            problemas_html = ""
            if problemas_lista:
                problemas_html = "<ul style='margin:.6rem 0 1rem;padding-left:1.2rem;line-height:1.8;color:#94A3B8'>"
                for p in problemas_lista[:3]:
                    problemas_html += f"<li>{p}</li>"
                problemas_html += "</ul>"

            from urllib.parse import quote
            unsub_url = f"{base_url}/api/unsubscribe?email={quote(destinatario)}"
            cta_url = f"{base_url}/register?email={quote(destinatario)}&target={quote(objetivo)}"

            cuerpo = (
                f"Hace una semana escaneaste <strong>{objetivo}</strong> en ReconBase.<br><br>"
                f"Te dejo un dato del INCIBE que igual te importa: el <strong>43% de los ciberataques en España "
                f"van a pymes</strong> y la mayoría son via <strong>emails suplantados</strong> (BEC, Business "
                f"Email Compromise) o <strong>credenciales filtradas</strong>.<br><br>"
                f"En tu caso:"
                f"{problemas_html}"
                "<p style='background:#0A1F12;border:1px solid #166534;border-radius:8px;padding:1rem;color:#BBF7D0;margin:1rem 0;font-size:.88rem'>"
                "<strong>📌 Caso real:</strong> Una asesoría de Madrid recibió un mail \"de su jefe\" pidiendo "
                "transferir 12.500€ a una cuenta. SPF no estaba configurado → el mail pasó el filtro. Lo enviaron. "
                "El jefe nunca lo había mandado. Recuperar el dinero les costó 6 meses y un proceso legal. "
                "<strong>SPF + DMARC habrían bloqueado ese email en origen.</strong>"
                "</p>"
                "<p>Configurar SPF/DMARC son 5 minutos en tu DNS. ReconBase te dice exactamente qué registros añadir.</p>"
                "<p style='font-size:.78rem;color:#64748B;margin-top:1.5rem'>"
                f"¿No te interesa? <a href='{unsub_url}' style='color:#64748B'>Darse de baja</a>."
                "</p>"
            )
            with app.app_context():
                send_html_email(
                    destinatario,
                    f"Por qué tu pyme es 5x más probable de ser hackeada que Apple",
                    "Lo que aprendí escaneando 50 dominios de pymes",
                    cuerpo,
                    cta_url=cta_url, cta_text="Ver mi informe completo →"
                )
                logger.info(f"[LeadDia7] Email enviado a {destinatario}")
        except Exception as e:
            logger.warning(f"[LeadDia7] Error a {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()


def enviar_email_lead_dia14(destinatario, objetivo, riesgo):
    """Email día 14: última oportunidad con cupón para activar Pro."""
    base_url = BASE_URL
    def _send():
        try:
            from urllib.parse import quote
            unsub_url = f"{base_url}/api/unsubscribe?email={quote(destinatario)}"
            cta_url = f"{base_url}/register?email={quote(destinatario)}&target={quote(objetivo)}"

            cuerpo = (
                f"Hace 2 semanas analizaste <strong>{objetivo}</strong> con ReconBase. "
                f"Riesgo detectado: <strong>{riesgo}%</strong>.<br><br>"
                "Sé que estás ocupado. Te mando este último email con una propuesta concreta:<br><br>"
                "<div style='background:linear-gradient(135deg,#0A1F12,#0F2A18);border:1px solid #166534;border-radius:10px;padding:1.25rem;margin:1rem 0;text-align:center'>"
                "<div style='font-size:1.05rem;font-weight:800;color:#F0FDF4;margin-bottom:.5rem'>"
                "🎁 30 días Pro gratis"
                "</div>"
                "<div style='font-size:.85rem;color:#BBF7D0;line-height:1.5'>"
                "Crea tu cuenta antes del próximo lunes y te activamos <strong>30 días del plan Pro</strong> sin tarjeta. "
                "Vigilancia 24/7, alertas automáticas, informes PDF ilimitados.<br><br>"
                "Sin permanencia. Si no te convence, no haces nada y vuelves a Free automáticamente."
                "</div>"
                "</div>"
                "<p>Una vez activado tendrás:</p>"
                "<ul style='margin:.5rem 0 1rem;padding-left:1.2rem;line-height:1.8'>"
                "<li>✅ Tu dominio escaneado cada noche automáticamente</li>"
                "<li>✅ Email instantáneo si detectamos algo nuevo</li>"
                "<li>✅ Informe PDF ejecutivo (para enseñar a tu jefe / cliente / proveedor)</li>"
                "<li>✅ Filtraciones de tus emails corporativos contra HIBP</li>"
                "</ul>"
                "<p style='font-size:.85rem;color:#94A3B8'>Si no te interesa, no pasa nada. Es el último que te mando del lanzamiento.</p>"
                "<p style='font-size:.78rem;color:#64748B;margin-top:1.5rem'>"
                f"<a href='{unsub_url}' style='color:#64748B'>Darse de baja de todos los emails</a>."
                "</p>"
            )
            with app.app_context():
                send_html_email(
                    destinatario,
                    "30 días Pro gratis — última oferta para tu pyme",
                    "Última oportunidad antes de cerrar tu acceso",
                    cuerpo,
                    cta_url=cta_url, cta_text="Activar 30 días Pro gratis →"
                )
                logger.info(f"[LeadDia14] Email enviado a {destinatario}")
        except Exception as e:
            logger.warning(f"[LeadDia14] Error a {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()


@app.route("/api/unsubscribe", methods=["GET"])
@limiter.limit("60 per hour")
def api_unsubscribe():
    """Opt-out de los emails de followup. RGPD: derecho de oposición (art. 21)."""
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return ("Falta email", 400)
    try:
        # Marcar todos los leads con ese email como unsubscribed
        leads = Lead.query.filter_by(email=email).all()
        for l in leads:
            l.unsubscribed = True
        # Si tiene cuenta, marcar también la flag de comunicaciones (si existe)
        db.session.commit()
        logger.info(f"[Unsubscribe] {email} dado de baja ({len(leads)} leads)")
    except Exception as e:
        db.session.rollback()
        logger.warning(f"[Unsubscribe] error con {email}: {e}")
    return Response(
        "<html><body style='font-family:sans-serif;text-align:center;padding:3rem;background:#060D09;color:#E2EDF8'>"
        "<h2>Te hemos dado de baja</h2>"
        "<p>No recibirás más emails de seguimiento de ReconBase.</p>"
        "<p style='color:#64748B;font-size:.85rem'>Si fue un error, escríbenos a hola@reconbase.es y te volvemos a apuntar.</p>"
        "<a href='https://reconbase.es' style='color:#22C55E'>Volver al sitio</a>"
        "</body></html>",
        mimetype="text/html"
    )


def enviar_alerta_email(destinatario, objetivo, riesgo, label, desglose, riesgo_anterior=None):
    def _send():
        try:
            nivel = "CRITICO" if riesgo >= 70 else "MODERADO" if riesgo >= 40 else "BAJO"
            color_riesgo = "#EF4444" if riesgo >= 70 else "#F59E0B" if riesgo >= 40 else "#22C55E"
            consejos = {
                "Red":            "Tienes puertos de red expuestos. Contacta con tu proveedor para cerrarlos.",
                "SPF ausente":    "Tu dominio no tiene SPF. Añade un registro SPF en tu DNS.",
                "DMARC ausente":  "Sin DMARC, cualquiera puede suplantar tu empresa por email.",
                "Filtraciones":   "Datos en filtraciones conocidas. Cambia contraseñas afectadas.",
                "CMS desactualizable": "CMS con posibles vulnerabilidades. Actualiza a la última versión.",
                "SSL caducado":   "Certificado SSL caducado. Renuévalo urgentemente.",
                "SSL por caducar": "Certificado SSL próximo a caducar. Programa su renovación.",
            }
            desglose_html = ""
            for k, v in desglose.items():
                if v > 0:
                    consejo = consejos.get(k, "Revisa este punto en tu dashboard.")
                    desglose_html += f"<li><strong>{k}</strong> — {consejo}</li>"

            cambio_html = ""
            if riesgo_anterior is not None:
                diff = riesgo - riesgo_anterior
                cambio_html = f"<p style='color:#94A3B8;font-size:13px'>Cambio respecto al anterior: {riesgo_anterior}% → <strong style='color:{color_riesgo}'>{riesgo}%</strong> (+{diff}%)</p>"

            cuerpo_html = (
                f"Se ha detectado un <strong>aumento en el nivel de riesgo</strong> de tu dominio.<br><br>"
                f"<table style='background:#080C14;border:1px solid #152B1E;border-radius:8px;padding:16px;width:100%;border-collapse:collapse'>"
                f"<tr><td style='padding:8px 12px;color:#64748B;font-size:13px'>Dominio</td>"
                f"<td style='padding:8px 12px;color:#E2EDF8;font-weight:700'>{objetivo}</td></tr>"
                f"<tr><td style='padding:8px 12px;color:#64748B;font-size:13px'>Riesgo</td>"
                f"<td style='padding:8px 12px;color:{color_riesgo};font-weight:700;font-size:18px'>{riesgo}% — {nivel}</td></tr>"
                f"</table><br>"
                f"{cambio_html}"
                f"{'<p><strong>Puntos a revisar:</strong></p><ul>' + desglose_html + '</ul>' if desglose_html else ''}"
            )
            base_url = BASE_URL
            with app.app_context():
                send_html_email(
                    destinatario,
                    f"⚠️ Alerta de seguridad en {objetivo} — {nivel}",
                    f"Alerta: {objetivo}",
                    cuerpo_html,
                    cta_url=base_url,
                    cta_text="Ver informe completo"
                )
                logger.info(f"[Alerta] HTML enviado a {destinatario} ({objetivo} {riesgo}%)")
        except Exception as e:
            logger.warning(f"[Alerta] Error a {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()

@app.route("/api/scan", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def scan():
    if current_user.plan_efectivo == "free":
        from sqlalchemy import extract
        now = datetime.utcnow()
        scans_mes = Scan.query.filter(
            Scan.user_id == current_user.id,
            extract('month', Scan.timestamp) == now.month,
            extract('year',  Scan.timestamp) == now.year
        ).count()
        if scans_mes >= 10:
            return jsonify({"error": "limite_free"}), 403

    data     = request.get_json()
    raw      = (data.get("objetivo") or "").strip()
    if not raw:
        return jsonify({"error": "Objetivo vacío"}), 400
    # Normalización consistente con /api/scan-demo: quita scheme, www., path, espacios
    import re as _re_norm
    objetivo = _re_norm.sub(r'^https?://', '', raw, flags=_re_norm.IGNORECASE)
    objetivo = objetivo.replace('www.', '', 1).split('/')[0].rstrip('.').lower()
    if not objetivo:
        return jsonify({"error": "Objetivo vacío"}), 400

    es_ip    = engine.es_ip(objetivo)
    dominio  = objetivo.split("@")[-1] if "@" in objetivo else objetivo
    es_email = "@" in objetivo

    # Módulos comunes: puertos, SSL, banners
    puertos  = engine.scan_critical_ports_fast(dominio)
    ssl_info = engine.ssl_scan(dominio)
    banners  = engine.banner_grab(dominio, puertos)
    os_det   = engine.detect_os_from_banners(banners)

    # Módulos solo para dominios (no IPs)
    wp_audit = {"is_wordpress": False}
    ps_audit = {"is_prestashop": False}
    if not es_ip:
        dns     = engine.check_email_spoofing(dominio)
        headers = engine.check_security_headers(dominio)
        subs    = engine.scan_subdomains(dominio)
        cms     = engine.detect_cms(dominio)
        # Auditoría WordPress dedicada si CMS = WordPress
        if cms.get("cms") == "WordPress":
            try: wp_audit = engine.wordpress_audit(dominio)
            except Exception: wp_audit = {"is_wordpress": False}
        # Auditoría PrestaShop dedicada si CMS = PrestaShop
        if cms.get("cms") == "PrestaShop":
            try: ps_audit = engine.prestashop_audit(dominio)
            except Exception: ps_audit = {"is_prestashop": False}
    else:
        dns     = {"SPF": None, "DMARC": None, "SPF_raw": "", "DMARC_raw": ""}
        headers = {}
        subs    = []
        cms     = {"cms": None, "version": None, "riesgo": False, "detalle": ""}

    leaks = []
    if es_email and API_KEY:
        leaks = engine.check_leaks_real(objetivo, API_KEY) or []

    riesgo, desglose = calcular_riesgo(puertos, dns, leaks, headers)
    if cms.get("riesgo"):
        riesgo = min(100, riesgo + 10)
        desglose["CMS desactualizable"] = 10
    # Penalizaciones específicas WordPress
    if wp_audit.get("is_wordpress"):
        if wp_audit.get("version_outdated"):
            riesgo = min(100, riesgo + 10); desglose["WordPress obsoleto"] = 10
        if wp_audit.get("xmlrpc_exposed"):
            riesgo = min(100, riesgo + 5);  desglose["xmlrpc.php expuesto"] = 5
        if wp_audit.get("users_enumerable"):
            riesgo = min(100, riesgo + 10); desglose["Usuarios WP enumerables"] = 10
        vp = len(wp_audit.get("vulnerable_plugins") or [])
        if vp:
            pts = min(20, vp * 8)
            riesgo = min(100, riesgo + pts); desglose[f"{vp} plugin(s) vulnerable(s)"] = pts
        sf = len(wp_audit.get("sensitive_files") or [])
        if sf:
            pts = min(15, sf * 5)
            riesgo = min(100, riesgo + pts); desglose[f"{sf} archivo(s) sensible(s) WP"] = pts
    # Penalizaciones específicas PrestaShop
    if ps_audit.get("is_prestashop"):
        if ps_audit.get("version_outdated"):
            riesgo = min(100, riesgo + 10); desglose["PrestaShop obsoleto"] = 10
        if ps_audit.get("admin_path_default"):
            riesgo = min(100, riesgo + 15); desglose["Admin PrestaShop sin renombrar"] = 15
        if ps_audit.get("install_dir_exposed"):
            riesgo = min(100, riesgo + 18); desglose["/install/ PrestaShop accesible"] = 18
        vm = len(ps_audit.get("vulnerable_modules") or [])
        if vm:
            pts = min(20, vm * 8)
            riesgo = min(100, riesgo + pts); desglose[f"{vm} módulo(s) PS vulnerable(s)"] = pts
        sfp = len(ps_audit.get("sensitive_files") or [])
        if sfp:
            pts = min(15, sfp * 5)
            riesgo = min(100, riesgo + pts); desglose[f"{sfp} archivo(s) sensible(s) PS"] = pts
        if not ps_audit.get("https_forced"):
            riesgo = min(100, riesgo + 10); desglose["HTTPS no forzado (checkout)"] = 10
        if ps_audit.get("skimmer_suspect"):
            riesgo = min(100, riesgo + 25); desglose["Posible skimmer en checkout"] = 25
    # Penalización SSL
    if ssl_info.get("caducado"):
        riesgo = min(100, riesgo + 20)
        desglose["SSL caducado"] = 20
    elif ssl_info.get("pronto_a_caducar"):
        riesgo = min(100, riesgo + 10)
        desglose["SSL por caducar"] = 10
    label, color = label_riesgo(riesgo)

    resultado = {
        "objetivo":  objetivo,
        "dominio":   dominio,
        "es_ip":     es_ip,
        "puertos":   puertos,
        "dns":       dns,
        "headers":   {k: bool(v) for k, v in headers.items()},
        "subs":      subs,
        "leaks":     len(leaks),
        "leaks_raw": leaks,
        "riesgo":    riesgo,
        "label":     label,
        "color":     color,
        "desglose":  desglose,
        "cms":       cms,
        "wp":        wp_audit,
        "ps":        ps_audit,
        "ssl":       ssl_info,
        "banners":   banners,
        "os":        os_det,
        "timestamp": datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
    }

    scan = Scan(
        user_id  = current_user.id,
        objetivo = objetivo,
        dominio  = dominio,
        riesgo   = riesgo,
        label    = label,
        resultado= resultado
    )
    db.session.add(scan)
    # Marcar timestamp del último escaneo en el usuario (para ver actividad reciente)
    try:
        current_user.last_scan_at = datetime.utcnow()
    except Exception:
        pass
    db.session.commit()
    resultado["scan_id"]      = scan.id
    resultado["pdf_unlocked"] = scan.pdf_unlocked

    # Email post-primer-escaneo
    total_scans_usuario = Scan.query.filter_by(user_id=current_user.id).count()
    if total_scans_usuario == 1:
        enviar_email_post_escaneo(current_user.email, current_user.empresa, objetivo, riesgo, label, desglose, puertos, len(subs) if not es_ip else 0)

    # Email de límite Free cuando se agota el último escaneo del mes
    if current_user.plan == 'free':
        from sqlalchemy import extract as _ext
        _now = datetime.utcnow()
        _total = Scan.query.filter(
            Scan.user_id == current_user.id,
            _ext('month', Scan.timestamp) == _now.month,
            _ext('year',  Scan.timestamp) == _now.year
        ).count()
        if _total >= 10:
            enviar_email_limite_free(current_user.email)

    # Enviar alerta solo si el riesgo subió respecto al escaneo anterior del mismo dominio
    scan_anterior = Scan.query.filter_by(user_id=current_user.id, dominio=dominio)\
        .order_by(Scan.timestamp.desc()).offset(1).first()
    riesgo_anterior = scan_anterior.riesgo if scan_anterior else None
    umbral = getattr(current_user, 'alerta_umbral', 0) or 0
    if riesgo >= umbral:  # 0 = siempre alertar
        if riesgo_anterior is None:
            if riesgo >= 50:
                enviar_alerta_email(current_user.email, objetivo, riesgo, label, desglose, riesgo_anterior)
        elif riesgo > riesgo_anterior:
            enviar_alerta_email(current_user.email, objetivo, riesgo, label, desglose, riesgo_anterior)

    # Notificar integraciones (Slack / webhook) en segundo plano.
    # Capturar atributos del usuario AHORA: dentro del hilo, current_user
    # es un proxy que pierde el request context y devuelve None.
    _slack_url  = getattr(current_user, "slack_webhook", None)
    _custom_url = getattr(current_user, "custom_webhook", None)
    if _slack_url or _custom_url:
        _user_snapshot = type("UserSnap", (), {
            "slack_webhook":  _slack_url,
            "custom_webhook": _custom_url,
            "email":          current_user.email,
        })()
        threading.Thread(target=notificar_integraciones, args=(_user_snapshot, resultado), daemon=True).start()

    return jsonify(resultado)

@app.route("/api/historial", methods=["GET"])
@login_required
def historial():
    # Free: últimos 7 días. Pro: histórico ilimitado.
    q = Scan.query.filter_by(user_id=current_user.id)
    if current_user.plan_efectivo == 'free':
        from datetime import datetime, timedelta
        cutoff = datetime.utcnow() - timedelta(days=7)
        q = q.filter(Scan.timestamp >= cutoff)
    scans = q.order_by(Scan.timestamp.desc()).limit(500).all()
    result = []
    for s in scans:
        r = dict(s.resultado or {})
        r['scan_id'] = s.id
        r['timestamp'] = s.timestamp.strftime('%d/%m/%Y %H:%M')
        result.append(r)
    return jsonify({"scans": result})

@app.route("/api/scan/<int:scan_id>", methods=["GET"])
@login_required
def get_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
    if not scan:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    return jsonify(scan.resultado or {})

@app.route("/api/pdf", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def generar_pdf():
    """Informe ejecutivo de seguridad — diseño profesional con todos los módulos
    del escáner (puertos, DNS, headers, SSL, CMS/WordPress, filtraciones,
    subdominios, OS) + cálculo de riesgo desglosado + plan de remediación."""
    if not PDF_OK:
        return jsonify({"error": "fpdf2 no instalado"}), 500
    datos = request.get_json() or {}

    # ─── Paleta de color corporativa ───
    BRAND_GREEN   = (22, 163, 74)
    BRAND_GREEN_LIGHT = (34, 197, 94)
    BG_DARK       = (8, 12, 20)
    TEXT_DARK     = (15, 23, 42)
    TEXT_MUTED    = (100, 116, 139)
    TEXT_LIGHT    = (148, 163, 184)
    BORDER        = (226, 232, 240)
    CRIT_RED      = (220, 38, 38)
    WARN_AMBER    = (245, 158, 11)
    OK_GREEN      = (22, 163, 74)
    BG_SOFT       = (248, 250, 252)

    riesgo = int(datos.get('riesgo', 0) or 0)
    label  = datos.get('label', '')
    if riesgo >= 70:
        risk_color, risk_label = CRIT_RED, "CRÍTICO"
    elif riesgo >= 40:
        risk_color, risk_label = WARN_AMBER, "MODERADO"
    else:
        risk_color, risk_label = OK_GREEN, "BAJO"

    pdf = FPDF(unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(15, 15, 15)

    # ════════════════════════════════════════════════════════
    # FOOTER en todas las páginas
    # ════════════════════════════════════════════════════════
    def draw_footer():
        pdf.set_y(-15)
        pdf.set_font("Helvetica", size=7)
        pdf.set_text_color(*TEXT_LIGHT)
        pdf.set_draw_color(*BORDER)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(2)
        pdf.cell(60, 4, sanitizar("ReconBase - Auditoría de seguridad"), align="L")
        pdf.cell(60, 4, sanitizar(f"Informe de {datos.get('dominio','')}"), align="C")
        pdf.cell(60, 4, f"Página {pdf.page_no()}", align="R")

    # ════════════════════════════════════════════════════════
    # PÁGINA 1: PORTADA + RESUMEN EJECUTIVO
    # ════════════════════════════════════════════════════════
    pdf.add_page()

    # Header bar
    pdf.set_fill_color(*BG_DARK)
    pdf.rect(0, 0, 210, 55, "F")
    pdf.set_fill_color(*BRAND_GREEN_LIGHT)
    pdf.rect(0, 55, 210, 1.5, "F")

    # Logo
    pdf.set_font("Helvetica", "B", 30)
    pdf.set_text_color(226, 237, 248)
    pdf.set_xy(15, 18)
    pdf.cell(pdf.get_string_width("RECON"), 14, "RECON", ln=0)
    pdf.set_text_color(*BRAND_GREEN_LIGHT)
    pdf.cell(pdf.get_string_width("BASE"), 14, "BASE", ln=1)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*TEXT_LIGHT)
    pdf.set_xy(15, 38)
    pdf.cell(0, 5, sanitizar("INFORME EJECUTIVO DE AUDITORÍA DE SEGURIDAD"), ln=1)
    pdf.set_x(15)
    pdf.cell(0, 5, sanitizar(f"Generado: {datos.get('timestamp','')}"), ln=1)

    pdf.ln(20)

    # ─── Resumen: objetivo + risk score gauge ───
    pdf.set_y(70)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.cell(0, 5, sanitizar("OBJETIVO ANALIZADO"), ln=1)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*TEXT_DARK)
    pdf.cell(0, 10, sanitizar(datos.get('objetivo','—')), ln=1)
    pdf.ln(2)

    # Caja de riesgo grande
    pdf.set_fill_color(*BG_SOFT)
    pdf.set_draw_color(*risk_color)
    pdf.set_line_width(0.5)
    y_box = pdf.get_y()
    pdf.rect(15, y_box, 180, 40, "DF")
    pdf.set_line_width(0.2)

    pdf.set_xy(20, y_box + 5)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.cell(0, 5, sanitizar("NIVEL DE RIESGO"), ln=1)
    pdf.set_xy(20, y_box + 11)
    pdf.set_font("Helvetica", "B", 36)
    pdf.set_text_color(*risk_color)
    pdf.cell(50, 16, f"{riesgo}%", ln=0)
    pdf.set_xy(75, y_box + 14)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 7, sanitizar(risk_label), ln=1)
    pdf.set_x(75)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.cell(0, 5, sanitizar(label or ""), ln=1)

    pdf.set_y(y_box + 45)

    # ─── Resumen de hallazgos ───
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*TEXT_DARK)
    pdf.cell(0, 7, sanitizar("Resumen de hallazgos"), ln=1)
    pdf.set_draw_color(*BORDER)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(3)

    puertos = datos.get('puertos', []) or []
    dns     = datos.get('dns', {}) or {}
    headers = datos.get('headers', {}) or {}
    ssl_i   = datos.get('ssl', {}) or {}
    wp      = datos.get('wp', {}) or {}
    ps      = datos.get('ps', {}) or {}
    cms     = datos.get('cms', {}) or {}
    subs    = datos.get('subs', []) or []
    leaks_n = datos.get('leaks', 0) or 0
    desglose= datos.get('desglose', {}) or {}

    # Top hallazgos en formato lista con badges
    critPorts = [p for p in puertos if p.get('puerto') in {3389,22,3306,5432,27017,6379,5900,23,21,1433}]
    findings = []
    if critPorts:
        findings.append(('crit', f"{len(critPorts)} puerto(s) crítico(s) expuesto(s)", ', '.join(str(p['puerto']) for p in critPorts[:5])))
    if not dns.get('SPF') and not dns.get('DMARC'):
        findings.append(('crit', "SPF y DMARC ausentes", "Cualquiera puede suplantar tu dominio para enviar emails"))
    elif not dns.get('DMARC'):
        findings.append(('warn', "DMARC no configurado", "Riesgo de phishing con tu dominio"))
    elif not dns.get('SPF'):
        findings.append(('warn', "SPF no configurado", "Vulnerable a suplantación"))
    miss_h = [k for k in ['Content-Security-Policy','X-Frame-Options','X-Content-Type-Options'] if not headers.get(k)]
    if len(miss_h) >= 2:
        findings.append(('warn', f"{len(miss_h)} cabeceras HTTP ausentes", ', '.join(miss_h)))
    if ssl_i.get('caducado'):
        findings.append(('crit', "Certificado SSL caducado", f"Caducó el {ssl_i.get('expira','?')}"))
    elif ssl_i.get('pronto_a_caducar'):
        findings.append(('warn', f"SSL caduca en {ssl_i.get('dias_restantes','?')} días", "Renueva pronto"))
    elif not ssl_i.get('tiene_ssl'):
        findings.append(('crit', "Sin SSL/TLS", "El sitio no usa HTTPS"))
    if wp.get('is_wordpress'):
        wp_issues = []
        if wp.get('version_outdated'): wp_issues.append(f"versión {wp.get('version','?')} obsoleta")
        if wp.get('xmlrpc_exposed'):   wp_issues.append("xmlrpc.php expuesto")
        if wp.get('users_enumerable'): wp_issues.append(f"{len(wp.get('users_found') or [])} usuarios enumerables")
        if wp.get('vulnerable_plugins'): wp_issues.append(f"{len(wp['vulnerable_plugins'])} plugins vulnerables")
        if wp.get('sensitive_files'):   wp_issues.append(f"{len(wp['sensitive_files'])} archivos sensibles expuestos")
        if wp_issues:
            findings.append(('crit', f"WordPress {wp.get('version','')} con {len(wp_issues)} hallazgos", ' · '.join(wp_issues[:3])))
    if ps.get('is_prestashop'):
        ps_issues = []
        if ps.get('skimmer_suspect'):     ps_issues.append("posible SKIMMER en checkout")
        if ps.get('install_dir_exposed'): ps_issues.append("/install/ accesible")
        if ps.get('admin_path_default'):  ps_issues.append(f"admin en {ps.get('admin_path_found','/admin')}")
        if ps.get('version_outdated'):    ps_issues.append(f"versión {ps.get('version','?')} obsoleta")
        if ps.get('vulnerable_modules'):  ps_issues.append(f"{len(ps['vulnerable_modules'])} módulos vulnerables")
        if ps.get('sensitive_files'):     ps_issues.append(f"{len(ps['sensitive_files'])} archivos sensibles")
        if not ps.get('https_forced'):    ps_issues.append("HTTPS no forzado")
        if ps_issues:
            sev = 'crit' if (ps.get('skimmer_suspect') or ps.get('install_dir_exposed') or ps.get('admin_path_default')) else 'warn'
            findings.append((sev, f"PrestaShop {ps.get('version','')} con {len(ps_issues)} hallazgos", ' · '.join(ps_issues[:3])))
    if leaks_n:
        findings.append(('crit', f"{leaks_n} filtración(es) de datos detectada(s)", "Credenciales comprometidas en brechas"))

    if not findings:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*OK_GREEN)
        pdf.cell(0, 6, sanitizar("✓ No se detectaron problemas críticos en este escaneo."), ln=1)
    else:
        for sev, title, desc in findings[:8]:
            color = CRIT_RED if sev == 'crit' else WARN_AMBER if sev == 'warn' else OK_GREEN
            tag   = "CRÍTICO" if sev == 'crit' else "AVISO" if sev == 'warn' else "OK"
            # Badge
            pdf.set_fill_color(*color)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(18, 5, sanitizar(tag), align="C", fill=True)
            pdf.set_text_color(*TEXT_DARK)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 5, "  " + sanitizar(title), ln=1)
            pdf.set_x(33)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*TEXT_MUTED)
            pdf.multi_cell(160, 4.5, sanitizar(desc))
            pdf.ln(1.5)

    draw_footer()

    # ════════════════════════════════════════════════════════
    # PÁGINA 2+: DETALLE TÉCNICO
    # ════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(*TEXT_DARK)
    pdf.cell(0, 9, sanitizar("Detalle técnico"), ln=1)
    pdf.set_fill_color(*BRAND_GREEN_LIGHT)
    pdf.rect(15, pdf.get_y(), 30, 1, "F")
    pdf.ln(8)

    def section_header(text):
        if pdf.get_y() > 240:
            draw_footer()
            pdf.add_page()
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*TEXT_DARK)
        pdf.set_fill_color(*BG_SOFT)
        pdf.cell(0, 7, "  " + sanitizar(text), ln=1, fill=True)
        pdf.ln(2)

    def kv(k, v, color=None):
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*TEXT_MUTED)
        pdf.cell(55, 5, sanitizar(k))
        pdf.set_font("Helvetica", "", 9)
        if color: pdf.set_text_color(*color)
        else:     pdf.set_text_color(*TEXT_DARK)
        pdf.multi_cell(135, 5, sanitizar(str(v)))
        pdf.ln(0.5)

    def body(text):
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*TEXT_DARK)
        pdf.multi_cell(0, 5, sanitizar(text))
        pdf.ln(1)

    # ─── 1. Puertos ───
    section_header("1. PUERTOS Y SERVICIOS EXPUESTOS")
    if puertos:
        kv("Total expuestos", str(len(puertos)))
        kv("Puertos críticos", str(len(critPorts)), CRIT_RED if critPorts else OK_GREEN)
        if puertos:
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*TEXT_MUTED)
            pdf.cell(25, 5, "PUERTO")
            pdf.cell(60, 5, "SERVICIO")
            pdf.cell(0, 5, "EVALUACIÓN", ln=1)
            pdf.set_draw_color(*BORDER); pdf.line(15, pdf.get_y(), 195, pdf.get_y()); pdf.ln(1)
            for p in puertos[:15]:
                pdf.set_font("Helvetica", "B", 9)
                es_crit = p.get('puerto') in {3389,22,3306,5432,27017,6379,5900,23,21,1433}
                pdf.set_text_color(*CRIT_RED if es_crit else TEXT_DARK)
                pdf.cell(25, 5, str(p.get('puerto', '?')))
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*TEXT_DARK)
                pdf.cell(60, 5, sanitizar(str(p.get('servicio', '?'))[:30]))
                pdf.set_text_color(*CRIT_RED if es_crit else TEXT_MUTED)
                pdf.cell(0, 5, sanitizar("Crítico - revisar" if es_crit else "Estándar"), ln=1)
        pdf.ln(2)
    else:
        body("No se detectan puertos expuestos al exterior. Estado seguro.")

    # ─── 2. DNS / Email ───
    section_header("2. AUTENTICACIÓN DE CORREO (anti-phishing)")
    kv("SPF (Sender Policy Framework)", "OK" if dns.get('SPF') else "AUSENTE", OK_GREEN if dns.get('SPF') else CRIT_RED)
    kv("DMARC", "OK" if dns.get('DMARC') else "AUSENTE", OK_GREEN if dns.get('DMARC') else CRIT_RED)
    if dns.get('SPF_raw'):
        kv("Registro SPF", dns.get('SPF_raw','')[:200])
    if dns.get('DMARC_raw'):
        kv("Registro DMARC", dns.get('DMARC_raw','')[:200])
    if not dns.get('SPF') or not dns.get('DMARC'):
        pdf.ln(1)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*WARN_AMBER)
        pdf.multi_cell(0, 4.5, sanitizar("Recomendación: configura SPF + DMARC en tu DNS. Sin esto, cualquiera puede enviar emails simulando ser tu empresa (ataques BEC)."))
    pdf.ln(2)

    # ─── 3. Cabeceras HTTP ───
    section_header("3. CABECERAS HTTP DE SEGURIDAD")
    h_list = [
        ('Strict-Transport-Security', 'HSTS - fuerza HTTPS'),
        ('X-Frame-Options', 'Anti-clickjacking'),
        ('X-Content-Type-Options', 'Anti MIME-sniffing'),
        ('Content-Security-Policy', 'CSP - anti-XSS'),
        ('Referrer-Policy', 'Política de referer'),
        ('Permissions-Policy', 'Permisos del navegador'),
    ]
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.cell(95, 5, "CABECERA")
    pdf.cell(45, 5, "PROTECCIÓN")
    pdf.cell(0, 5, "ESTADO", ln=1)
    pdf.set_draw_color(*BORDER); pdf.line(15, pdf.get_y(), 195, pdf.get_y()); pdf.ln(1)
    for hname, hdesc in h_list:
        present = bool(headers.get(hname) or headers.get(hdesc.split(' - ')[0]))
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*TEXT_DARK)
        pdf.cell(95, 5, sanitizar(hname))
        pdf.set_text_color(*TEXT_MUTED)
        pdf.cell(45, 5, sanitizar(hdesc[:35]))
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*OK_GREEN if present else WARN_AMBER)
        pdf.cell(0, 5, "Presente" if present else "AUSENTE", ln=1)
    pdf.ln(2)

    # ─── 4. SSL/TLS ───
    section_header("4. CERTIFICADO SSL/TLS")
    if ssl_i.get('tiene_ssl'):
        kv("Estado", "Caducado" if ssl_i.get('caducado') else ("Próximo a caducar" if ssl_i.get('pronto_a_caducar') else "Válido"),
           CRIT_RED if ssl_i.get('caducado') else (WARN_AMBER if ssl_i.get('pronto_a_caducar') else OK_GREEN))
        if ssl_i.get('expira'):       kv("Caduca el", ssl_i.get('expira'))
        if ssl_i.get('dias_restantes') is not None:
            kv("Días restantes", str(ssl_i.get('dias_restantes')))
        if ssl_i.get('emitido_por'):  kv("Emitido por", ssl_i.get('emitido_por'))
        if ssl_i.get('sujeto'):       kv("Sujeto", ssl_i.get('sujeto'))
    else:
        kv("Estado", "Sin certificado SSL/TLS", CRIT_RED)
        body("CRÍTICO: el sitio no usa HTTPS. Toda comunicación es interceptable.")
    pdf.ln(2)

    # ─── 5. CMS + WordPress audit ───
    if cms.get('cms'):
        section_header(f"5. CMS DETECTADO: {cms.get('cms','').upper()}")
        kv("CMS", cms.get('cms',''))
        if cms.get('version'): kv("Versión", cms.get('version',''))
        if wp.get('is_wordpress'):
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*TEXT_DARK)
            pdf.cell(0, 6, sanitizar("Auditoría WordPress detallada"), ln=1)
            kv("Versión instalada", wp.get('version','?'),
               WARN_AMBER if wp.get('version_outdated') else OK_GREEN)
            if wp.get('version_outdated') and wp.get('version_diff'):
                kv("Análisis de versión", wp.get('version_diff',''), WARN_AMBER)
            kv("xmlrpc.php", "EXPUESTO (DDoS amplifier / brute-force)" if wp.get('xmlrpc_exposed') else "Protegido",
               CRIT_RED if wp.get('xmlrpc_exposed') else OK_GREEN)
            if wp.get('users_enumerable'):
                users = wp.get('users_found') or []
                kv("Enumeración de usuarios", f"VULNERABLE - {len(users)} usuarios listables via wp-json", CRIT_RED)
                if users:
                    kv("Usuarios visibles", ', '.join(users[:5]), TEXT_MUTED)
            else:
                kv("Enumeración de usuarios", "Protegida", OK_GREEN)
            if wp.get('theme'):
                kv("Tema activo", wp.get('theme',''))
            plugins = wp.get('plugins') or []
            if plugins:
                kv("Plugins detectados", f"{len(plugins)}: " + ', '.join(plugins[:8]) + ("..." if len(plugins)>8 else ""))
            vp = wp.get('vulnerable_plugins') or []
            if vp:
                pdf.ln(1)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*CRIT_RED)
                pdf.cell(0, 5, sanitizar(f"Plugins con vulnerabilidades conocidas: {len(vp)}"), ln=1)
                for p in vp[:5]:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.set_text_color(*TEXT_DARK)
                    pdf.cell(0, 5, sanitizar(f"  • {p.get('name','')}"), ln=1)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(*TEXT_MUTED)
                    pdf.multi_cell(0, 4, sanitizar(f"    {p.get('desc','')} [{p.get('severity','').upper()}]"))
            sf = wp.get('sensitive_files') or []
            if sf:
                pdf.ln(1)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*CRIT_RED)
                pdf.cell(0, 5, sanitizar(f"Archivos sensibles expuestos: {len(sf)}"), ln=1)
                for f in sf[:6]:
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(*TEXT_DARK)
                    pdf.cell(0, 4, sanitizar(f"  • {f.get('path','')} - {f.get('desc','')}"), ln=1)

        # ── Detalle PrestaShop (si aplica) ──
        if ps.get('is_prestashop'):
            pdf.ln(1)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*TEXT_DARK)
            pdf.cell(0, 6, sanitizar("Auditoría PrestaShop detallada"), ln=1)
            kv("Versión instalada", ps.get('version','?'),
               WARN_AMBER if ps.get('version_outdated') else OK_GREEN)
            if ps.get('version_outdated') and ps.get('version_diff'):
                kv("Análisis de versión", ps.get('version_diff',''), WARN_AMBER)
            # Skimmer detection — lo MÁS importante, va arriba
            if ps.get('skimmer_suspect'):
                kv("Detector de skimmers", "ALERTA - patrones sospechosos en checkout", CRIT_RED)
                ev = ps.get('skimmer_evidence') or []
                for e in ev[:3]:
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(*TEXT_MUTED)
                    pdf.multi_cell(0, 4, sanitizar(f"  - {e}"))
            else:
                kv("Detector de skimmers", "Sin patrones sospechosos detectados", OK_GREEN)
            # Admin / install dir
            kv("Panel admin", f"SIN RENOMBRAR ({ps.get('admin_path_found','/admin')})" if ps.get('admin_path_default') else "Renombrado o protegido",
               CRIT_RED if ps.get('admin_path_default') else OK_GREEN)
            kv("Directorio /install/", "ACCESIBLE - permite reinstalación maliciosa" if ps.get('install_dir_exposed') else "Eliminado o protegido",
               CRIT_RED if ps.get('install_dir_exposed') else OK_GREEN)
            kv("HTTPS forzado", "No - checkout vulnerable a sniffing" if not ps.get('https_forced') else "Sí - cumple PCI-DSS",
               CRIT_RED if not ps.get('https_forced') else OK_GREEN)
            # Módulos
            mods = ps.get('modules_detected') or []
            if mods:
                kv("Módulos detectados", f"{len(mods)}: " + ', '.join(mods[:8]) + ("..." if len(mods)>8 else ""))
            vm = ps.get('vulnerable_modules') or []
            if vm:
                pdf.ln(1)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*CRIT_RED)
                pdf.cell(0, 5, sanitizar(f"Módulos con vulnerabilidades conocidas: {len(vm)}"), ln=1)
                for m in vm[:5]:
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.set_text_color(*TEXT_DARK)
                    pdf.cell(0, 5, sanitizar(f"  • {m.get('name','')}"), ln=1)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(*TEXT_MUTED)
                    pdf.multi_cell(0, 4, sanitizar(f"    {m.get('desc','')} [{m.get('severity','').upper()}]"))
            sfp = ps.get('sensitive_files') or []
            if sfp:
                pdf.ln(1)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*CRIT_RED)
                pdf.cell(0, 5, sanitizar(f"Archivos sensibles expuestos: {len(sfp)}"), ln=1)
                for f in sfp[:6]:
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(*TEXT_DARK)
                    pdf.cell(0, 4, sanitizar(f"  • {f.get('path','')} - {f.get('desc','')}"), ln=1)
        pdf.ln(2)

    # ─── 6. Filtraciones ───
    section_header("6. FILTRACIONES DE DATOS")
    if leaks_n > 0:
        kv("Brechas encontradas", str(leaks_n), CRIT_RED)
        leaks_raw = datos.get('leaks_raw') or []
        for leak in leaks_raw[:5]:
            if isinstance(leak, dict):
                name = leak.get('fuente') or leak.get('name') or leak.get('Title','?')
                date = leak.get('fecha') or leak.get('BreachDate','')
                body(f"  • {name}  {date}")
        body("Acciones urgentes: cambia las contraseñas de los emails afectados, activa 2FA, notifica al equipo.")
    else:
        kv("Estado", "Sin filtraciones detectadas", OK_GREEN)
    pdf.ln(2)

    # ─── 7. Subdominios ───
    section_header("7. SUBDOMINIOS DETECTADOS")
    if subs:
        kv("Total", str(len(subs)))
        for s in subs[:15]:
            sd = s.get('subdominio') if isinstance(s, dict) else str(s)
            ip = s.get('ip', '—') if isinstance(s, dict) else ''
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*TEXT_DARK)
            pdf.cell(120, 5, sanitizar(f"  • {sd}"))
            pdf.set_text_color(*TEXT_MUTED)
            pdf.cell(0, 5, sanitizar(ip), ln=1)
    else:
        body("No se detectaron subdominios activos en el rango analizado.")
    pdf.ln(2)

    # ─── 8. OS ───
    if datos.get('os'):
        section_header("8. SISTEMA OPERATIVO DETECTADO")
        kv("Inferido de banners", datos.get('os',''))
        pdf.ln(2)

    # ════════════════════════════════════════════════════════
    # PÁGINA: DESGLOSE DE RIESGO
    # ════════════════════════════════════════════════════════
    if desglose:
        if pdf.get_y() > 200:
            draw_footer()
            pdf.add_page()
        section_header("DESGLOSE DEL CÁLCULO DE RIESGO")
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*TEXT_MUTED)
        pdf.cell(140, 5, "FACTOR")
        pdf.cell(0, 5, "PUNTOS", ln=1)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y()); pdf.ln(1)
        for factor, pts in desglose.items():
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*TEXT_DARK)
            pdf.cell(140, 5, sanitizar(factor))
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*WARN_AMBER if pts >= 10 else TEXT_MUTED)
            pdf.cell(0, 5, f"+{pts}", ln=1)
        pdf.ln(1)
        pdf.set_draw_color(*risk_color); pdf.line(15, pdf.get_y(), 195, pdf.get_y()); pdf.ln(2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*risk_color)
        pdf.cell(140, 7, "TOTAL")
        pdf.cell(0, 7, f"{riesgo}%", ln=1)
        pdf.ln(2)

    # ════════════════════════════════════════════════════════
    # PÁGINA FINAL: PLAN DE REMEDIACIÓN + CTA
    # ════════════════════════════════════════════════════════
    if pdf.get_y() > 230:
        draw_footer()
        pdf.add_page()
    else:
        pdf.ln(8)

    section_header("PLAN DE REMEDIACIÓN RECOMENDADO")
    recom = []
    if critPorts:
        recom.append("Cierra los puertos críticos en el firewall. Solo deja 80/443 abiertos al exterior. RDP, SSH, BBDD → solo accesibles via VPN o IP whitelist.")
    if not dns.get('SPF') or not dns.get('DMARC'):
        recom.append("Configura SPF y DMARC en tu DNS. Empieza con DMARC en p=none (monitor) y sube a p=quarantine tras 2 semanas. Guía: reconbase.es/blog/configurar-spf-dkim-dmarc-paso-a-paso")
    if miss_h:
        recom.append("Añade cabeceras HTTP en nginx/Apache: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options DENY, X-Content-Type-Options nosniff.")
    if ssl_i.get('caducado') or ssl_i.get('pronto_a_caducar'):
        recom.append("Renueva el certificado SSL antes de que caduque. Si usas Let's Encrypt, activa renovación automática (certbot --auto-renew).")
    if wp.get('is_wordpress'):
        wpr = []
        if wp.get('version_outdated'): wpr.append("actualizar WordPress core")
        if wp.get('xmlrpc_exposed'):   wpr.append("deshabilitar xmlrpc.php en .htaccess")
        if wp.get('users_enumerable'): wpr.append("bloquear /wp-json/wp/v2/users (plugin Stop User Enumeration)")
        if wp.get('vulnerable_plugins'): wpr.append(f"actualizar/borrar {len(wp['vulnerable_plugins'])} plugin(s) con CVE")
        if wp.get('sensitive_files'): wpr.append("borrar archivos .bak, install.php, debug.log accesibles")
        if wpr:
            recom.append("WordPress: " + "; ".join(wpr) + ". Instala Wordfence o Sucuri para monitorización continua.")
    if ps.get('is_prestashop'):
        psr = []
        if ps.get('skimmer_suspect'):
            psr.append("URGENTE inspeccionar JavaScript del checkout, hacer backup forense, restaurar versión limpia y notificar AEPD en 72h si hubo robo de datos de tarjeta")
        if ps.get('install_dir_exposed'): psr.append("eliminar /install/ del servidor")
        if ps.get('admin_path_default'):  psr.append("renombrar el panel admin a una ruta aleatoria")
        if ps.get('version_outdated'):    psr.append("actualizar PrestaShop a la última versión estable (backup BD antes)")
        if ps.get('vulnerable_modules'):  psr.append(f"actualizar/desinstalar {len(ps['vulnerable_modules'])} módulo(s) con CVE")
        if ps.get('sensitive_files'):     psr.append("bloquear archivos sensibles vía .htaccess (composer.lock, .env, /var/logs/, /.git/)")
        if not ps.get('https_forced'):    psr.append("activar SSL forzado en Parámetros → General (obligatorio PCI-DSS)")
        if psr:
            recom.append("PrestaShop: " + "; ".join(psr) + ". Más detalle en reconbase.es/blog/skimmers-digitales-prestashop-magecart-2026")
    if leaks_n:
        recom.append(f"Cambia inmediatamente las contraseñas de los {leaks_n} email(s) comprometido(s). Activa 2FA en TODAS las cuentas críticas (email, banca, ERP).")

    if not recom:
        body("Sin acciones urgentes detectadas. Mantén el plan de vigilancia regular.")
    else:
        for i, r in enumerate(recom, 1):
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*BRAND_GREEN)
            pdf.cell(10, 6, f"{i}.")
            pdf.set_font("Helvetica", "", 9.5)
            pdf.set_text_color(*TEXT_DARK)
            pdf.multi_cell(170, 5, sanitizar(r))
            pdf.ln(1.5)

    pdf.ln(4)
    # Caja de marca / CTA
    plan = current_user.plan_efectivo
    if plan == 'free':
        pdf.set_fill_color(240, 253, 244)
        pdf.set_draw_color(*BRAND_GREEN_LIGHT)
        y0 = pdf.get_y()
        pdf.rect(15, y0, 180, 28, "DF")
        pdf.set_xy(20, y0 + 4)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*BRAND_GREEN)
        pdf.cell(0, 5, sanitizar("Plan Pro - Vigilancia continua y sin marca de agua"), ln=1)
        pdf.set_x(20)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*TEXT_DARK)
        pdf.multi_cell(170, 4.5, sanitizar("Escaneos ilimitados, monitorización 24/7, alertas automáticas, integración Slack/webhook, hasta 10 dominios y reports PDF mensuales sin marca."))
        pdf.set_x(20)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*BRAND_GREEN)
        pdf.cell(0, 5, sanitizar(">> Activa Pro en reconbase.es/pricing - 29 EUR/mes, sin permanencia"), ln=1)
    else:
        pdf.set_fill_color(*BG_SOFT)
        pdf.set_draw_color(*BORDER)
        y0 = pdf.get_y()
        pdf.rect(15, y0, 180, 20, "DF")
        pdf.set_xy(20, y0 + 5)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*BRAND_GREEN)
        pdf.cell(0, 5, sanitizar("¿Necesitas ayuda implementando estas recomendaciones?"), ln=1)
        pdf.set_x(20)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*TEXT_DARK)
        pdf.cell(0, 5, sanitizar("Escríbenos a hola@reconbase.es y te orientamos sin coste."), ln=1)

    draw_footer()

    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    nombre = f"reconbase_{datos.get('dominio','report').replace('.','_')}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=nombre)

def enviar_informe_automatico(destinatario, dominio, riesgo, label, desglose, puertos, num_subs):
    def _send():
        try:
            nivel = "CRITICO" if riesgo >= 70 else "MODERADO" if riesgo >= 40 else "BAJO"
            puertos_txt = ""
            if puertos:
                lista = ", ".join([f"{p['puerto']}/{p['servicio']}" for p in puertos[:5]])
                puertos_txt = f"  - Puertos expuestos: {lista}\n"
            desglose_txt = ""
            consejos = {
                "DMARC ausente": "Configura un registro DMARC en tu DNS para evitar suplantacion de identidad.",
                "SPF ausente":   "Añade un registro SPF en tu DNS para proteger tu dominio.",
                "Red":           "Revisa los puertos abiertos y cierra los que no sean necesarios.",
                "Headers":       "Configura cabeceras de seguridad HTTP (HSTS, CSP, X-Frame-Options).",
            }
            for k, v in desglose.items():
                if v > 0:
                    consejo = consejos.get(k, "Accede al dashboard para ver los detalles.")
                    desglose_txt += f"  - {k}: {consejo}\n"
            cuerpo = (
                f"Hola,\n\n"
                f"ReconBase ha completado el escaneo automatico de tu dominio.\n\n"
                f"DOMINIO:           {dominio}\n"
                f"NIVEL DE RIESGO:   {riesgo}% - {label} ({nivel})\n"
                f"PUERTOS EXPUESTOS: {len(puertos)}\n"
                f"SUBDOMINIOS:       {num_subs}\n\n"
                f"{'PUNTOS A REVISAR:' if desglose_txt else 'Todo en orden, no se detectaron problemas criticos.'}\n"
                f"{desglose_txt}{puertos_txt}\n"
                f"Ver informe completo:\n"
                f"{BASE_URL}/app\n\n"
                f"--\nReconBase - Vigilancia automatica Pro\n"
            )
            with app.app_context():
                msg = Message(
                    subject=f"[ReconBase] Informe automatico de {dominio} - {nivel}",
                    recipients=[destinatario],
                    body=cuerpo
                )
                mail.send(msg)
                print(f"[Cron] Email enviado a {destinatario}")
        except Exception as e:
            print(f"[!] Error enviando informe automatico: {e}")
    threading.Thread(target=_send, daemon=True).start()

def escaneo_automatico():
    with app.app_context():
        from zoneinfo import ZoneInfo
        now_madrid = datetime.now(ZoneInfo("Europe/Madrid"))
        hora_actual = now_madrid.hour
        dia_actual  = now_madrid.weekday()  # 0=lunes, 6=domingo

        usuarios_pro = User.query.filter_by(plan='pro').all()
        for user in usuarios_pro:
            # Global schedule defaults
            user_dias_str = user.scan_dias or ''
            user_dias = [int(d) for d in user_dias_str.split(',') if d.strip()] if user_dias_str else []
            user_hora = user.scan_hora

            # Multi-dominio: escanear dominios activos, cada uno con su propio horario si lo tiene.
            dominios_user = Domain.query.filter_by(user_id=user.id, activo=True).all()
            if not dominios_user:
                # Fallback: sin dominios configurados, usar último escaneo con horario global
                if not user_dias or user_hora != hora_actual or dia_actual not in user_dias:
                    continue
                ultimo = Scan.query.filter_by(user_id=user.id).order_by(Scan.timestamp.desc()).first()
                if not ultimo:
                    continue
                dominios_user = [type('D', (), {'dominio': ultimo.dominio, 'scan_hora': None, 'scan_dias': None})()]

            for dom_obj in dominios_user:
                # Per-domain schedule override
                d_hora = dom_obj.scan_hora if dom_obj.scan_hora is not None else user_hora
                d_dias_str = dom_obj.scan_dias if dom_obj.scan_dias else user_dias_str
                d_dias = [int(d) for d in d_dias_str.split(',') if d.strip()] if d_dias_str else user_dias
                if d_hora != hora_actual or dia_actual not in d_dias:
                    continue
                dominio  = dom_obj.dominio
                objetivo = dominio
                try:
                    puertos = engine.scan_critical_ports_fast(dominio)
                    dns     = engine.check_email_spoofing(dominio)
                    headers = engine.check_security_headers(dominio)
                    subs    = engine.scan_subdomains(dominio)
                    # CMS detection + auditoría específica WP/PS para detectar skimmers
                    try:
                        cms = engine.detect_cms(dominio)
                    except Exception:
                        cms = {"cms": None, "version": None}
                    wp_audit = {"is_wordpress": False}
                    ps_audit = {"is_prestashop": False}
                    if cms.get("cms") == "WordPress":
                        try: wp_audit = engine.wordpress_audit(dominio)
                        except Exception: pass
                    if cms.get("cms") == "PrestaShop":
                        try: ps_audit = engine.prestashop_audit(dominio)
                        except Exception: pass

                    riesgo, desglose = calcular_riesgo(puertos, dns, [], headers)
                    # Penalizaciones de WP/PS para que el riesgo refleje los hallazgos del CMS
                    if wp_audit.get("is_wordpress"):
                        if wp_audit.get("version_outdated"):  riesgo = min(100, riesgo + 10); desglose["WordPress obsoleto"] = 10
                        if wp_audit.get("xmlrpc_exposed"):    riesgo = min(100, riesgo + 5);  desglose["xmlrpc.php expuesto"] = 5
                        if wp_audit.get("vulnerable_plugins"): riesgo = min(100, riesgo + 10); desglose["Plugins WP vulnerables"] = 10
                    if ps_audit.get("is_prestashop"):
                        if ps_audit.get("skimmer_suspect"):     riesgo = min(100, riesgo + 25); desglose["Posible skimmer en checkout"] = 25
                        if ps_audit.get("install_dir_exposed"): riesgo = min(100, riesgo + 18); desglose["/install/ PrestaShop accesible"] = 18
                        if ps_audit.get("admin_path_default"):  riesgo = min(100, riesgo + 15); desglose["Admin PrestaShop sin renombrar"] = 15

                    label, color     = label_riesgo(riesgo)
                    resultado = {
                        "objetivo": objetivo, "dominio": dominio,
                        "puertos": puertos, "dns": dns,
                        "headers": {k: bool(v) for k, v in headers.items()},
                        "subs": subs, "leaks": 0, "leaks_raw": [],
                        "riesgo": riesgo, "label": label, "color": color,
                        "desglose": desglose,
                        "cms": cms, "wp": wp_audit, "ps": ps_audit,
                        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
                        "automatico": True
                    }
                    scan = Scan(user_id=user.id, objetivo=objetivo, dominio=dominio,
                                riesgo=riesgo, label=label, resultado=resultado)
                    db.session.add(scan)
                    db.session.commit()

                    # ── NOTIFICACIÓN CRÍTICA: skimmer detectado en escaneo automático ──
                    if ps_audit.get("is_prestashop") and ps_audit.get("skimmer_suspect"):
                        try:
                            ev = "; ".join((ps_audit.get("skimmer_evidence") or [])[:3])
                            _crear_notificacion(
                                user.id, 'scan',
                                f"⚠️ ALERTA CRÍTICA: posible skimmer en {dominio}",
                                f"La vigilancia ha detectado patrones de robo de tarjeta (Magecart) en el checkout de {dominio}. "
                                f"Evidencia: {ev}. Revisa URGENTE y sigue el protocolo: copia forense, cambio de credenciales, "
                                f"AEPD en 72h si confirmas exfiltración.",
                                url=f"/scan/{scan.id}"
                            )
                            # Email aparte con sello de urgencia (no usa la plantilla normal de informe)
                            try:
                                with app.app_context():
                                    send_html_email(
                                        user.email,
                                        f"[URGENTE] Posible skimmer detectado en {dominio}",
                                        "⚠️ Alerta crítica: posible robo de tarjetas en tu checkout",
                                        f"<p>La vigilancia nocturna ha detectado patrones característicos de skimmers digitales (Magecart) en el JavaScript de <strong>{dominio}</strong>.</p>"
                                        f"<p><strong>Evidencia detectada:</strong><br>{ev}</p>"
                                        f"<p>Esto NO es una confirmación forense, pero sí una alerta preliminar muy seria. Si tu tienda procesa pagos con tarjeta, sigue el protocolo de respuesta inmediatamente.</p>",
                                        BASE_URL + f"/scan/{scan.id}",
                                        "Ver informe completo"
                                    )
                            except Exception as ee:
                                logger.warning(f"[Cron skimmer] email fallido: {ee}")
                        except Exception as en:
                            logger.warning(f"[Cron skimmer] notif fallida: {en}")

                    enviar_informe_automatico(user.email, dominio, riesgo, label, desglose, puertos, len(subs))
                    notificar_integraciones(user, resultado)
                    print(f"[Cron] Escaneado {dominio} para {user.email}")
                except Exception as e:
                    print(f"[Cron] Error escaneando {dominio} ({user.email}): {e}")

def enviar_alerta_ssl(destinatario, dominio, dias_restantes):
    def _send():
        try:
            urgencia = "URGENTE: " if dias_restantes <= 7 else ""
            cuerpo = (
                f"Hola,\n\n"
                f"{urgencia}El certificado SSL de {dominio} caduca en {dias_restantes} días.\n\n"
                f"Si no lo renuevas, los navegadores mostrarán un aviso de seguridad a tus visitantes "
                f"y tu web dejará de funcionar correctamente.\n\n"
                f"Pasos para renovarlo:\n"
                f"  1. Accede al panel de tu proveedor de hosting\n"
                f"  2. Busca la opción 'Renovar certificado SSL'\n"
                f"  3. Si usas Let's Encrypt, ejecuta: certbot renew\n\n"
                f"Ver detalles en tu dashboard:\n"
                f"{BASE_URL}/\n\n"
                f"--\nReconBase - Vigilancia automática Pro\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject=f"[ReconBase] SSL de {dominio} caduca en {dias_restantes} días",
                    recipients=[destinatario],
                    body=cuerpo
                ))
                print(f"[SSL] Alerta enviada a {destinatario} ({dominio}, {dias_restantes}d)")
        except Exception as e:
            print(f"[!] Error alerta SSL {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def cron_ssl_alerts():
    """Alerta a usuarios Pro cuando su SSL caduca en ≤30 días."""
    with app.app_context():
        usuarios_pro = User.query.filter_by(plan='pro').all()
        for user in usuarios_pro:
            ultimo = Scan.query.filter_by(user_id=user.id).order_by(Scan.timestamp.desc()).first()
            if not ultimo or not ultimo.resultado:
                continue
            ssl_info = ultimo.resultado.get('ssl', {})
            dias = ssl_info.get('dias_restantes')
            if dias is not None and dias in (1, 3, 7, 14, 30):
                enviar_alerta_ssl(user.email, ultimo.dominio, dias)

def enviar_resumen_mensual(destinatario, empresa, scans_mes, riesgo_promedio, dominios):
    def _send():
        try:
            cuerpo = (
                f"Hola {empresa},\n\n"
                f"Aquí tienes el resumen de seguridad de este mes en ReconBase.\n\n"
                f"{'='*50}\n"
                f"ESCANEOS REALIZADOS: {scans_mes}\n"
                f"RIESGO PROMEDIO:     {riesgo_promedio}%\n"
                f"DOMINIOS ANALIZADOS: {', '.join(dominios[:5]) if dominios else 'Ninguno'}\n"
                f"{'='*50}\n\n"
                f"Entra al dashboard para ver el historial completo:\n"
                f"{BASE_URL}/\n\n"
                f"--\nReconBase - Resumen mensual de seguridad\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject=f"[ReconBase] Resumen de seguridad de {empresa} — {datetime.utcnow().strftime('%B %Y')}",
                    recipients=[destinatario],
                    body=cuerpo
                ))
                print(f"[Mensual] Resumen enviado a {destinatario}")
        except Exception as e:
            print(f"[!] Error resumen mensual {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def cron_resumen_mensual():
    """El día 1 de cada mes envía resumen del mes anterior a todos los usuarios."""
    with app.app_context():
        ahora = datetime.utcnow()
        if ahora.day != 1:
            return
        mes_ant_fin = ahora.replace(day=1) - timedelta(seconds=1)
        mes_ant_ini = mes_ant_fin.replace(day=1, hour=0, minute=0, second=0)
        usuarios = User.query.all()
        for user in usuarios:
            scans = Scan.query.filter(
                Scan.user_id == user.id,
                Scan.timestamp >= mes_ant_ini,
                Scan.timestamp <= mes_ant_fin
            ).all()
            if not scans:
                continue
            riesgo_prom = int(sum(s.riesgo for s in scans) / len(scans))
            dominios = list({s.dominio for s in scans})
            enviar_resumen_mensual(user.email, user.empresa, len(scans), riesgo_prom, dominios)

def cron_trial_expiring():
    """Avisa a usuarios cuyo trial expira en 2 días o en 1 día."""
    with app.app_context():
        ahora = datetime.utcnow()
        usuarios = User.query.filter(
            User.trial_end.isnot(None),
            User.plan == 'free'
        ).all()
        for user in usuarios:
            dias = (user.trial_end - ahora).days
            if dias in (1, 2):
                enviar_email_trial_expirando(user, dias)

def enviar_email_reengagement(user):
    email_destino  = user.email
    nombre_empresa = user.empresa
    base_url       = BASE_URL
    def _send(email, empresa):
        try:
            cuerpo = (
                f"Hola {empresa},\n\n"
                f"Hace tiempo que no escaneas tu dominio en ReconBase.\n\n"
                f"Las amenazas cambian constantemente. En las últimas 2 semanas:\n"
                f"  - Nuevas brechas de datos pueden haber expuesto emails de tu empresa\n"
                f"  - Los certificados SSL pueden haber caducado\n"
                f"  - Nuevos puertos pueden haberse abierto sin que lo sepas\n\n"
                f"Un escaneo tarda 2 minutos y es gratis:\n"
                f"{base_url}/\n\n"
                f"--\nReconBase - Seguridad perimetral para PYMEs\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject=f"Hace 2 semanas que no revisas la seguridad de {empresa} — ReconBase",
                    recipients=[email],
                    body=cuerpo
                ))
                logger.info(f"[Reengage] Email enviado a {email}")
        except Exception as e:
            logger.warning(f"[Reengage] Error reengage {email}: {e}")
    threading.Thread(target=_send, args=(email_destino, nombre_empresa), daemon=True).start()

def cron_reengagement():
    """Envía email a usuarios que no han escaneado en 14 días."""
    with app.app_context():
        ahora = datetime.utcnow()
        limite = ahora - timedelta(days=14)
        usuarios = User.query.all()
        for user in usuarios:
            ultimo_scan = Scan.query.filter_by(user_id=user.id).order_by(Scan.timestamp.desc()).first()
            if ultimo_scan and limite - timedelta(days=1) <= ultimo_scan.timestamp <= limite:
                enviar_email_reengagement(user)

def cron_lead_followup():
    """Secuencia de 3 emails post-captura para leads que no se registraron:
       Stage 1 (48h):  recordatorio del informe
       Stage 2 (7d):   educativo + caso real (BEC, INCIBE)
       Stage 3 (14d):  oferta 30 días Pro gratis
    Skip si: ya creó cuenta, ya unsubscribed, o ya estamos en stage 3.
    """
    with app.app_context():
        ahora = datetime.utcnow()

        try:
            # Coger todos los leads no convertidos no dados de baja
            todos = Lead.query.filter(
                getattr(Lead, 'unsubscribed', None) == False,
                Lead.convertido == False
            ).all() if hasattr(Lead, 'unsubscribed') else Lead.query.filter(
                Lead.convertido == False
            ).all()
        except Exception as e:
            logger.warning(f"[LeadFollowup] Query error: {e}")
            return

        for lead in todos:
            try:
                stage = getattr(lead, 'followup_stage', 0) or 0
                if stage >= 3:
                    continue  # ya completó toda la secuencia

                # Si ya creó cuenta entre medias, marcar convertido y saltar
                if User.query.filter_by(email=lead.email).first():
                    lead.convertido = True
                    db.session.commit()
                    continue

                edad = ahora - lead.created_at
                dias = edad.total_seconds() / 86400.0

                # Decidir qué stage toca enviar HOY (sin solapar)
                next_stage = None
                if stage == 0 and 2.0 <= dias < 3.0:      # día 2 (~48h)
                    next_stage = 1
                elif stage == 1 and 7.0 <= dias < 8.0:    # día 7
                    next_stage = 2
                elif stage == 2 and 14.0 <= dias < 15.0:  # día 14
                    next_stage = 3

                if next_stage is None:
                    continue

                r = lead.resultado or {}

                if next_stage == 1:
                    # Stage 1 — recordatorio 48h (email lead followup ya existente)
                    enviar_email_lead(
                        lead.email, lead.objetivo, lead.riesgo,
                        r.get('label', ''), r.get('puertos', []),
                        r.get('dns', {}), r.get('ssl', {}),
                        es_followup=True
                    )

                elif next_stage == 2:
                    # Stage 2 — educativo día 7
                    problemas = []
                    crit = [p for p in (r.get('puertos') or []) if p.get('puerto') in {3389,22,3306,5432,27017,6379,5900,23,21,1433}]
                    if crit:
                        problemas.append(f"<strong>{len(crit)} puerto(s) críticos expuestos</strong>: " + ", ".join(str(p['puerto']) for p in crit[:3]))
                    dns = r.get('dns') or {}
                    if not dns.get('spf') and not dns.get('dmarc'):
                        problemas.append("<strong>Sin SPF ni DMARC</strong>: cualquiera puede mandar emails como tu empresa")
                    elif not dns.get('dmarc'):
                        problemas.append("<strong>DMARC no configurado</strong>: tu dominio puede ser suplantado")
                    enviar_email_lead_dia7(lead.email, lead.objetivo, lead.riesgo, problemas)

                elif next_stage == 3:
                    # Stage 3 — última oferta día 14
                    enviar_email_lead_dia14(lead.email, lead.objetivo, lead.riesgo)

                # Actualizar tracking
                lead.followup_stage = next_stage
                lead.followup_sent = True  # legacy compat
                if hasattr(lead, 'last_email_at'):
                    lead.last_email_at = ahora
                db.session.commit()

            except Exception as e:
                db.session.rollback()
                logger.error(f"[LeadFollowup] Error con lead {getattr(lead, 'id', '?')}: {e}")

def cron_onboarding():
    """Envía email a usuarios registrados hace ~2 días que no han hecho ningún escaneo."""
    with app.app_context():
        ahora = datetime.utcnow()
        ventana_ini = ahora - timedelta(days=3)
        ventana_fin = ahora - timedelta(days=2)
        candidatos = User.query.filter(
            User.created_at >= ventana_ini,
            User.created_at <  ventana_fin
        ).all()
        for user in candidatos:
            if Scan.query.filter_by(user_id=user.id).count() == 0:
                enviar_email_onboarding(user.email)

scheduler = BackgroundScheduler(timezone="Europe/Madrid")
scheduler.add_job(escaneo_automatico,   'cron', minute=0)
scheduler.add_job(cron_onboarding,      'cron', hour=10, minute=0)
scheduler.add_job(cron_ssl_alerts,      'cron', hour=9,  minute=0)
scheduler.add_job(cron_resumen_mensual, 'cron', hour=8,  minute=0)
scheduler.add_job(cron_trial_expiring,  'cron', hour=9,  minute=30)
scheduler.add_job(cron_reengagement,    'cron', hour=11, minute=0)
scheduler.add_job(cron_lead_followup,   'cron', hour=10, minute=30)
if os.environ.get("WERKZEUG_RUN_MAIN") != "true" or not app.debug:
    scheduler.start()

@app.route("/api/horario", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def guardar_horario():
    if current_user.plan != 'pro':
        return jsonify({"ok": False, "error": "Solo disponible en Pro"}), 403
    data = request.get_json()
    hora = int(data.get("hora", 3))
    dias = data.get("dias", [0,1,2,3,4,5,6])
    try:
        user = db.session.get(User, current_user.id)
        user.scan_hora = hora
        user.scan_dias = ','.join(str(d) for d in dias)
        db.session.commit()
        return jsonify({"ok": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

# ── COMPARATIVA ENTRE ESCANEOS ──
@app.route("/api/evolucion", methods=["GET"])
@login_required
def evolucion_riesgo():
    """Devuelve la evolución de riesgo agrupada por dominio para gráficos."""
    dominio_filter = request.args.get("dominio", "")
    q = Scan.query.filter_by(user_id=current_user.id)
    if dominio_filter:
        q = q.filter_by(dominio=dominio_filter)
    scans = q.order_by(Scan.timestamp.asc()).limit(200).all()
    # Agrupar por dominio
    series = {}
    for s in scans:
        d = s.dominio
        if d not in series:
            series[d] = []
        series[d].append({
            "fecha": s.timestamp.strftime("%d/%m/%Y %H:%M") if s.timestamp else "",
            "riesgo": s.riesgo,
            "label": s.label,
        })
    return jsonify({"series": series})

# ── ALERTAS CONFIGURABLES ──
@app.route("/api/alertas", methods=["GET"])
@login_required
def get_alertas():
    return jsonify({"alerta_umbral": current_user.alerta_umbral or 0})

@app.route("/api/alertas", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def guardar_alertas():
    data = request.get_json() or {}
    umbral = int(data.get("alerta_umbral", 0))
    if umbral not in (0, 40, 70):
        return jsonify({"ok": False, "error": "Umbral debe ser 0 (todas), 40 (moderado+) o 70 (solo crítico)"}), 400
    user = db.session.get(User, current_user.id)
    user.alerta_umbral = umbral
    db.session.commit()
    return jsonify({"ok": True})

# ── SCAN PROGRAMADO POR DOMINIO ──
@app.route("/api/dominios/<int:dom_id>/horario", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def horario_dominio(dom_id):
    """Configura horario individual para un dominio."""
    if current_user.plan_efectivo != 'pro':
        return jsonify({"ok": False, "error": "Solo Pro"}), 403
    dom = Domain.query.filter_by(id=dom_id, user_id=current_user.id).first()
    if not dom:
        return jsonify({"ok": False, "error": "Dominio no encontrado"}), 404
    data = request.get_json() or {}
    dom.scan_hora = int(data.get("hora", 3)) if data.get("hora") is not None else None
    dom.scan_dias = ','.join(str(d) for d in data["dias"]) if data.get("dias") is not None else None
    db.session.commit()
    return jsonify({"ok": True})

# ── API PÚBLICA CON API KEY ──
@app.route("/api/apikey", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def generar_api_key():
    """Genera o regenera la API key del usuario."""
    user = db.session.get(User, current_user.id)
    user.generate_api_key()
    db.session.commit()
    return jsonify({"ok": True, "api_key": user.api_key})

@app.route("/api/apikey", methods=["GET"])
@login_required
def get_api_key():
    return jsonify({"api_key": current_user.api_key or ""})

@app.route("/api/v1/scan", methods=["POST"])
@limiter.limit("30 per hour")
def api_v1_scan():
    """API pública: escanea un dominio con autenticación por API key.
    Headers: X-API-Key: rb_xxx...
    Body JSON: {"dominio": "ejemplo.com"}
    """
    api_key = request.headers.get("X-API-Key", "")
    if not api_key:
        return jsonify({"error": "Header X-API-Key requerido"}), 401
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({"error": "API key inválida"}), 401
    # Limites: free=10/mes, pro=100/mes
    max_calls = 10 if user.plan_efectivo == 'free' else 100
    if (user.api_calls_month or 0) >= max_calls:
        return jsonify({"error": f"Límite mensual alcanzado ({max_calls} llamadas)"}), 429

    data = request.get_json() or {}
    import re as _re_api
    dominio = (data.get("dominio") or "").strip().lower()
    dominio = _re_api.sub(r'^https?://', '', dominio).replace("www.", "").split("/")[0].strip()
    if not dominio or len(dominio) < 3:
        return jsonify({"error": "Dominio no válido"}), 400

    try:
        es_ip_flag = engine.es_ip(dominio)
        puertos = engine.scan_critical_ports_fast(dominio)
        dns = {} if es_ip_flag else engine.check_email_spoofing(dominio)
        headers_sec = engine.check_security_headers(dominio)
        ssl_info = engine.ssl_scan(dominio)
        riesgo, desglose = calcular_riesgo(puertos, dns, [], headers_sec)
        if ssl_info.get("caducado"):
            riesgo = min(100, riesgo + 20); desglose["SSL caducado"] = 20
        label, color = label_riesgo(riesgo)

        resultado = {
            "dominio": dominio, "es_ip": es_ip_flag,
            "puertos": puertos, "dns": dns,
            "headers": {k: bool(v) for k, v in headers_sec.items()},
            "ssl": ssl_info,
            "riesgo": riesgo, "label": label, "color": color,
            "desglose": desglose,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        # Guardar en BD y contar uso
        scan = Scan(user_id=user.id, objetivo=dominio, dominio=dominio,
                    riesgo=riesgo, label=label, resultado=resultado)
        db.session.add(scan)
        user.api_calls_month = (user.api_calls_month or 0) + 1
        db.session.commit()
        return jsonify(resultado)
    except Exception as e:
        logger.exception(f"[API v1] Error escaneando {dominio}: {e}")
        return jsonify({"error": "Error durante el escaneo"}), 500

# ── 2FA TOTP (Google Authenticator) ──
@app.route("/api/2fa/setup", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def totp_setup():
    """Genera un secreto TOTP y devuelve el QR code como data URI."""
    try:
        import pyotp, qrcode
    except ImportError:
        return jsonify({"ok": False, "error": "pyotp/qrcode no instalado"}), 500
    user = db.session.get(User, current_user.id)
    if user.totp_enabled:
        return jsonify({"ok": False, "error": "2FA ya está activado"}), 400
    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.session.commit()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="ReconBase")
    # Generar QR como PNG en base64
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")  # type: ignore
    buf.seek(0)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return jsonify({"ok": True, "qr": f"data:image/png;base64,{b64}", "secret": secret})

@app.route("/api/2fa/enable", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def totp_enable():
    """Verifica el código TOTP y activa 2FA."""
    try:
        import pyotp
    except ImportError:
        return jsonify({"ok": False, "error": "pyotp no instalado"}), 500
    data = request.get_json() or {}
    code = (data.get("code") or "").strip()
    if not current_user.totp_secret:
        return jsonify({"ok": False, "error": "Primero llama a /api/2fa/setup"}), 400
    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"ok": False, "error": "Código incorrecto"}), 400
    user = db.session.get(User, current_user.id)
    user.totp_enabled = True
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/2fa/disable", methods=["POST"])
@login_required
@limiter.limit("5 per hour")
def totp_disable():
    """Desactiva 2FA (requiere contraseña)."""
    data = request.get_json() or {}
    password = data.get("password", "")
    if not current_user.check_password(password):
        return jsonify({"ok": False, "error": "Contraseña incorrecta"}), 400
    user = db.session.get(User, current_user.id)
    user.totp_enabled = False
    user.totp_secret = None
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/2fa/verify", methods=["POST"])
@limiter.limit("10 per minute")
def totp_verify_login():
    """Paso 2 del login: verificar código TOTP."""
    try:
        import pyotp
    except ImportError:
        return jsonify({"ok": False, "error": "pyotp no instalado"}), 500
    uid = session.get("2fa_pending_user")
    if not uid:
        return jsonify({"ok": False, "error": "No hay login pendiente de 2FA"}), 400
    data = request.get_json() or {}
    code = (data.get("code") or "").strip()
    user = db.session.get(User, uid)
    if not user or not user.totp_secret:
        session.pop("2fa_pending_user", None)
        return jsonify({"ok": False, "error": "Usuario no encontrado"}), 400
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=1):
        _track_login_attempt(user.email, exito=False, razon="2fa_fail")
        return jsonify({"ok": False, "error": "Código 2FA incorrecto"}), 400
    session.pop("2fa_pending_user", None)
    # Sesión persistente: sobrevive a cerrar el navegador hasta 30 días
    session.permanent = True
    login_user(user, remember=True, duration=timedelta(days=30))
    _marcar_login_exitoso(user)
    _track_login_attempt(user.email, exito=True, razon="ok_2fa")
    return jsonify({"ok": True})

# ── BLOG / CENTRO DE RECURSOS ──
@app.route("/blog")
def blog_index():
    posts = BlogPost.query.filter_by(publicado=True).order_by(BlogPost.created_at.desc()).limit(50).all()
    return render_template("blog.html", posts=posts)

@app.route("/blog/<slug>")
def blog_post(slug):
    post = BlogPost.query.filter_by(slug=slug, publicado=True).first()
    if not post:
        return render_template("404.html"), 404
    return render_template("blog_post.html", post=post)

@app.route("/api/admin/blog", methods=["POST"])
@login_required
def admin_crear_post():
    if not getattr(current_user, 'is_admin', False):
        return abort(403)
    data = request.get_json() or {}
    slug = (data.get("slug") or "").strip().lower().replace(" ", "-")
    titulo = (data.get("titulo") or "").strip()
    contenido = data.get("contenido", "")
    if not slug or not titulo or not contenido:
        return jsonify({"ok": False, "error": "slug, titulo y contenido son obligatorios"}), 400
    if BlogPost.query.filter_by(slug=slug).first():
        return jsonify({"ok": False, "error": "Slug ya existe"}), 400
    post = BlogPost(
        slug=slug, titulo=titulo, contenido=contenido,
        excerpt=(data.get("excerpt") or contenido[:200]),
        autor=data.get("autor", "ReconBase"),
        imagen=data.get("imagen"),
        publicado=data.get("publicado", True),
        tags=data.get("tags", ""),
    )
    db.session.add(post)
    db.session.commit()
    return jsonify({"ok": True, "id": post.id, "slug": post.slug})

@app.route("/api/admin/blog/<int:post_id>", methods=["PUT"])
@login_required
def admin_editar_post(post_id):
    if not getattr(current_user, 'is_admin', False):
        return abort(403)
    post = db.session.get(BlogPost, post_id)
    if not post:
        return jsonify({"ok": False, "error": "Post no encontrado"}), 404
    data = request.get_json() or {}
    for field in ("titulo", "contenido", "excerpt", "autor", "imagen", "tags", "publicado"):
        if field in data:
            setattr(post, field, data[field])
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/admin/blog/<int:post_id>", methods=["DELETE"])
@login_required
def admin_borrar_post(post_id):
    if not getattr(current_user, 'is_admin', False):
        return abort(403)
    post = db.session.get(BlogPost, post_id)
    if not post:
        return jsonify({"ok": False, "error": "Post no encontrado"}), 404
    db.session.delete(post)
    db.session.commit()
    return jsonify({"ok": True})

# ── BANNER DE COOKIES ──
@app.route("/api/cookie-consent", methods=["POST"])
@limiter.limit("60 per hour")
def cookie_consent():
    """Registra el consentimiento de cookies (para cumplir con la ley)."""
    value = "accepted"
    try:
        data = request.get_json(silent=True) or {}
        if data.get("level") == "essential":
            value = "essential"
    except Exception:
        pass
    resp = jsonify({"ok": True})
    # NO httponly — así el JS puede leerla también como segundo nivel de detección.
    resp.set_cookie("cookie_consent", value, max_age=365*24*3600, samesite="Lax")
    return resp

# ── EMAILS HTML TRANSACCIONALES ──
def html_email_wrapper(titulo, cuerpo_html, cta_url=None, cta_text=None):
    """Envuelve contenido en una plantilla HTML corporativa."""
    cta_block = ""
    if cta_url and cta_text:
        cta_block = f'''
        <tr><td style="padding:24px 40px 0">
          <a href="{cta_url}" style="display:inline-block;background:#16A34A;color:#fff;
            padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px">
            {cta_text}
          </a>
        </td></tr>'''
    return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head>
<body style="margin:0;padding:0;background:#060D09;font-family:Arial,Helvetica,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#060D09;padding:32px 0">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="background:#0A1410;border:1px solid #152B1E;border-radius:12px;overflow:hidden">
      <tr><td style="background:#080C14;padding:24px 40px;border-bottom:1px solid #152B1E">
        <span style="font-size:22px;font-weight:900;letter-spacing:-0.5px">
          <span style="color:#E2EDF8">RECON</span><span style="color:#22C55E">BASE</span>
        </span>
      </td></tr>
      <tr><td style="padding:32px 40px 8px">
        <h1 style="color:#E2EDF8;font-size:20px;margin:0 0 16px">{titulo}</h1>
        <div style="color:#94A3B8;font-size:14px;line-height:1.7">{cuerpo_html}</div>
      </td></tr>
      {cta_block}
      <tr><td style="padding:32px 40px 24px;border-top:1px solid #152B1E;margin-top:24px">
        <p style="color:#475569;font-size:12px;margin:0">
          ReconBase — Seguridad perimetral para PYMEs<br>
          <a href="{BASE_URL}" style="color:#22C55E;text-decoration:none">{BASE_HOST}</a>
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>'''

def send_html_email(to, subject, titulo, cuerpo_html, cta_url=None, cta_text=None):
    """Envía email HTML con fallback a texto plano."""
    html = html_email_wrapper(titulo, cuerpo_html, cta_url, cta_text)
    # Texto plano fallback
    import re as _re_strip
    text_body = _re_strip.sub(r'<[^>]+>', '', cuerpo_html).strip()
    if cta_url:
        text_body += f"\n\n{cta_text}: {cta_url}"

    if RESEND_API_KEY:
        payload = json.dumps({
            "from": RESEND_FROM,
            "to": [to] if isinstance(to, str) else to,
            "subject": subject,
            "html": html,
            "text": text_body,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
                "User-Agent": f"ReconBase/1.0 (+{BASE_URL})",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return True
        except urllib.error.HTTPError as he:
            err_body = he.read().decode('utf-8', errors='ignore')
            hint = ""
            if he.code == 403:
                hint = " (dominio RESEND_FROM sin verificar o sandbox limitado)"
            logger.warning(f"[Resend HTML] {he.code} a {to}{hint}: {err_body[:200]}")
            # Fallback a SMTP — no romper el flujo de registro/notificacion
            if _smtp_configured():
                try:
                    _send_via_smtp(to, subject, text_body, html=html)
                    logger.info(f"[Resend HTML→SMTP fallback] OK a {to}")
                    return True
                except Exception as smtp_err:
                    logger.error(f"[Resend HTML→SMTP fallback] Tambien fallo: {smtp_err}")
            raise RuntimeError(f"Resend {he.code}: {err_body[:200]}{hint}")
        except Exception as e:
            logger.warning(f"[Resend HTML] Error red a {to}: {e}")
            if _smtp_configured():
                try:
                    _send_via_smtp(to, subject, text_body, html=html)
                    logger.info(f"[Resend HTML→SMTP fallback] OK a {to}")
                    return True
                except Exception as smtp_err:
                    logger.error(f"[Resend HTML→SMTP fallback] Tambien fallo: {smtp_err}")
            raise
    else:
        _send_via_smtp(to, subject, text_body, html=html)
        return True

# ── ADMIN PANEL ──
def admin_required(f):
    """Decorador: solo usuarios con is_admin=True."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            return abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    from sqlalchemy import func, extract
    now = datetime.utcnow()
    total_users     = User.query.count()
    total_scans     = Scan.query.count()
    users_pro       = User.query.filter_by(plan='pro').count()
    users_trial     = User.query.filter(User.trial_end.isnot(None), User.trial_end > now, User.plan == 'free').count()
    scans_hoy       = Scan.query.filter(func.date(Scan.timestamp) == now.date()).count()
    scans_mes       = Scan.query.filter(extract('month', Scan.timestamp) == now.month, extract('year', Scan.timestamp) == now.year).count()
    users_verified  = User.query.filter_by(email_verified=True).count()
    recent_users    = User.query.order_by(User.created_at.desc()).limit(50).all()
    recent_scans    = Scan.query.order_by(Scan.timestamp.desc()).limit(20).all()
    return render_template("admin.html",
        total_users=total_users, total_scans=total_scans,
        users_pro=users_pro, users_trial=users_trial,
        scans_hoy=scans_hoy, scans_mes=scans_mes,
        users_verified=users_verified,
        recent_users=recent_users, recent_scans=recent_scans,
        now=now)

@app.route("/admin/metricas")
@login_required
@admin_required
def admin_metricas():
    """Dashboard de métricas: usuarios, leads, escaneos, facturación.
    Snapshot rápido del negocio en una sola pantalla."""
    from sqlalchemy import func, extract, desc
    now = datetime.utcnow()
    hoy_start = datetime(now.year, now.month, now.day)
    semana_start = now - timedelta(days=7)
    mes_start = datetime(now.year, now.month, 1)

    # ── USUARIOS ──
    total_users   = User.query.count()
    users_free    = User.query.filter_by(plan='free').count()
    users_pro     = User.query.filter_by(plan='pro').count()
    users_trial   = User.query.filter(User.trial_end.isnot(None), User.trial_end > now, User.plan == 'free').count()
    users_verified= User.query.filter_by(email_verified=True).count()
    users_hoy     = User.query.filter(User.created_at >= hoy_start).count()
    users_semana  = User.query.filter(User.created_at >= semana_start).count()
    users_mes     = User.query.filter(User.created_at >= mes_start).count()
    ultimos_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    # ── LEADS (capturados via email magnet, sin registro) ──
    leads_total   = Lead.query.count()
    try:
        leads_no_conv = Lead.query.filter_by(convertido=False).count()
    except Exception:
        leads_no_conv = 0
        db.session.rollback()
    try:
        leads_unsub = Lead.query.filter(getattr(Lead, 'unsubscribed', None) == True).count() if hasattr(Lead, 'unsubscribed') else 0
    except Exception:
        leads_unsub = 0
        db.session.rollback()
    try:
        leads_recientes = Lead.query.filter_by(convertido=False).order_by(Lead.created_at.desc()).limit(15).all()
    except Exception:
        leads_recientes = []
        db.session.rollback()
    conv_rate = (Lead.query.filter_by(convertido=True).count() / max(leads_total, 1)) * 100 if leads_total else 0

    # ── ESCANEOS (autenticados) ──
    scans_total   = Scan.query.count()
    scans_hoy     = Scan.query.filter(Scan.timestamp >= hoy_start).count()
    scans_semana  = Scan.query.filter(Scan.timestamp >= semana_start).count()
    scans_mes     = Scan.query.filter(extract('month', Scan.timestamp) == now.month,
                                      extract('year',  Scan.timestamp) == now.year).count()

    # ── ESCANEOS ANÓNIMOS (visitantes sin login que usan el demo) ──
    try:
        anon_total    = AnonymousScan.query.count()
        anon_hoy      = AnonymousScan.query.filter(AnonymousScan.created_at >= hoy_start).count()
        anon_semana   = AnonymousScan.query.filter(AnonymousScan.created_at >= semana_start).count()
        # Visitantes únicos (por IP hash) hoy
        anon_unicos_hoy = db.session.query(func.count(func.distinct(AnonymousScan.ip_hash))).\
            filter(AnonymousScan.created_at >= hoy_start).\
            filter(AnonymousScan.ip_hash.isnot(None)).scalar() or 0
        # Top dominios escaneados anónimamente (lo que la GENTE busca)
        top_anon_dominios = db.session.query(
            AnonymousScan.dominio, func.count(AnonymousScan.id).label('n'),
            func.avg(AnonymousScan.riesgo).label('avg_riesgo')
        ).filter(AnonymousScan.created_at >= semana_start).\
            group_by(AnonymousScan.dominio).order_by(desc('n')).limit(15).all()
        # Últimos 10 escaneos anónimos (para ver qué buscan AHORA)
        anon_recientes = AnonymousScan.query.order_by(AnonymousScan.created_at.desc()).limit(15).all()
    except Exception as _e:
        logger.warning(f"[admin_metricas] anonymous_scans table no disponible: {_e}")
        db.session.rollback()
        anon_total = anon_hoy = anon_semana = anon_unicos_hoy = 0
        top_anon_dominios = []
        anon_recientes = []

    # ── FACTURACIÓN ──
    try:
        invoices_pagadas = Invoice.query.filter_by(estado='pagada').all()
        revenue_total = sum(float(inv.importe or 0) for inv in invoices_pagadas)
        # MRR: contar suscripciones Pro activas × 29 (asumiendo mensual)
        mrr = User.query.filter_by(plan='pro').count() * 29.0
        ultimas_facturas = Invoice.query.order_by(Invoice.created_at.desc()).limit(10).all()
    except Exception:
        revenue_total = 0
        mrr = 0
        ultimas_facturas = []
        db.session.rollback()

    # ── ESCANEOS POR DÍA (últimos 7 días) ──
    scans_por_dia = []
    for i in range(6, -1, -1):
        dia = (now - timedelta(days=i)).date()
        siguiente = dia + timedelta(days=1)
        c = Scan.query.filter(Scan.timestamp >= dia,
                              Scan.timestamp < siguiente).count()
        scans_por_dia.append({'fecha': dia.strftime('%d/%m'), 'count': c})

    # ── TOP DOMINIOS ESCANEADOS ──
    try:
        top_dominios = db.session.query(Scan.dominio, func.count(Scan.id).label('n')).\
            group_by(Scan.dominio).order_by(desc('n')).limit(10).all()
    except Exception:
        top_dominios = []
        db.session.rollback()

    # ── ACTIVIDAD DE USUARIOS (logins + escaneos) ──
    # Top 30 usuarios por actividad reciente: orden por last_login DESC
    try:
        actividad_users_raw = db.session.query(
            User,
            func.count(Scan.id).label('n_scans')
        ).outerjoin(Scan, Scan.user_id == User.id).\
            group_by(User.id).\
            order_by(desc(func.coalesce(User.last_login, User.created_at))).\
            limit(30).all()
        actividad_users = [
            {
                'id': u.id, 'email': u.email, 'empresa': u.empresa,
                'plan': u.plan, 'trial_end': u.trial_end,
                'created_at': u.created_at,
                'last_login': u.last_login,
                'login_count': u.login_count or 0,
                'last_scan_at': u.last_scan_at,
                'n_scans': n_scans or 0,
                'email_verified': u.email_verified,
            }
            for (u, n_scans) in actividad_users_raw
        ]
        # Logins en la última semana / hoy (agregado)
        logins_hoy_count = db.session.query(func.count(LoginAttempt.id)).\
            filter(LoginAttempt.exito == True, LoginAttempt.created_at >= hoy_start).scalar() or 0
        logins_semana_count = db.session.query(func.count(LoginAttempt.id)).\
            filter(LoginAttempt.exito == True, LoginAttempt.created_at >= semana_start).scalar() or 0
        logins_fallidos_hoy = db.session.query(func.count(LoginAttempt.id)).\
            filter(LoginAttempt.exito == False, LoginAttempt.created_at >= hoy_start).scalar() or 0
        # Últimos intentos fallidos
        logins_fallidos_recientes = LoginAttempt.query.\
            filter(LoginAttempt.exito == False).\
            order_by(LoginAttempt.created_at.desc()).limit(20).all()
    except Exception as _e:
        logger.warning(f"[admin_metricas] tablas actividad no disponibles: {_e}")
        db.session.rollback()
        actividad_users = []
        logins_hoy_count = logins_semana_count = logins_fallidos_hoy = 0
        logins_fallidos_recientes = []

    return render_template("admin_metricas.html",
        total_users=total_users, users_free=users_free, users_pro=users_pro,
        users_trial=users_trial, users_verified=users_verified,
        users_hoy=users_hoy, users_semana=users_semana, users_mes=users_mes,
        ultimos_users=ultimos_users,
        leads_total=leads_total, leads_no_conv=leads_no_conv, leads_unsub=leads_unsub,
        leads_recientes=leads_recientes, conv_rate=round(conv_rate, 1),
        scans_total=scans_total, scans_hoy=scans_hoy, scans_semana=scans_semana,
        scans_mes=scans_mes, scans_por_dia=scans_por_dia,
        anon_total=anon_total, anon_hoy=anon_hoy, anon_semana=anon_semana,
        anon_unicos_hoy=anon_unicos_hoy,
        top_anon_dominios=top_anon_dominios, anon_recientes=anon_recientes,
        revenue_total=revenue_total, mrr=mrr, ultimas_facturas=ultimas_facturas,
        top_dominios=top_dominios,
        actividad_users=actividad_users,
        logins_hoy_count=logins_hoy_count,
        logins_semana_count=logins_semana_count,
        logins_fallidos_hoy=logins_fallidos_hoy,
        logins_fallidos_recientes=logins_fallidos_recientes,
        now=now)


@app.route("/api/admin/user/<int:uid>/plan", methods=["POST"])
@login_required
@admin_required
def admin_cambiar_plan(uid):
    data = request.get_json() or {}
    plan = data.get("plan", "free")
    if plan not in ("free", "pro"):
        return jsonify({"ok": False, "error": "Plan inválido"}), 400
    user = db.session.get(User, uid)
    if not user:
        return jsonify({"ok": False, "error": "Usuario no encontrado"}), 404
    user.plan = plan
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/admin/user/<int:uid>/delete", methods=["POST"])
@login_required
@admin_required
def admin_borrar_usuario(uid):
    user = db.session.get(User, uid)
    if not user:
        return jsonify({"ok": False, "error": "Usuario no encontrado"}), 404
    Scan.query.filter_by(user_id=uid).delete(synchronize_session=False)
    Domain.query.filter_by(user_id=uid).delete(synchronize_session=False)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"ok": True})

# ── MULTI-DOMINIO ──
@app.route("/api/dominios", methods=["GET"])
@login_required
def listar_dominios():
    doms = Domain.query.filter_by(user_id=current_user.id).order_by(Domain.added_at.desc()).all()
    return jsonify({"dominios": [
        {"id": d.id, "dominio": d.dominio, "activo": d.activo,
         "added_at": d.added_at.strftime("%d/%m/%Y") if d.added_at else None}
        for d in doms
    ]})

@app.route("/api/dominios", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def anadir_dominio():
    data = request.get_json() or {}
    import re as _re3
    dominio = (data.get("dominio") or "").strip().lower()
    dominio = _re3.sub(r'^https?://', '', dominio).replace("www.", "").split("/")[0].strip()
    if not dominio or len(dominio) < 3:
        return jsonify({"ok": False, "error": "Dominio no válido"}), 400
    # Limites: free=5, pro=50
    max_doms = 5 if current_user.plan_efectivo == 'free' else 50
    count = Domain.query.filter_by(user_id=current_user.id).count()
    if count >= max_doms:
        plan_txt = f"{max_doms} dominios en plan Gratis" if current_user.plan_efectivo == 'free' else f"{max_doms} dominios en plan Pro"
        return jsonify({"ok": False, "error": f"Máximo {plan_txt}. Elimina uno antes de añadir otro."}), 400
    existing = Domain.query.filter_by(user_id=current_user.id, dominio=dominio).first()
    if existing:
        return jsonify({"ok": False, "error": "Este dominio ya está añadido"}), 400
    dom = Domain(user_id=current_user.id, dominio=dominio)
    db.session.add(dom)
    db.session.commit()
    return jsonify({"ok": True, "id": dom.id, "dominio": dom.dominio})

@app.route("/api/dominios/<int:dom_id>", methods=["DELETE"])
@login_required
def eliminar_dominio(dom_id):
    dom = Domain.query.filter_by(id=dom_id, user_id=current_user.id).first()
    if not dom:
        return jsonify({"ok": False, "error": "Dominio no encontrado"}), 404
    db.session.delete(dom)
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/dominios/<int:dom_id>/toggle", methods=["POST"])
@login_required
def toggle_dominio(dom_id):
    dom = Domain.query.filter_by(id=dom_id, user_id=current_user.id).first()
    if not dom:
        return jsonify({"ok": False, "error": "Dominio no encontrado"}), 404
    dom.activo = not dom.activo
    db.session.commit()
    return jsonify({"ok": True, "activo": dom.activo})

# ── INTEGRACIONES (Slack / Webhook) ──
@app.route("/api/integraciones", methods=["GET"])
@login_required
def get_integraciones():
    return jsonify({
        "slack_webhook": current_user.slack_webhook or "",
        "custom_webhook": current_user.custom_webhook or "",
    })

@app.route("/api/integraciones", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def guardar_integraciones():
    # Integraciones (Slack / webhooks custom) son exclusivas del plan Pro
    if current_user.plan_efectivo == 'free':
        return jsonify({"ok": False, "error": "Las integraciones (Slack y webhooks) son exclusivas del plan Pro. Actualiza tu plan para activarlas."}), 403
    data = request.get_json() or {}
    user = db.session.get(User, current_user.id)
    slack = (data.get("slack_webhook") or "").strip()
    custom = (data.get("custom_webhook") or "").strip()
    # Validar URLs
    if slack and not slack.startswith("https://hooks.slack.com/"):
        return jsonify({"ok": False, "error": "La URL de Slack debe empezar por https://hooks.slack.com/"}), 400
    if custom and not custom.startswith("https://"):
        return jsonify({"ok": False, "error": "El webhook debe usar HTTPS"}), 400
    user.slack_webhook = slack or None
    user.custom_webhook = custom or None
    db.session.commit()
    return jsonify({"ok": True})

def notificar_integraciones(user, resultado):
    """Envía notificación de resultado de escaneo a Slack y/o webhook custom del usuario.
    Robusto frente a:
      - user=None (current_user fuera de request context)
      - user detached (atributos lazy-load fallan en hilo)
    """
    if not user:
        return
    # Capturar atributos AHORA (en el hilo del request, sesión SQLA viva).
    try:
        slack_url    = getattr(user, "slack_webhook", None)
        custom_url   = getattr(user, "custom_webhook", None)
        user_email   = getattr(user, "email", "?")
    except Exception as _detach:
        logger.warning(f"[Integraciones] user detached, skip: {_detach}")
        return
    if not slack_url and not custom_url:
        return  # nada que notificar

    dominio = resultado.get("dominio", "")
    riesgo  = resultado.get("riesgo", 0)
    label   = resultado.get("label", "")
    puertos = resultado.get("puertos", [])
    ps_audit = resultado.get("ps") or {}
    skimmer_alert = bool(ps_audit.get("is_prestashop") and ps_audit.get("skimmer_suspect"))
    skimmer_evidence = (ps_audit.get("skimmer_evidence") or [])[:3]
    base_url = BASE_URL

    # Slack
    if slack_url:
        try:
            if skimmer_alert:
                slack_msg = {
                    "text": f":rotating_light: *RECONBASE — POSIBLE SKIMMER DETECTADO en {dominio}*",
                    "blocks": [
                        {"type": "header", "text": {"type": "plain_text", "text": f"🚨 SKIMMER · {dominio}"}},
                        {"type": "section", "text": {"type": "mrkdwn",
                            "text": f"*Alerta crítica de Magecart en tu checkout PrestaShop.*\nLa vigilancia ha detectado patrones característicos de robo de tarjeta en el JS del checkout."}},
                        {"type": "section", "fields": [
                            {"type": "mrkdwn", "text": f"*Riesgo:* {riesgo}% ({label})"},
                            {"type": "mrkdwn", "text": f"*PrestaShop:* {ps_audit.get('version','?')}"},
                        ]},
                        {"type": "section", "text": {"type": "mrkdwn",
                            "text": "*Evidencia:*\n" + "\n".join(f"• {e}" for e in skimmer_evidence) if skimmer_evidence else "*Evidencia:* patrones de ofuscación + referencias a campos de tarjeta"}},
                        {"type": "section", "text": {"type": "mrkdwn",
                            "text": "*Acción inmediata:* no toques nada, haz copia forense, cambia credenciales y notifica AEPD en 72h si confirmas exfiltración."}},
                        {"type": "actions", "elements": [
                            {"type": "button", "text": {"type": "plain_text", "text": "Ver informe completo"}, "url": base_url, "style": "danger"},
                            {"type": "button", "text": {"type": "plain_text", "text": "Protocolo de respuesta"}, "url": f"{base_url}/blog/skimmers-digitales-prestashop-magecart-2026"}
                        ]}
                    ]
                }
            else:
                emoji = ":red_circle:" if riesgo >= 70 else ":large_orange_circle:" if riesgo >= 40 else ":large_green_circle:"
                slack_msg = {
                    "text": f"{emoji} *ReconBase — Escaneo completado*",
                    "blocks": [
                        {"type": "header", "text": {"type": "plain_text", "text": f"ReconBase — Escaneo de {dominio}"}},
                        {"type": "section", "fields": [
                            {"type": "mrkdwn", "text": f"*Riesgo:* {riesgo}% ({label})"},
                            {"type": "mrkdwn", "text": f"*Puertos expuestos:* {len(puertos)}"},
                        ]},
                        {"type": "actions", "elements": [
                            {"type": "button", "text": {"type": "plain_text", "text": "Ver en ReconBase"}, "url": base_url}
                        ]}
                    ]
                }
            payload = json.dumps(slack_msg).encode("utf-8")
            req = urllib.request.Request(slack_url, data=payload,
                                        headers={"Content-Type": "application/json", "User-Agent": "ReconBase/1.0"},
                                        method="POST")
            urllib.request.urlopen(req, timeout=10)
            logger.info(f"[Slack] Notificación enviada a {user_email}{' (SKIMMER)' if skimmer_alert else ''}")
        except Exception as e:
            logger.warning(f"[Slack] Error para {user_email}: {e}")

    # Custom webhook
    if custom_url:
        try:
            webhook_payload_dict = {
                "event": "skimmer_detected" if skimmer_alert else "scan_completed",
                "dominio": dominio,
                "riesgo": riesgo,
                "label": label,
                "puertos": len(puertos),
                "timestamp": resultado.get("timestamp", ""),
                "url": base_url,
            }
            if skimmer_alert:
                webhook_payload_dict["severity"] = "critical"
                webhook_payload_dict["skimmer"] = {
                    "detected": True,
                    "version_prestashop": ps_audit.get("version"),
                    "evidence": skimmer_evidence,
                    "action_url": f"{base_url}/blog/skimmers-digitales-prestashop-magecart-2026",
                }
            webhook_payload = json.dumps(webhook_payload_dict).encode("utf-8")
            req = urllib.request.Request(custom_url, data=webhook_payload,
                                        headers={"Content-Type": "application/json", "User-Agent": "ReconBase/1.0"},
                                        method="POST")
            urllib.request.urlopen(req, timeout=10)
            logger.info(f"[Webhook] Notificación enviada a {user_email}{' (SKIMMER)' if skimmer_alert else ''}")
        except Exception as e:
            logger.warning(f"[Webhook] Error para {user_email}: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# ─── HELPERS: SSL, Uptime, Tech, DNS, IP Rep, Audit, Notificaciones ────────
# ═══════════════════════════════════════════════════════════════════════════

def _crear_notificacion(user_id, tipo, titulo, mensaje=None, url=None):
    """Crea una notificación in-app para el usuario."""
    try:
        n = Notification(user_id=user_id, tipo=tipo, titulo=titulo,
                         mensaje=mensaje, url=url)
        db.session.add(n)
        db.session.commit()
    except Exception as _e:
        logger.error(f"[Notif] {_e}")
        db.session.rollback()


def _registrar_audit(user_id, evento, detalles=None, req=None):
    """Registra un evento de auditoría."""
    try:
        ip = (req or request).remote_addr if (req or request) else None
        ua = (req or request).headers.get('User-Agent', '')[:500] if (req or request) else None
        log = AuditLog(user_id=user_id, evento=evento, ip=ip,
                       user_agent=ua, detalles=detalles)
        db.session.add(log)
        db.session.commit()
    except Exception as _e:
        logger.error(f"[Audit] {_e}")
        db.session.rollback()


def _check_ssl(dominio):
    """Comprueba el certificado SSL de un dominio. Devuelve dict con resultado."""
    try:
        ctx = _ssl_mod.create_default_context()
        with socket.create_connection((dominio, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
        expiry_str = cert.get('notAfter', '')
        expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
        dias = (expiry - datetime.utcnow()).days
        issuer  = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        return {
            'valido': True,
            'expira': expiry,
            'dias_restantes': dias,
            'emitido_por': issuer.get('organizationName', ''),
            'sujeto': subject.get('commonName', dominio),
            'error': None,
        }
    except _ssl_mod.SSLError as e:
        return {'valido': False, 'expira': None, 'dias_restantes': -1,
                'emitido_por': '', 'sujeto': dominio, 'error': str(e)[:400]}
    except Exception as e:
        return {'valido': None, 'expira': None, 'dias_restantes': -1,
                'emitido_por': '', 'sujeto': dominio, 'error': str(e)[:400]}


def _check_uptime(dominio):
    """Comprueba si un dominio responde. Devuelve dict {up, status_code, response_ms}."""
    import requests as _req
    for scheme in ('https', 'http'):
        try:
            t0 = time.time()
            r = _req.get(f"{scheme}://{dominio}", timeout=10, allow_redirects=True,
                         headers={'User-Agent': 'ReconBase-Uptime/1.0'})
            ms = int((time.time() - t0) * 1000)
            return {'up': True, 'status_code': r.status_code, 'response_ms': ms}
        except Exception:
            continue
    return {'up': False, 'status_code': None, 'response_ms': None}


def _detect_technologies(dominio):
    """Detecta tecnologías usadas en un dominio vía headers + HTML."""
    import requests as _req
    techs = []
    try:
        for scheme in ('https', 'http'):
            try:
                r = _req.get(f"{scheme}://{dominio}", timeout=12, allow_redirects=True,
                             headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconBase/1.0)'})
                break
            except Exception:
                continue
        else:
            return techs

        hdrs = {k.lower(): v for k, v in r.headers.items()}
        html = r.text[:80000]

        # ── Server ──
        srv = hdrs.get('server', '')
        if srv:
            if 'nginx' in srv.lower():
                techs.append({'nombre': 'Nginx', 'categoria': 'Servidor web',
                               'version': srv.split('/')[-1] if '/' in srv else ''})
            elif 'apache' in srv.lower():
                techs.append({'nombre': 'Apache', 'categoria': 'Servidor web', 'version': ''})
            elif 'iis' in srv.lower():
                techs.append({'nombre': 'Microsoft IIS', 'categoria': 'Servidor web', 'version': ''})
            elif 'litespeed' in srv.lower():
                techs.append({'nombre': 'LiteSpeed', 'categoria': 'Servidor web', 'version': ''})
            elif 'cloudflare' in srv.lower():
                techs.append({'nombre': 'Cloudflare', 'categoria': 'CDN / Proxy', 'version': ''})

        # ── X-Powered-By ──
        pb = hdrs.get('x-powered-by', '')
        if 'php' in pb.lower():
            vm = re.search(r'PHP/([\d.]+)', pb, re.I)
            techs.append({'nombre': 'PHP', 'categoria': 'Lenguaje backend',
                           'version': vm.group(1) if vm else ''})
        if 'asp.net' in pb.lower():
            techs.append({'nombre': 'ASP.NET', 'categoria': 'Framework', 'version': ''})

        # ── CDN / headers ──
        if 'cf-ray' in hdrs and not any(t['nombre'] == 'Cloudflare' for t in techs):
            techs.append({'nombre': 'Cloudflare', 'categoria': 'CDN / Proxy', 'version': ''})

        # ── CMS ──
        cms_patterns = [
            (r'wp-content|wp-includes|wordpress',            'WordPress',   'CMS'),
            (r'/sites/default/files|Drupal\.settings',       'Drupal',      'CMS'),
            (r'/components/com_|Joomla',                     'Joomla',      'CMS'),
            (r'cdn\.shopify\.com|shopify',                   'Shopify',     'E-commerce'),
            (r'woocommerce',                                 'WooCommerce', 'E-commerce'),
            (r'squarespace',                                 'Squarespace', 'CMS'),
            (r'wix\.com',                                    'Wix',         'CMS'),
            (r'webflow\.com',                                'Webflow',     'CMS'),
            (r'ghost\.org|content-api\.ghost\.io',           'Ghost',       'CMS'),
            (r'prestashop',                                  'PrestaShop',  'E-commerce'),
            (r'magento',                                     'Magento',     'E-commerce'),
        ]
        for pat, nombre, cat in cms_patterns:
            if re.search(pat, html, re.I):
                if not any(t['nombre'] == nombre for t in techs):
                    vm = None
                    if nombre == 'WordPress':
                        vm = re.search(r'ver=([\d.]+)', html)
                    techs.append({'nombre': nombre, 'categoria': cat,
                                   'version': vm.group(1) if vm else ''})

        # ── JS Frameworks ──
        js_patterns = [
            (r'data-reactroot|__REACT|react\.production\.min',        'React',   'Framework JS'),
            (r'__vue|data-v-[a-f0-9]{8}|vue\.min\.js',               'Vue.js',  'Framework JS'),
            (r'ng-version="([\d.]+)"',                                'Angular', 'Framework JS'),
            (r'svelte',                                               'Svelte',  'Framework JS'),
            (r'nuxt|__nuxt',                                          'Nuxt.js', 'Framework JS'),
            (r'__next|_next/static',                                  'Next.js', 'Framework JS'),
        ]
        for pat, nombre, cat in js_patterns:
            m = re.search(pat, html, re.I)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else ''
                techs.append({'nombre': nombre, 'categoria': cat, 'version': version})

        # ── Analytics ──
        if re.search(r'google-analytics\.com|gtag\(', html, re.I):
            techs.append({'nombre': 'Google Analytics', 'categoria': 'Analytics', 'version': ''})
        if 'googletagmanager.com' in html:
            techs.append({'nombre': 'Google Tag Manager', 'categoria': 'Analytics', 'version': ''})
        if re.search(r'plausible\.io', html, re.I):
            techs.append({'nombre': 'Plausible', 'categoria': 'Analytics', 'version': ''})
        if re.search(r'hotjar', html, re.I):
            techs.append({'nombre': 'Hotjar', 'categoria': 'Analytics', 'version': ''})

        # ── CSS Frameworks ──
        if re.search(r'bootstrap', html, re.I):
            bm = re.search(r'bootstrap(?:\.min)?\.css\?v=([\d.]+)', html, re.I)
            techs.append({'nombre': 'Bootstrap', 'categoria': 'CSS Framework',
                           'version': bm.group(1) if bm else ''})
        if re.search(r'tailwindcss|tailwind', html, re.I):
            techs.append({'nombre': 'Tailwind CSS', 'categoria': 'CSS Framework', 'version': ''})

        # ── JS Libs ──
        if re.search(r'jquery', html, re.I):
            jm = re.search(r'jquery-([\d.]+)', html, re.I)
            techs.append({'nombre': 'jQuery', 'categoria': 'Librería JS',
                           'version': jm.group(1) if jm else ''})

        # ── Seguridad (headers presentes) ──
        if 'x-frame-options' in hdrs:
            techs.append({'nombre': 'X-Frame-Options', 'categoria': 'Seguridad',
                           'version': hdrs['x-frame-options']})
        if 'content-security-policy' in hdrs:
            techs.append({'nombre': 'Content-Security-Policy', 'categoria': 'Seguridad', 'version': '✓'})
        if 'strict-transport-security' in hdrs:
            techs.append({'nombre': 'HSTS', 'categoria': 'Seguridad', 'version': '✓'})

    except Exception as e:
        logger.error(f"[Tech] {dominio}: {e}")
    return techs


def _check_dns_cambios(user_id, dominio):
    """Detecta cambios en registros DNS respecto al snapshot anterior."""
    try:
        import dns.resolver as _resolver
    except ImportError:
        return []

    cambios = []
    tipos = ['A', 'MX', 'TXT', 'NS']
    for tipo in tipos:
        try:
            answers = _resolver.resolve(dominio, tipo, raise_on_no_answer=False, lifetime=5)
            nuevos = set()
            for rd in answers:
                if tipo == 'A':
                    nuevos.add(str(rd))
                elif tipo == 'MX':
                    nuevos.add(f"{rd.preference} {rd.exchange}")
                elif tipo == 'TXT':
                    nuevos.add(b''.join(rd.strings).decode('utf-8', errors='ignore'))
                elif tipo == 'NS':
                    nuevos.add(str(rd))

            existentes = DNSRecord.query.filter_by(
                user_id=user_id, dominio=dominio, tipo=tipo, activo=True).all()
            existentes_vals = {r.valor for r in existentes}

            # Añadidos
            for val in nuevos - existentes_vals:
                try:
                    rec = DNSRecord(user_id=user_id, dominio=dominio,
                                    tipo=tipo, valor=val, activo=True)
                    db.session.add(rec)
                    if existentes:   # Solo alerta si ya teníamos datos previos
                        cambios.append({'tipo': tipo, 'valor': val, 'cambio': 'añadido'})
                except Exception:
                    db.session.rollback()

            # Eliminados
            for rec in existentes:
                if rec.valor not in nuevos:
                    rec.activo = False
                    cambios.append({'tipo': tipo, 'valor': rec.valor, 'cambio': 'eliminado'})
                else:
                    rec.ultima_vez = datetime.utcnow()

            db.session.commit()
        except Exception:
            db.session.rollback()
    return cambios


def _check_ip_reputacion(ip):
    """Comprueba la IP contra listas negras DNS (DNSBL)."""
    try:
        import dns.resolver as _resolver
    except ImportError:
        return {'limpio': True, 'listas_negras': []}

    DNSBL = [
        'zen.spamhaus.org', 'bl.spamcop.net', 'dnsbl.sorbs.net',
        'cbl.abuseat.org',  'b.barracudacentral.org', 'dnsbl-1.uceprotect.net',
    ]
    reversed_ip = '.'.join(reversed(ip.split('.')))
    listas = []
    for bl in DNSBL:
        try:
            _resolver.resolve(f"{reversed_ip}.{bl}", 'A', lifetime=3)
            listas.append(bl)
        except Exception:
            pass
    return {'limpio': len(listas) == 0, 'listas_negras': listas}


def _generar_numero_factura():
    year = datetime.utcnow().year
    count = Invoice.query.filter(
        Invoice.created_at >= datetime(year, 1, 1)).count() + 1
    return f"RB-{year}-{count:04d}"


# ═══════════════════════════════════════════════════════════════════════════
# ─── CRON: SSL, Uptime, DNS, IP Rep, PDF Reports ──────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

def cron_ssl_monitoring():
    """Comprueba SSL para todos los dominios activos. Alerta si <30 días."""
    with app.app_context():
        dominios_vistos = set()
        users = User.query.filter(User.email_verified == True).all()
        for user in users:
            doms = Domain.query.filter_by(user_id=user.id, activo=True).all()
            for dom in doms:
                d = dom.dominio
                if d in dominios_vistos:
                    continue
                dominios_vistos.add(d)
                try:
                    res = _check_ssl(d)
                    # Upsert: borrar el check anterior del mismo dominio/usuario
                    SSLCheck.query.filter_by(user_id=user.id, dominio=d).delete()
                    sc = SSLCheck(
                        user_id=user.id, dominio=d,
                        valido=res['valido'], expira=res['expira'],
                        dias_restantes=res.get('dias_restantes', 0),
                        emitido_por=res.get('emitido_por', ''),
                        sujeto=res.get('sujeto', d),
                        error=res.get('error'),
                    )
                    db.session.add(sc)
                    db.session.commit()
                    dias = res.get('dias_restantes', 999)
                    if res['valido'] is False:
                        _crear_notificacion(user.id, 'ssl',
                            f"⚠️ SSL inválido en {d}",
                            f"El certificado SSL de {d} no es válido: {res.get('error','')}")
                    elif dias is not None and dias <= 30:
                        nivel = '🔴' if dias <= 7 else '🟠' if dias <= 15 else '🟡'
                        _crear_notificacion(user.id, 'ssl',
                            f"{nivel} SSL de {d} expira en {dias} días",
                            f"Renueva el certificado SSL de {d} antes de que expire.")
                except Exception as e:
                    logger.error(f"[Cron SSL] {d}: {e}")
                    db.session.rollback()


def cron_uptime_monitoring():
    """Comprueba uptime de todos los dominios activos cada 15 min."""
    with app.app_context():
        dominios_vistos = {}
        users = User.query.filter(User.email_verified == True).all()
        for user in users:
            doms = Domain.query.filter_by(user_id=user.id, activo=True).all()
            for dom in doms:
                d = dom.dominio
                if d in dominios_vistos:
                    res = dominios_vistos[d]
                else:
                    res = _check_uptime(d)
                    dominios_vistos[d] = res
                try:
                    uc = UptimeCheck(
                        user_id=user.id, dominio=d,
                        up=res['up'], status_code=res.get('status_code'),
                        response_ms=res.get('response_ms'),
                    )
                    db.session.add(uc)
                    db.session.commit()
                    if not res['up']:
                        # Solo notificar si los 2 últimos checks fueron down
                        recientes = UptimeCheck.query.filter_by(
                            user_id=user.id, dominio=d
                        ).order_by(UptimeCheck.checked_at.desc()).limit(2).all()
                        if len(recientes) >= 2 and all(not r.up for r in recientes):
                            _crear_notificacion(user.id, 'uptime',
                                f"🔴 {d} no responde",
                                f"El dominio {d} lleva más de 15 minutos sin responder.")
                except Exception as e:
                    logger.error(f"[Cron Uptime] {d}: {e}")
                    db.session.rollback()
        # Limpiar historial >7 días para no crecer indefinidamente
        try:
            cutoff = datetime.utcnow() - timedelta(days=7)
            UptimeCheck.query.filter(UptimeCheck.checked_at < cutoff).delete()
            db.session.commit()
        except Exception:
            db.session.rollback()


def cron_dns_monitoring():
    """Detecta cambios en DNS para todos los dominios activos."""
    with app.app_context():
        users = User.query.filter(User.email_verified == True).all()
        for user in users:
            doms = Domain.query.filter_by(user_id=user.id, activo=True).all()
            for dom in doms:
                try:
                    cambios = _check_dns_cambios(user.id, dom.dominio)
                    if cambios:
                        detalle = ', '.join(
                            f"{c['tipo']} {c['cambio']}: {c['valor'][:40]}"
                            for c in cambios[:5])
                        _crear_notificacion(user.id, 'dns',
                            f"⚡ Cambio DNS en {dom.dominio}",
                            f"Se detectaron {len(cambios)} cambios: {detalle}")
                except Exception as e:
                    logger.error(f"[Cron DNS] {dom.dominio}: {e}")


def cron_ip_reputation():
    """Comprueba reputación IP de todos los dominios activos (diario)."""
    with app.app_context():
        dominios_vistos = {}
        users = User.query.filter(User.email_verified == True).all()
        for user in users:
            doms = Domain.query.filter_by(user_id=user.id, activo=True).all()
            for dom in doms:
                d = dom.dominio
                try:
                    # Resolver IP del dominio
                    import dns.resolver as _res
                    ips = [str(r) for r in _res.resolve(d, 'A', lifetime=5)]
                    ip = ips[0] if ips else None
                    if not ip:
                        continue
                    if ip in dominios_vistos:
                        rep = dominios_vistos[ip]
                    else:
                        rep = _check_ip_reputacion(ip)
                        dominios_vistos[ip] = rep

                    IPReputation.query.filter_by(user_id=user.id, dominio=d).delete()
                    ir = IPReputation(
                        user_id=user.id, dominio=d, ip=ip,
                        limpio=rep['limpio'],
                        listas_negras=json.dumps(rep['listas_negras']),
                    )
                    db.session.add(ir)
                    db.session.commit()
                    if not rep['limpio']:
                        listas = ', '.join(rep['listas_negras'][:3])
                        _crear_notificacion(user.id, 'ip_rep',
                            f"🚨 IP de {d} en lista negra",
                            f"La IP {ip} aparece en: {listas}")
                except Exception as e:
                    logger.error(f"[Cron IP Rep] {d}: {e}")
                    db.session.rollback()


def cron_pdf_reports():
    """Genera y envía informes PDF automáticos según la configuración de cada usuario."""
    with app.app_context():
        hoy = datetime.utcnow()
        users = User.query.filter_by(informe_pdf_activo=True, email_verified=True).all()
        for user in users:
            try:
                frecuencia = user.informe_pdf_frecuencia or 'semanal'
                dia = user.informe_pdf_dia or 1
                # Semanal: día de la semana 0-6 (0=lunes)
                if frecuencia == 'semanal' and hoy.weekday() != dia:
                    continue
                # Mensual: día del mes
                if frecuencia == 'mensual' and hoy.day != dia:
                    continue

                # Generar informe
                desde = hoy - timedelta(days=7 if frecuencia == 'semanal' else 30)
                scans = Scan.query.filter(
                    Scan.user_id == user.id,
                    Scan.timestamp >= desde
                ).order_by(Scan.timestamp.desc()).all()

                if not scans:
                    continue

                riesgo_avg = round(sum(s.riesgo for s in scans) / len(scans))
                # Generar PDF si está disponible
                pdf_bytes = None
                if PDF_OK:
                    try:
                        pdf = FPDF()
                        pdf.set_auto_page_break(auto=True, margin=15)
                        pdf.add_page()
                        pdf.set_font('Helvetica', 'B', 20)
                        pdf.set_text_color(22, 163, 74)
                        pdf.cell(0, 12, 'ReconBase — Informe de Seguridad', ln=True, align='C')
                        pdf.set_font('Helvetica', '', 11)
                        pdf.set_text_color(100, 116, 139)
                        pdf.cell(0, 8, f"Empresa: {user.empresa}  |  Periodo: {desde.strftime('%d/%m/%Y')} — {hoy.strftime('%d/%m/%Y')}", ln=True, align='C')
                        pdf.ln(6)
                        pdf.set_fill_color(240, 253, 244)
                        pdf.set_font('Helvetica', 'B', 13)
                        pdf.set_text_color(0, 0, 0)
                        pdf.cell(0, 10, 'Resumen ejecutivo', ln=True, fill=True)
                        pdf.set_font('Helvetica', '', 11)
                        pdf.cell(90, 9, f"Escaneos realizados: {len(scans)}", ln=False)
                        pdf.cell(0, 9, f"Riesgo promedio: {riesgo_avg}%", ln=True)
                        pdf.ln(4)
                        pdf.set_font('Helvetica', 'B', 13)
                        pdf.cell(0, 10, 'Detalle de escaneos', ln=True, fill=True)
                        pdf.set_font('Helvetica', 'B', 9)
                        for col, w in [('Dominio', 70), ('Riesgo', 25), ('Nivel', 35), ('Fecha', 55)]:
                            pdf.cell(w, 8, col, border=1)
                        pdf.ln()
                        pdf.set_font('Helvetica', '', 9)
                        for s in scans[:30]:
                            pdf.cell(70, 7, s.objetivo[:35], border=1)
                            pdf.cell(25, 7, f"{s.riesgo}%", border=1, align='C')
                            pdf.cell(35, 7, s.label or '', border=1, align='C')
                            pdf.cell(55, 7, s.timestamp.strftime('%d/%m/%Y %H:%M'), border=1)
                            pdf.ln()
                        pdf_bytes = bytes(pdf.output())
                    except Exception as _pe:
                        logger.error(f"[PDF Report] PDF error para {user.email}: {_pe}")

                periodo = f"{desde.strftime('%d/%m/%Y')} — {hoy.strftime('%d/%m/%Y')}"
                cuerpo = f"""
<p>Hola {user.empresa},</p>
<p>Aquí tienes tu informe de seguridad automático correspondiente al periodo <strong>{periodo}</strong>.</p>
<table style="width:100%;border-collapse:collapse;margin:1rem 0">
  <tr><td style="padding:.5rem;background:#0A1410;color:#94A3B8;font-size:.8rem">Escaneos realizados</td>
      <td style="padding:.5rem;font-weight:700;font-size:1.1rem">{len(scans)}</td></tr>
  <tr><td style="padding:.5rem;background:#0A1410;color:#94A3B8;font-size:.8rem">Riesgo promedio</td>
      <td style="padding:.5rem;font-weight:700;font-size:1.1rem;color:{'#DC2626' if riesgo_avg>=70 else '#D97706' if riesgo_avg>=40 else '#16A34A'}">{riesgo_avg}%</td></tr>
</table>
<p style="color:#94A3B8;font-size:.85rem">{"El informe PDF detallado se adjunta a este email." if pdf_bytes else ""}</p>
"""
                send_html_email(user.email,
                    f"Informe de seguridad — {periodo}",
                    "Tu informe de seguridad ReconBase", cuerpo,
                    BASE_URL + "/",
                    "Ver plataforma")
            except Exception as e:
                logger.error(f"[Cron PDF] {user.email}: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# ─── RUTAS: Notificaciones ─────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/notificaciones")
@login_required
def get_notificaciones():
    notifs = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc()).limit(50).all()
    no_leidas = sum(1 for n in notifs if not n.leida)
    return jsonify({
        "notificaciones": [{
            "id": n.id, "tipo": n.tipo, "titulo": n.titulo,
            "mensaje": n.mensaje, "leida": n.leida,
            "url": n.url,
            "created_at": n.created_at.strftime('%d/%m/%Y %H:%M'),
        } for n in notifs],
        "no_leidas": no_leidas,
    })


@app.route("/api/notificaciones/<int:nid>/leer", methods=["POST"])
@login_required
def marcar_notif_leida(nid):
    n = Notification.query.filter_by(id=nid, user_id=current_user.id).first_or_404()
    n.leida = True
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/notificaciones/leer-todas", methods=["POST"])
@login_required
def marcar_todas_leidas():
    Notification.query.filter_by(user_id=current_user.id, leida=False)\
        .update({'leida': True})
    db.session.commit()
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════════════════
# ─── RUTAS: SSL / Uptime / Tech / DNS / IP Rep ────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/ssl")
@login_required
def get_ssl():
    uid = current_user.id
    checks = SSLCheck.query.filter_by(user_id=uid)\
        .order_by(SSLCheck.checked_at.desc()).all()
    # Si no hay checks, lanzar uno en background
    if not checks:
        def _bg(user_id=uid):
            with app.app_context():
                doms = Domain.query.filter_by(user_id=user_id, activo=True).all()
                for dom in doms:
                    res = _check_ssl(dom.dominio)
                    SSLCheck.query.filter_by(user_id=user_id, dominio=dom.dominio).delete()
                    sc = SSLCheck(user_id=user_id, dominio=dom.dominio,
                                  valido=res['valido'], expira=res['expira'],
                                  dias_restantes=res.get('dias_restantes', 0),
                                  emitido_por=res.get('emitido_por',''),
                                  sujeto=res.get('sujeto', dom.dominio),
                                  error=res.get('error'))
                    db.session.add(sc)
                    db.session.commit()
        threading.Thread(target=_bg, daemon=True).start()

    return jsonify({"ssl": [{
        "dominio": c.dominio,
        "valido": c.valido,
        "dias_restantes": c.dias_restantes,
        "expira": c.expira.strftime('%d/%m/%Y') if c.expira else None,
        "emitido_por": c.emitido_por,
        "sujeto": c.sujeto,
        "error": c.error,
        "checked_at": c.checked_at.strftime('%d/%m/%Y %H:%M'),
    } for c in checks]})


@app.route("/api/ssl/refresh", methods=["POST"])
@login_required
@limiter.limit("6 per hour")
def refresh_ssl():
    """Fuerza un nuevo check SSL en background."""
    def _bg(uid):
        with app.app_context():
            doms = Domain.query.filter_by(user_id=uid, activo=True).all()
            for dom in doms:
                res = _check_ssl(dom.dominio)
                SSLCheck.query.filter_by(user_id=uid, dominio=dom.dominio).delete()
                sc = SSLCheck(user_id=uid, dominio=dom.dominio,
                              valido=res['valido'], expira=res['expira'],
                              dias_restantes=res.get('dias_restantes', 0),
                              emitido_por=res.get('emitido_por',''),
                              sujeto=res.get('sujeto', dom.dominio),
                              error=res.get('error'))
                db.session.add(sc)
                db.session.commit()
    threading.Thread(target=_bg, args=(current_user.id,), daemon=True).start()
    return jsonify({"ok": True, "msg": "Check SSL lanzado en background"})


@app.route("/api/uptime")
@login_required
def get_uptime():
    # Último check por dominio
    from sqlalchemy import func
    subq = db.session.query(
        UptimeCheck.dominio,
        func.max(UptimeCheck.checked_at).label('last_check')
    ).filter_by(user_id=current_user.id).group_by(UptimeCheck.dominio).subquery()

    checks = db.session.query(UptimeCheck).join(
        subq, (UptimeCheck.dominio == subq.c.dominio) &
               (UptimeCheck.checked_at == subq.c.last_check)
    ).filter(UptimeCheck.user_id == current_user.id).all()

    # Historial últimas 24h por dominio
    since = datetime.utcnow() - timedelta(hours=24)
    history_raw = UptimeCheck.query.filter(
        UptimeCheck.user_id == current_user.id,
        UptimeCheck.checked_at >= since
    ).order_by(UptimeCheck.checked_at.asc()).all()

    history = {}
    for c in history_raw:
        history.setdefault(c.dominio, []).append({
            'up': c.up, 'ms': c.response_ms,
            'ts': c.checked_at.strftime('%H:%M'),
        })

    return jsonify({"uptime": [{
        "dominio": c.dominio,
        "up": c.up,
        "status_code": c.status_code,
        "response_ms": c.response_ms,
        "checked_at": c.checked_at.strftime('%d/%m/%Y %H:%M'),
        "history": history.get(c.dominio, []),
    } for c in checks]})


@app.route("/api/tecnologias")
@login_required
@limiter.limit("10 per hour")
def get_tecnologias():
    detecciones = TechDetection.query.filter_by(user_id=current_user.id)\
        .order_by(TechDetection.detected_at.desc()).all()
    return jsonify({"tecnologias": [{
        "dominio": t.dominio,
        "tecnologias": json.loads(t.tecnologias) if t.tecnologias else [],
        "detected_at": t.detected_at.strftime('%d/%m/%Y %H:%M'),
    } for t in detecciones]})


@app.route("/api/tecnologias/refresh", methods=["POST"])
@login_required
@limiter.limit("4 per hour")
def refresh_tecnologias():
    def _bg(uid):
        with app.app_context():
            doms = Domain.query.filter_by(user_id=uid, activo=True).all()
            for dom in doms:
                techs = _detect_technologies(dom.dominio)
                TechDetection.query.filter_by(user_id=uid, dominio=dom.dominio).delete()
                td = TechDetection(user_id=uid, dominio=dom.dominio,
                                   tecnologias=json.dumps(techs))
                db.session.add(td)
                db.session.commit()
    threading.Thread(target=_bg, args=(current_user.id,), daemon=True).start()
    return jsonify({"ok": True, "msg": "Detección lanzada"})


@app.route("/api/dns-cambios")
@login_required
def get_dns_cambios():
    # Todos los registros del usuario, separados en activos e históricos
    registros = DNSRecord.query.filter_by(user_id=current_user.id)\
        .order_by(DNSRecord.dominio, DNSRecord.tipo, DNSRecord.primera_vez.desc()).all()

    por_dominio = {}
    for r in registros:
        por_dominio.setdefault(r.dominio, []).append({
            'tipo': r.tipo, 'valor': r.valor,
            'activo': r.activo,
            'desde': r.primera_vez.strftime('%d/%m/%Y'),
            'hasta': None if r.activo else r.ultima_vez.strftime('%d/%m/%Y'),
        })
    return jsonify({"dns": [{"dominio": d, "registros": v}
                             for d, v in por_dominio.items()]})


@app.route("/api/dns-cambios/refresh", methods=["POST"])
@login_required
@limiter.limit("6 per hour")
def refresh_dns():
    def _bg(uid):
        with app.app_context():
            doms = Domain.query.filter_by(user_id=uid, activo=True).all()
            for dom in doms:
                cambios = _check_dns_cambios(uid, dom.dominio)
                if cambios:
                    _crear_notificacion(uid, 'dns',
                        f"⚡ Cambio DNS en {dom.dominio}",
                        f"Detectados {len(cambios)} cambios en registros DNS.")
    threading.Thread(target=_bg, args=(current_user.id,), daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/ip-reputacion")
@login_required
def get_ip_reputacion():
    checks = IPReputation.query.filter_by(user_id=current_user.id)\
        .order_by(IPReputation.checked_at.desc()).all()
    return jsonify({"reputacion": [{
        "dominio": c.dominio,
        "ip": c.ip,
        "limpio": c.limpio,
        "listas_negras": json.loads(c.listas_negras) if c.listas_negras else [],
        "checked_at": c.checked_at.strftime('%d/%m/%Y %H:%M'),
    } for c in checks]})


@app.route("/api/ip-reputacion/refresh", methods=["POST"])
@login_required
@limiter.limit("4 per hour")
def refresh_ip_reputacion():
    def _bg(uid):
        with app.app_context():
            doms = Domain.query.filter_by(user_id=uid, activo=True).all()
            for dom in doms:
                try:
                    import dns.resolver as _res
                    ips = [str(r) for r in _res.resolve(dom.dominio, 'A', lifetime=5)]
                    ip = ips[0] if ips else None
                    if not ip:
                        continue
                    rep = _check_ip_reputacion(ip)
                    IPReputation.query.filter_by(user_id=uid, dominio=dom.dominio).delete()
                    ir = IPReputation(user_id=uid, dominio=dom.dominio, ip=ip,
                                     limpio=rep['limpio'],
                                     listas_negras=json.dumps(rep['listas_negras']))
                    db.session.add(ir)
                    db.session.commit()
                    if not rep['limpio']:
                        listas = ', '.join(rep['listas_negras'][:3])
                        _crear_notificacion(uid, 'ip_rep',
                            f"🚨 IP de {dom.dominio} en lista negra",
                            f"La IP {ip} aparece en: {listas}")
                except Exception as e:
                    logger.error(f"[IP Rep refresh] {dom.dominio}: {e}")
                    db.session.rollback()
    threading.Thread(target=_bg, args=(current_user.id,), daemon=True).start()
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════════════════
# ─── RUTAS: Audit Log ──────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/audit-log")
@login_required
def get_audit_log():
    logs = AuditLog.query.filter_by(user_id=current_user.id)\
        .order_by(AuditLog.created_at.desc()).limit(50).all()
    return jsonify({"logs": [{
        "id": l.id,
        "evento": l.evento,
        "ip": l.ip,
        "detalles": l.detalles,
        "created_at": l.created_at.strftime('%d/%m/%Y %H:%M'),
    } for l in logs]})


# ═══════════════════════════════════════════════════════════════════════════
# ─── RUTAS: Trial 14 días gratis ──────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/trial/activar", methods=["POST"])
@app.route("/api/activar-trial", methods=["POST"])
@login_required
@limiter.limit("3 per day")
def activar_trial():
    user = db.session.get(User, current_user.id)
    if user.trial_used:
        return jsonify({"ok": False, "error": "Ya usaste tu período de prueba gratuito"}), 400
    if user.plan == 'pro':
        return jsonify({"ok": False, "error": "Ya tienes el plan Pro"}), 400
    user.trial_end = datetime.utcnow() + timedelta(days=14)
    user.trial_used = True
    db.session.commit()
    _registrar_audit(user.id, 'trial_activado', f"Trial Pro 14 días activado")
    _crear_notificacion(user.id, 'trial',
        "🎉 Trial Pro activo — 14 días",
        "Tienes acceso completo a todas las funciones Pro durante 14 días. ¡Aprovéchalo!")
    try:
        send_html_email(user.email,
            "¡Tu Trial Pro de ReconBase ha comenzado!",
            "Trial Pro activo — 14 días de acceso completo",
            f"""<p>Hola {user.empresa},</p>
<p>Tu período de prueba <strong>Pro de 14 días</strong> está ahora activo.
Tienes acceso completo a todas las funciones:</p>
<ul style="color:#94A3B8;margin:.5rem 0 1rem 1.5rem">
<li>Dominios ilimitados</li><li>Escaneos ilimitados</li>
<li>Monitorización SSL/Uptime/DNS en tiempo real</li>
<li>API pública</li><li>Alertas avanzadas</li>
</ul>
<p>Tu trial expira el <strong>{user.trial_end.strftime('%d/%m/%Y')}</strong>.</p>""",
            BASE_URL + "/",
            "Ir a ReconBase")
    except Exception:
        pass
    return jsonify({"ok": True, "trial_end": user.trial_end.strftime('%d/%m/%Y')})


# ═══════════════════════════════════════════════════════════════════════════
# ─── RUTAS: Facturas ──────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/facturas")
@login_required
def get_facturas():
    facturas = Invoice.query.filter_by(user_id=current_user.id)\
        .order_by(Invoice.created_at.desc()).all()
    return jsonify({"facturas": [{
        "id": f.id,
        "numero": f.numero,
        "concepto": f.concepto,
        "importe": f.importe,
        "moneda": f.moneda,
        "estado": f.estado,
        "created_at": f.created_at.strftime('%d/%m/%Y'),
        "periodo": (f"{f.periodo_desde.strftime('%d/%m/%Y')} — {f.periodo_hasta.strftime('%d/%m/%Y')}"
                    if f.periodo_desde and f.periodo_hasta else None),
    } for f in facturas]})


@app.route("/api/facturas/<int:fid>/pdf")
@login_required
def descargar_factura_pdf(fid):
    factura = Invoice.query.filter_by(id=fid, user_id=current_user.id).first_or_404()
    user    = db.session.get(User, current_user.id)
    if not PDF_OK:
        return jsonify({"ok": False, "error": "PDF no disponible"}), 500
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        # Cabecera
        pdf.set_font('Helvetica', 'B', 22)
        pdf.set_text_color(22, 163, 74)
        pdf.cell(0, 14, 'RECONBASE', ln=True, align='L')
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, BASE_HOST, ln=True)
        pdf.cell(0, 6, 'hola@reconbase.es', ln=True)
        pdf.ln(8)
        pdf.set_font('Helvetica', 'B', 28)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 14, 'FACTURA', ln=True, align='R')
        pdf.set_font('Helvetica', '', 11)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, f"Nº: {factura.numero}", ln=True, align='R')
        pdf.cell(0, 6, f"Fecha: {factura.created_at.strftime('%d/%m/%Y')}", ln=True, align='R')
        pdf.ln(8)
        # Cliente
        pdf.set_fill_color(240, 253, 244)
        pdf.set_font('Helvetica', 'B', 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 9, 'Datos del cliente', ln=True, fill=True)
        pdf.set_font('Helvetica', '', 11)
        pdf.cell(0, 7, f"Empresa: {user.empresa}", ln=True)
        pdf.cell(0, 7, f"Email: {user.email}", ln=True)
        pdf.ln(8)
        # Concepto
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(0, 9, 'Concepto', ln=True, fill=True)
        pdf.set_font('Helvetica', 'B', 10)
        for col, w in [('Descripción', 110), ('Importe', 40)]:
            pdf.cell(w, 8, col, border=1, fill=True)
        pdf.ln()
        pdf.set_font('Helvetica', '', 10)
        periodo = (f" ({factura.periodo_desde.strftime('%d/%m/%Y')} — {factura.periodo_hasta.strftime('%d/%m/%Y')})"
                   if factura.periodo_desde and factura.periodo_hasta else "")
        pdf.cell(110, 8, (factura.concepto or '') + periodo, border=1)
        _imp = factura.importe or 0.0
        pdf.cell(40, 8, f"{_imp:.2f} {factura.moneda or 'EUR'}", border=1, align='R')
        pdf.ln(10)
        pdf.set_font('Helvetica', 'B', 12)
        pdf.cell(110, 9, 'TOTAL')
        pdf.cell(40, 9, f"{_imp:.2f} {factura.moneda or 'EUR'}", align='R')
        pdf.ln(16)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 6, f"Estado: {factura.estado.upper()}  |  Factura {factura.numero}", ln=True, align='C')

        buf = io.BytesIO(bytes(pdf.output()))
        return send_file(buf, mimetype='application/pdf',
                         download_name=f"factura-{factura.numero}.pdf",
                         as_attachment=True)
    except Exception as e:
        logger.error(f"[Factura PDF] {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════
# ─── RUTAS: Informe PDF automático ────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/informe-pdf", methods=["GET", "POST"])
@login_required
def informe_pdf_config():
    user = db.session.get(User, current_user.id)
    if request.method == 'GET':
        return jsonify({
            "activo": user.informe_pdf_activo,
            "frecuencia": user.informe_pdf_frecuencia or 'semanal',
            "dia": user.informe_pdf_dia or 1,
        })
    data = request.get_json()
    user.informe_pdf_activo    = bool(data.get('activo', False))
    user.informe_pdf_frecuencia = data.get('frecuencia', 'semanal')
    user.informe_pdf_dia       = int(data.get('dia', 1))
    db.session.commit()
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════════════════
# ─── RUTA: Onboarding ──────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/onboarding/completar", methods=["POST"])
@login_required
def completar_onboarding():
    user = db.session.get(User, current_user.id)
    user.onboarding_done = True
    db.session.commit()
    return jsonify({"ok": True})


# ─── Registrar cron jobs batch 2 (APScheduler soporta add tras start) ────────
try:
    scheduler.add_job(cron_ssl_monitoring,   'cron', hour=6,   minute=0,   id='ssl_mon',    replace_existing=True)
    scheduler.add_job(cron_uptime_monitoring, 'cron', minute='*/15',        id='uptime_mon', replace_existing=True)
    scheduler.add_job(cron_dns_monitoring,   'cron', minute=30,             id='dns_mon',    replace_existing=True)
    scheduler.add_job(cron_ip_reputation,    'cron', hour=5,   minute=0,   id='ip_rep',     replace_existing=True)
    scheduler.add_job(cron_pdf_reports,      'cron', hour=7,   minute=30,  id='pdf_rep',    replace_existing=True)
except Exception as _sched_e:
    logger.warning(f"[Scheduler] Batch 2 jobs: {_sched_e}")


with app.app_context():
    db.create_all()
    from sqlalchemy import text
    for col_sql in [
        "ALTER TABLE users ADD COLUMN plan VARCHAR(20) DEFAULT 'free' NOT NULL",
        "ALTER TABLE users ADD COLUMN scan_hora INTEGER DEFAULT 3",
        "ALTER TABLE users ADD COLUMN scan_dias VARCHAR(20) DEFAULT '0,1,2,3,4,5,6'",
        "ALTER TABLE scans ADD COLUMN pdf_unlocked BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE users ADD COLUMN verify_token VARCHAR(64)",
        "ALTER TABLE users ADD COLUMN trial_end TIMESTAMP",
        "ALTER TABLE users ADD COLUMN reset_token VARCHAR(64)",
        "ALTER TABLE users ADD COLUMN reset_token_expiry TIMESTAMP",
        "ALTER TABLE users ADD COLUMN share_token VARCHAR(32)",
        "ALTER TABLE scans ADD COLUMN share_token VARCHAR(32)",
        "ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE users ADD COLUMN slack_webhook VARCHAR(500)",
        "ALTER TABLE users ADD COLUMN custom_webhook VARCHAR(500)",
        "CREATE TABLE IF NOT EXISTS domains (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), dominio VARCHAR(255) NOT NULL, activo BOOLEAN DEFAULT TRUE NOT NULL, added_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, dominio))",
        "ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64)",
        "ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE users ADD COLUMN alerta_umbral INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN api_key VARCHAR(64) UNIQUE",
        "ALTER TABLE users ADD COLUMN api_calls_month INTEGER DEFAULT 0",
        "ALTER TABLE domains ADD COLUMN scan_hora INTEGER",
        "ALTER TABLE domains ADD COLUMN scan_dias VARCHAR(20)",
        "CREATE TABLE IF NOT EXISTS blog_posts (id SERIAL PRIMARY KEY, slug VARCHAR(200) UNIQUE NOT NULL, titulo VARCHAR(300) NOT NULL, excerpt VARCHAR(500), contenido TEXT NOT NULL, autor VARCHAR(100) DEFAULT 'ReconBase', imagen VARCHAR(500), publicado BOOLEAN DEFAULT FALSE NOT NULL, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW(), tags VARCHAR(300))",
        "ALTER TABLE leads ADD COLUMN followup_sent BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE leads ADD COLUMN followup_stage INTEGER DEFAULT 0 NOT NULL",
        "ALTER TABLE leads ADD COLUMN last_email_at TIMESTAMP",
        "ALTER TABLE leads ADD COLUMN unsubscribed BOOLEAN DEFAULT FALSE NOT NULL",
        # ── Batch 2 ──
        "ALTER TABLE users ADD COLUMN trial_used BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE users ADD COLUMN onboarding_done BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE users ADD COLUMN informe_pdf_activo BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE users ADD COLUMN informe_pdf_frecuencia VARCHAR(20) DEFAULT 'semanal'",
        "ALTER TABLE users ADD COLUMN informe_pdf_dia INTEGER DEFAULT 1",
        "CREATE TABLE IF NOT EXISTS ssl_checks (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), dominio VARCHAR(255) NOT NULL, valido BOOLEAN, expira TIMESTAMP, dias_restantes INTEGER DEFAULT 0, emitido_por VARCHAR(300), sujeto VARCHAR(300), error VARCHAR(500), checked_at TIMESTAMP DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS uptime_checks (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), dominio VARCHAR(255) NOT NULL, up BOOLEAN NOT NULL DEFAULT TRUE, status_code INTEGER, response_ms INTEGER, checked_at TIMESTAMP DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), tipo VARCHAR(50) NOT NULL, titulo VARCHAR(300) NOT NULL, mensaje TEXT, leida BOOLEAN NOT NULL DEFAULT FALSE, url VARCHAR(500), created_at TIMESTAMP DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS dns_records (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), dominio VARCHAR(255) NOT NULL, tipo VARCHAR(10) NOT NULL, valor TEXT NOT NULL, primera_vez TIMESTAMP DEFAULT NOW(), ultima_vez TIMESTAMP DEFAULT NOW(), activo BOOLEAN NOT NULL DEFAULT TRUE)",
        "CREATE TABLE IF NOT EXISTS tech_detections (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), dominio VARCHAR(255) NOT NULL, tecnologias TEXT, headers_raw TEXT, detected_at TIMESTAMP DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS ip_reputations (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), dominio VARCHAR(255) NOT NULL, ip VARCHAR(45) NOT NULL, limpio BOOLEAN NOT NULL DEFAULT TRUE, listas_negras TEXT, checked_at TIMESTAMP DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS audit_logs (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), evento VARCHAR(100) NOT NULL, ip VARCHAR(45), user_agent VARCHAR(500), detalles TEXT, created_at TIMESTAMP DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS invoices (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), stripe_invoice_id VARCHAR(100), numero VARCHAR(50) NOT NULL, concepto VARCHAR(255) NOT NULL, importe FLOAT NOT NULL, moneda VARCHAR(10) DEFAULT 'EUR', estado VARCHAR(20) DEFAULT 'pagada', periodo_desde TIMESTAMP, periodo_hasta TIMESTAMP, created_at TIMESTAMP DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS processed_webhooks (id SERIAL PRIMARY KEY, event_id VARCHAR(120) UNIQUE NOT NULL, event_type VARCHAR(80), created_at TIMESTAMP DEFAULT NOW())",
        "CREATE TABLE IF NOT EXISTS anonymous_scans (id SERIAL PRIMARY KEY, dominio VARCHAR(255) NOT NULL, riesgo INTEGER DEFAULT 0, label VARCHAR(20), ip_hash VARCHAR(16), referer VARCHAR(255), user_agent VARCHAR(100), es_logged BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())",
        "CREATE INDEX IF NOT EXISTS idx_anon_scans_created ON anonymous_scans(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_anon_scans_dominio ON anonymous_scans(dominio)",
        "CREATE INDEX IF NOT EXISTS idx_processed_webhooks_event_id ON processed_webhooks(event_id)",
        # ── Actividad de usuarios (last_login + login_count + last_scan_at) ──
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0 NOT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP",
        # ── Tracking de logins (éxitos y fallos) ──
        "CREATE TABLE IF NOT EXISTS login_attempts (id SERIAL PRIMARY KEY, email VARCHAR(120) NOT NULL, ip VARCHAR(45), user_agent VARCHAR(255), exito BOOLEAN DEFAULT FALSE NOT NULL, razon VARCHAR(50), created_at TIMESTAMP DEFAULT NOW())",
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email)",
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip)",
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_exito ON login_attempts(exito)",
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_created ON login_attempts(created_at)",
    ]:
        try:
            db.session.execute(text(col_sql))
            db.session.commit()
        except Exception:
            db.session.rollback()

# ─── Bootstrap de blog SEO (idempotente — solo crea si no existe el slug) ───
_BLOG_SEEDS = [
    {
        "slug": "auditoria-seguridad-pymes-espana-guia-2026",
        "titulo": "Auditoría de seguridad gratis para PYMEs en España: guía completa 2026",
        "excerpt": "Cómo hacer una auditoría de seguridad básica de tu empresa sin contratar consultores: pasos, herramientas y normativa (RGPD, ENS, ISO 27001).",
        "tags": "seguridad,pyme,RGPD,ENS,auditoria,2026",
        "contenido": """
<h2>¿Por qué tu PYME necesita una auditoría de seguridad?</h2>
<p>El 43&nbsp;% de los ciberataques en España afectan a pequeñas y medianas empresas, según el INCIBE. La razón es simple: las PYMEs suelen tener menos defensas que las corporaciones grandes, pero los datos que manejan (clientes, facturas, nóminas) son igual de valiosos para los atacantes.</p>
<p>Una auditoría de seguridad básica te permite identificar los puntos débiles antes de que alguien los explote. Y, lejos de lo que piensa la mayoría, no necesitas un equipo de hackers ni miles de euros en consultores: con las herramientas adecuadas y un par de horas a la semana puedes cubrir lo esencial.</p>

<h2>Qué cubre una auditoría de seguridad básica</h2>
<ul>
  <li><strong>Superficie de exposición externa:</strong> qué servicios y puertos están abiertos en tu dominio o IP pública.</li>
  <li><strong>Configuración de DNS y email:</strong> registros SPF, DKIM y DMARC para evitar suplantaciones.</li>
  <li><strong>Cabeceras HTTP:</strong> que tu web tenga HTTPS forzado, HSTS, CSP, X-Frame-Options.</li>
  <li><strong>Filtraciones de datos:</strong> si los emails corporativos aparecen en brechas conocidas (HaveIBeenPwned).</li>
  <li><strong>Certificados SSL/TLS:</strong> versión TLS, fecha de expiración, emisor.</li>
  <li><strong>Subdominios olvidados:</strong> entornos de desarrollo, staging, paneles internos accesibles desde fuera.</li>
</ul>

<h2>Marcos normativos que aplican a tu PYME en España</h2>
<p>Aunque seas una empresa pequeña, hay tres normativas que casi siempre aplican:</p>
<ol>
  <li><strong>RGPD + LOPDGDD:</strong> obligatorio si manejas datos personales de clientes o empleados. Requiere medidas técnicas y organizativas, registro de actividades, y notificación de brechas en 72&nbsp;h.</li>
  <li><strong>ENS (Esquema Nacional de Seguridad):</strong> si trabajas con la Administración Pública española, aunque sea como subcontrata.</li>
  <li><strong>NIS2:</strong> si eres proveedor de un sector crítico (salud, energía, logística), aunque seas pequeño.</li>
</ol>

<h2>Cómo hacer la auditoría tú mismo</h2>
<p>El proceso simplificado:</p>
<ol>
  <li>Lista todos tus dominios, IPs públicas y servicios expuestos.</li>
  <li>Pasa cada uno por un escáner como <a href="/">ReconBase</a> o <code>nmap</code> + <code>testssl.sh</code>.</li>
  <li>Comprueba SPF/DMARC en <a href="/comprobar-dmarc-spf">esta herramienta gratuita</a>.</li>
  <li>Comprueba si tus emails están en brechas en <a href="https://haveibeenpwned.com" target="_blank" rel="noopener">HaveIBeenPwned</a>.</li>
  <li>Documenta los hallazgos y prioriza por riesgo (CVSS, criticidad del activo).</li>
  <li>Aplica los fixes y reescanea.</li>
</ol>

<h2>Cuándo contratar un profesional</h2>
<p>La auditoría DIY te cubre el 80&nbsp;% del riesgo común. Pero si manejas datos sensibles (sanitarios, financieros, biométricos) o ya has sufrido un incidente, contrata un pentester certificado. En España hay buenos profesionales por 2.000–5.000&nbsp;€ por proyecto.</p>

<h2>Conclusión</h2>
<p>La seguridad de tu empresa no es opcional, pero tampoco tiene por qué ser cara. <a href="/">Empieza con una auditoría gratuita</a> de tu dominio en 2&nbsp;minutos y descubre qué tienes expuesto. Si los resultados te asustan, hablamos.</p>
""".strip()
    },
    {
        "slug": "configurar-spf-dkim-dmarc-paso-a-paso",
        "titulo": "Cómo configurar SPF, DKIM y DMARC paso a paso (ejemplos para Gmail, Office 365 y servidor propio)",
        "excerpt": "Guía práctica para configurar SPF, DKIM y DMARC y evitar que suplanten tu dominio en correos. Ejemplos copy-paste para Gmail, Microsoft 365 y servidores propios.",
        "tags": "email,SPF,DMARC,DKIM,seguridad,phishing",
        "contenido": """
<h2>El problema: cualquiera puede enviar emails como si fuera tú</h2>
<p>Por defecto, el protocolo SMTP no verifica el remitente. Eso significa que un atacante puede enviar un correo aparentando venir de <code>jefe@tuempresa.es</code> aunque no tenga acceso a tu dominio. Es la base del 90&nbsp;% del phishing dirigido a empresas (Business Email Compromise).</p>
<p>SPF, DKIM y DMARC son tres registros DNS que, juntos, cierran este agujero. Configurarlos toma ~30&nbsp;minutos y reduce drásticamente las suplantaciones.</p>

<h2>1. SPF — Sender Policy Framework</h2>
<p>SPF declara qué servidores tienen permiso para enviar emails con tu dominio. Es un registro TXT en tu DNS.</p>
<p><strong>Ejemplo para Google Workspace + Resend:</strong></p>
<pre><code>v=spf1 include:_spf.google.com include:_spf.resend.com ~all</code></pre>
<p><strong>Ejemplo para Microsoft 365:</strong></p>
<pre><code>v=spf1 include:spf.protection.outlook.com ~all</code></pre>
<p><strong>Para servidor propio (con IP fija 1.2.3.4):</strong></p>
<pre><code>v=spf1 ip4:1.2.3.4 ~all</code></pre>
<p>El sufijo <code>~all</code> significa "softfail": si el origen no está autorizado, márcalo como sospechoso pero no lo rechaces. Una vez verificado que todo funciona, cámbialo a <code>-all</code> (rechazo estricto).</p>

<h2>2. DKIM — DomainKeys Identified Mail</h2>
<p>DKIM firma criptográficamente cada email saliente con una clave privada que solo tú tienes. El servidor receptor verifica la firma usando la clave pública publicada en tu DNS.</p>
<p><strong>Cómo activarlo en Google Workspace:</strong></p>
<ol>
  <li>Admin Console → Apps → Google Workspace → Gmail → Authenticate email.</li>
  <li>Click "Generate new record" → te da un valor TXT para <code>google._domainkey.tudominio.es</code>.</li>
  <li>Crea ese registro TXT en Cloudflare/tu DNS.</li>
  <li>Espera a que propague (~30&nbsp;min) y vuelve a Google → "Start authentication".</li>
</ol>
<p><strong>En Microsoft 365:</strong> Microsoft Defender → Email & collaboration → Policies → DKIM → Selecciona dominio → Enable.</p>

<h2>3. DMARC — Domain-based Message Authentication</h2>
<p>DMARC le dice a los servidores receptores qué hacer si SPF y DKIM fallan, y dónde enviarte los reportes.</p>
<p><strong>Empieza en modo monitor (sin rechazar nada):</strong></p>
<pre><code>v=DMARC1; p=none; rua=mailto:dmarc@tudominio.es; pct=100; aspf=r; adkim=r</code></pre>
<p>Crea un TXT en <code>_dmarc.tudominio.es</code> con ese contenido.</p>
<p>Después de 2 semanas analizando los reportes <code>rua</code>, sube la severidad:</p>
<pre><code>v=DMARC1; p=quarantine; rua=mailto:dmarc@tudominio.es; pct=50</code></pre>
<p>Y al cabo de otro mes, máxima severidad:</p>
<pre><code>v=DMARC1; p=reject; rua=mailto:dmarc@tudominio.es</code></pre>

<h2>4. Verifica que está bien configurado</h2>
<p>Usa <a href="/comprobar-dmarc-spf">nuestra herramienta gratuita</a> para comprobar tu dominio en 5 segundos. También sirven herramientas como MXToolbox o el "Check MX" de Google.</p>

<h2>Errores comunes</h2>
<ul>
  <li><strong>Múltiples SPF records:</strong> solo puede haber UNO por dominio. Si tienes varios, fusiónalos.</li>
  <li><strong>SPF sobrepasa 10 lookups:</strong> el límite del protocolo. Reduce <code>include:</code> innecesarios.</li>
  <li><strong>DKIM sin propagar:</strong> espera 30&nbsp;min – 24&nbsp;h tras crear el registro.</li>
  <li><strong>DMARC reject directo:</strong> si pones <code>p=reject</code> sin pasar por <code>p=none</code>, romperás emails legítimos.</li>
</ul>

<h2>Conclusión</h2>
<p>Configurar SPF, DKIM y DMARC es la mejor inversión de seguridad por hora invertida que puede hacer una PYME. <a href="/comprobar-dmarc-spf">Comprueba tu dominio gratis aquí</a> y arregla lo que falte hoy mismo.</p>
""".strip()
    },
    {
        "slug": "auditoria-wordpress-12-checks-2026",
        "titulo": "Auditoría WordPress: 12 checks de seguridad que tu web debería pasar (guía 2026)",
        "excerpt": "El 43% de los sitios web del mundo usa WordPress, y por eso es el CMS más atacado. Te enseño los 12 checks esenciales que toda web WordPress debería pasar — con ejemplos y herramientas gratuitas para validarlos.",
        "tags": "wordpress,seguridad,auditoria,plugins,cve",
        "contenido": """
<h2>Por qué WordPress es el objetivo número 1</h2>
<p>WordPress mueve el <strong>43&nbsp;% de internet</strong> según W3Techs. Eso lo convierte en el objetivo más rentable para atacantes: con un solo exploit pueden vulnerar miles de webs. En 2024 se reportaron más de <strong>5.000 vulnerabilidades conocidas</strong> en plugins de WordPress (datos de WPScan).</p>
<p>Y la mayoría son <strong>fáciles de explotar</strong>: solo necesitan que tu admin no haya actualizado un plugin en 3 meses. Por eso los pentesters profesionales empiezan SIEMPRE por WordPress cuando auditan una pyme.</p>

<h2>Los 12 checks que toda auditoría WordPress debería incluir</h2>

<h3>1. Versión de WordPress core actualizada</h3>
<p>Comprueba en <code>/readme.html</code> o el meta generator. Si estás más de <strong>una versión menor por detrás</strong> (ej. tienes 6.5 y existe 6.7), actualiza ya. Cada release corrige vulnerabilidades.</p>

<h3>2. Plugins instalados al día</h3>
<p>Ve a <strong>Plugins → Plugins instalados</strong>. Cualquier plugin con "actualización disponible" es un riesgo. Si ves plugins con label "no probado con tu versión de WordPress" — más alarma todavía.</p>

<h3>3. Plugins desactivados (¡borrar!)</h3>
<p>Un plugin <strong>desactivado pero instalado</strong> sigue siendo accesible vía URL directa y puede ejecutarse. Bórralos siempre.</p>

<h3>4. xmlrpc.php deshabilitado</h3>
<p>Es un protocolo legacy que se usa principalmente para amplificar ataques DDoS y para hacer brute-force masivo sin captcha. Si no usas Jetpack, deshabilítalo con esta regla en tu <code>.htaccess</code>:</p>
<pre><code>&lt;Files xmlrpc.php&gt;
  Order Allow,Deny
  Deny from all
&lt;/Files&gt;</code></pre>

<h3>5. Enumeración de usuarios bloqueada</h3>
<p>Prueba en tu navegador: <code>https://tudominio.com/wp-json/wp/v2/users</code>. ¿Te lista los usuarios admin? Si sí, cualquiera tiene el primer paso para un ataque de brute-force con tu username real. Instala el plugin <strong>"Stop User Enumeration"</strong> o bloquea esa ruta vía nginx/Apache.</p>

<h3>6. Login con 2FA</h3>
<p>Plugin <strong>"Two Factor"</strong> (oficial WP) o Wordfence Login Security. Sin 2FA, una contraseña filtrada = web hackeada.</p>

<h3>7. Límite de intentos de login</h3>
<p>WordPress por defecto deja intentar contraseñas <em>infinitamente</em>. Plugin <strong>"Limit Login Attempts Reloaded"</strong> bloquea IPs tras 3-5 fallos.</p>

<h3>8. Archivos backup expuestos</h3>
<p>Comprueba estas URLs en tu navegador. Si te devuelven contenido, BORRA esos archivos:</p>
<ul>
  <li><code>/wp-config.php.bak</code></li>
  <li><code>/wp-config.php~</code></li>
  <li><code>/wp-content/debug.log</code></li>
  <li><code>/wp-admin/install.php</code> (debe decir "ya instalado")</li>
</ul>

<h3>9. HTTPS forzado</h3>
<p>WordPress por defecto NO redirige HTTP → HTTPS. Añade en <code>wp-config.php</code>:</p>
<pre><code>define('FORCE_SSL_ADMIN', true);</code></pre>
<p>Y un redirect 301 a nivel servidor.</p>

<h3>10. Tema y plugins de fuentes confiables</h3>
<p>NO instales temas/plugins "premium gratis" de webs piratas. Vienen <strong>siempre con malware</strong>. Usa repositorio oficial de WordPress, ThemeForest, CodeCanyon o webs reconocidas (Yoast, WP Rocket, etc.).</p>

<h3>11. Backups automáticos</h3>
<p>Plugin <strong>UpdraftPlus</strong> (gratis) → configura backup semanal a Google Drive/Dropbox. Si te hackean, restauras en 5&nbsp;min en lugar de perder todo.</p>

<h3>12. Monitor de seguridad continua</h3>
<p><strong>Wordfence</strong> (gratis) o <strong>Sucuri</strong> escanean tu WordPress cada noche en busca de archivos modificados/malware. Es la red de seguridad final.</p>

<h2>Cómo automatizar esta auditoría</h2>
<p>Hacer estos 12 checks manualmente tarda 1-2 horas. <a href="/">ReconBase</a> los pasa automáticamente en 2 minutos analizando solo tu dominio — sin acceso a tu WordPress. Detecta versión, plugins visibles, archivos sensibles expuestos y mucho más. <strong>Gratis, sin tarjeta</strong>.</p>

<h2>Conclusión</h2>
<p>WordPress es seguro <em>cuando se mantiene</em>. La mayoría de hackeos a pymes españolas vienen de un plugin desactualizado durante 3 meses, no de un atacante sofisticado. Estos 12 checks cubren el 90&nbsp;% de los vectores de ataque comunes. <a href="/">Analiza tu WordPress aquí</a> y arregla lo que detecte hoy.</p>
""".strip()
    },
    {
        "slug": "ataques-bec-business-email-compromise-pymes-espana",
        "titulo": "Ataques BEC (Business Email Compromise): la estafa silenciosa que se lleva miles de euros de pymes españolas",
        "excerpt": "BEC es el tipo de ataque que más dinero roba a pymes en España según el INCIBE. No usa malware ni hackeo técnico: solo un email bien escrito. Te enseño cómo funciona, casos reales y cómo blindarte en 30 minutos.",
        "tags": "BEC,phishing,suplantacion,SPF,DMARC,pyme",
        "contenido": """
<h2>¿Qué es un ataque BEC y por qué deberías preocuparte?</h2>
<p><strong>BEC = Business Email Compromise</strong>. El atacante envía un email haciéndose pasar por una persona de confianza (el CEO, un proveedor, el banco) y consigue que alguien de tu empresa <strong>transfiera dinero</strong> a una cuenta controlada por él.</p>
<p>No usa malware. No usa exploits. No necesita "hackear" nada. Solo necesita:</p>
<ul>
  <li>Un email convincente</li>
  <li>Que tu dominio <strong>no tenga SPF/DMARC</strong> bien configurados</li>
</ul>
<p>Según el <a href="https://www.incibe.es" target="_blank" rel="noopener">INCIBE</a>, BEC es el tipo de ciberataque que <strong>más dinero roba</strong> en España, por encima del ransomware. Las pymes son su objetivo favorito porque no tienen procesos formales de verificación de transferencias.</p>

<h2>3 casos reales (sucedidos a pymes españolas)</h2>

<h3>Caso 1: La asesoría de Madrid (12.500&nbsp;€)</h3>
<p>Una asesoría fiscal recibió un email "del gerente" pidiendo a la administrativa que transfiriera 12.500&nbsp;€ a un nuevo proveedor por una "urgencia". El email venía de <code>gerente@asesoria-X.com</code> — exactamente el dominio real. La administrativa lo hizo. El gerente nunca había mandado ese email.</p>
<p><strong>Causa raíz</strong>: el dominio no tenía DMARC configurado. Cualquier atacante podía enviar emails como <code>gerente@asesoria-X.com</code> desde un servidor externo y pasar el filtro.</p>

<h3>Caso 2: La empresa de logística (40.000&nbsp;€)</h3>
<p>Una pyme de logística recibió un email "de su banco" pidiendo confirmar una operación. La factura adjunta venía de un dominio MUY parecido al banco real. La pyme tenía las credenciales bancarias del director financiero comprometidas (filtración antigua, no cambió la contraseña). El atacante hizo la transferencia desde la web del banco — para el banco, era una operación legítima.</p>
<p><strong>Causa raíz</strong>: credenciales filtradas + sin 2FA en banca online.</p>

<h3>Caso 3: La clínica dental (8.700&nbsp;€)</h3>
<p>Un email "del proveedor de material" pedía actualizar el IBAN de cobro porque "había cambiado de banco". La gestoría actualizó el IBAN en su programa de gestión sin verificar telefónicamente. La siguiente transferencia (8.700&nbsp;€) fue a la cuenta del atacante.</p>
<p><strong>Causa raíz</strong>: cero proceso de verificación de cambios de IBAN.</p>

<h2>Cómo blindar tu pyme contra BEC (30 minutos)</h2>

<h3>1. Configura SPF, DKIM y DMARC (10 min)</h3>
<p>Es el bloqueo técnico número 1. Sin esto, cualquiera puede suplantar tu dominio. Tenemos una <a href="/blog/configurar-spf-dkim-dmarc-paso-a-paso">guía paso a paso</a> y una <a href="/comprobar-dmarc-spf">herramienta gratuita</a> para validar tu configuración.</p>

<h3>2. Política interna de "doble verificación" en transferencias (10 min)</h3>
<p>Establece por escrito y comunica al equipo: <strong>cualquier transferencia &gt;1.000&nbsp;€ o cambio de IBAN debe verificarse telefónicamente con un número conocido</strong> (no el que aparezca en el email). Esta política sola previene el 80&nbsp;% de los BEC.</p>

<h3>3. 2FA en todas las cuentas críticas (5 min)</h3>
<p>Banca online, email, ERP, CRM. Sin 2FA, una credencial filtrada = atacante dentro. Usa Google Authenticator o Authy.</p>

<h3>4. Filtros antiphishing en el email (5 min)</h3>
<p>Si usas Google Workspace o Microsoft 365, ambos tienen filtros automáticos avanzados — actívalos. Si usas un email "raro" (hosting compartido), pásate a un proveedor profesional.</p>

<h3>5. Monitoriza filtraciones de tus emails corporativos</h3>
<p>Comprueba periódicamente si tus emails de empresa aparecen en filtraciones conocidas (HaveIBeenPwned). Con cuenta gratuita en <a href="/">ReconBase</a> te monitorizamos esto automáticamente.</p>

<h2>Señales de alerta para detectar un BEC</h2>
<ul>
  <li>⚠️ "Necesito que hagas esto ahora, estoy en una reunión y no puedo hablar" → urgencia artificial</li>
  <li>⚠️ "No me respondas a este mail, contactaré yo" → bloquea la verificación</li>
  <li>⚠️ El IBAN/cuenta de cobro cambia de repente, sin explicación</li>
  <li>⚠️ El remitente es <code>jefe@empresa-x.com</code> en lugar del habitual <code>jefe@empresa.com</code> (typosquatting)</li>
  <li>⚠️ Email enviado fuera del horario laboral o desde un sitio raro</li>
</ul>

<h2>Conclusión</h2>
<p>BEC es el ataque <em>más rentable</em> contra pymes españolas porque no requiere habilidad técnica del atacante — solo aprovecha procesos descuidados de la empresa. Las medidas son baratas (DMARC, 2FA, política de doble verificación) y reducen un 90&nbsp;% el riesgo. <a href="/">Empieza por analizar gratis tu dominio</a> y ver si tu empresa ya está expuesta.</p>
""".strip()
    },
    {
        "slug": "ransomware-pymes-espana-como-prevenirlo-2026",
        "titulo": "Ransomware en PYMEs españolas: cómo funciona, cuánto cuesta y cómo prevenirlo en 2026",
        "excerpt": "El ransomware paralizó a más de 1.500 pymes españolas en 2024. Te explicamos cómo entra, qué hace, cuánto cuesta el rescate (spoiler: pagar no sirve) y los 7 pasos concretos para no ser la próxima víctima.",
        "tags": "ransomware,pyme,backup,seguridad,INCIBE,2026",
        "contenido": """
<h2>¿Qué es el ransomware y por qué las pymes son el objetivo favorito?</h2>
<p>El <strong>ransomware</strong> es un tipo de malware que cifra todos los archivos de tu empresa y exige un rescate (ransom) en criptomonedas para devolverte el acceso. En 2024, el INCIBE gestionó más de 1.500 incidentes de ransomware en empresas españolas, con pérdidas medias de <strong>45.000&nbsp;€ por empresa</strong> entre rescate, tiempo de parada y recuperación.</p>
<p>Las pymes son el objetivo favorito porque:</p>
<ul>
  <li>No tienen backups automatizados y verificados.</li>
  <li>Usan software desactualizado (Windows 7, Office 2010, etc.).</li>
  <li>Un solo empleado con malos hábitos puede comprometer toda la red.</li>
  <li>Pagan con más frecuencia que las grandes empresas porque no tienen alternativas.</li>
</ul>

<h2>Cómo entra el ransomware en tu empresa</h2>
<p>En el 90&nbsp;% de los casos, uno de estos tres vectores:</p>
<ol>
  <li><strong>Phishing por email:</strong> un empleado abre un adjunto (PDF, Word, ZIP) o hace clic en un enlace. El malware se instala silenciosamente y se propaga por la red.</li>
  <li><strong>RDP expuesto a internet:</strong> si tienes el puerto 3389 (Escritorio Remoto) abierto con contraseñas débiles, los atacantes lo encuentran con herramientas automáticas y entran por fuerza bruta.</li>
  <li><strong>Software sin parchear:</strong> vulnerabilidades conocidas en VPNs, servidores web o sistemas operativos sin actualizar. EternalBlue (WannaCry) sigue activo 7 años después.</li>
</ol>

<h2>¿Pagar el rescate funciona?</h2>
<p>El <strong>40&nbsp;% de las empresas que pagan no recuperan todos sus archivos</strong> (Sophos, 2024). Además:</p>
<ul>
  <li>Pagas en criptomonedas no rastreables: no hay garantías.</li>
  <li>Apareces en las listas de "pagadores" y recibirás más ataques.</li>
  <li>En España puede ser ilegal si el grupo atacante está sancionado por la UE.</li>
  <li>El tiempo medio de recuperación tras pagar es de 16&nbsp;días igualmente.</li>
</ul>
<p><strong>Conclusión: la única defensa real es no llegar a necesitar pagar.</strong></p>

<h2>Los 7 pasos para proteger tu pyme del ransomware</h2>

<h3>1. Backups 3-2-1 verificados (el más importante)</h3>
<p>La regla <strong>3-2-1</strong>: 3 copias de los datos, en 2 medios distintos, con 1 copia offline (desconectada de internet). Un ransomware que llega a tu red cifrará también los discos conectados — la copia offline es la que te salva.</p>
<p>Además, <strong>verifica los backups cada mes</strong>: restaura un fichero aleatorio para confirmar que el backup funciona.</p>

<h3>2. Cierra el puerto RDP o ponlo detrás de VPN</h3>
<p>Si necesitas acceso remoto, usa una VPN con 2FA. El RDP directo a internet es una invitación abierta. Con <a href="/">ReconBase</a> puedes comprobar si el puerto 3389 está expuesto en tu dominio.</p>

<h3>3. Actualiza todo, siempre</h3>
<p>Windows Update, Office, Adobe, Java, el firmware del router. El 60&nbsp;% de los ransomwares explotan vulnerabilidades con parche disponible que nadie instaló.</p>

<h3>4. Formación anti-phishing para el equipo</h3>
<p>Un empleado formado es mejor que cualquier antivirus. Simula ataques de phishing con herramientas como <strong>GoPhish</strong> (gratuito) para medir y mejorar.</p>

<h3>5. Segmentación de red</h3>
<p>Si el ordenador del recepcionista se infecta, no debería poder alcanzar el servidor contable. VLANs básicas evitan la propagación lateral.</p>

<h3>6. Principio de mínimo privilegio</h3>
<p>Nadie debería tener permisos de administrador para el trabajo del día a día. Si el malware corre como usuario sin privilegios, su impacto es mucho menor.</p>

<h3>7. Plan de respuesta a incidentes escrito</h3>
<p>Decide HOY: si mañana te cifran los servidores, ¿quién llama a quién? ¿Cuándo involucras al INCIBE (017)? ¿Tienes el contacto de tu proveedor de IT? Tener el plan escrito antes del incidente vale más que cualquier herramienta.</p>

<h2>Si ya estás infectado: pasos inmediatos</h2>
<ol>
  <li><strong>Desconecta</strong> los equipos afectados de la red (sin apagarlos).</li>
  <li><strong>Llama al INCIBE:</strong> línea gratuita <strong>017</strong>, disponible 24/7 para empresas.</li>
  <li><strong>No pagues</strong> sin consultar antes con un experto.</li>
  <li><strong>Denuncia</strong> a la Guardia Civil (GDT) o Policía Nacional (UDEF) — en algunos casos recuperan fondos.</li>
  <li>Restaura desde el backup offline verificado.</li>
</ol>

<h2>Conclusión</h2>
<p>El ransomware no es una amenaza futura — está pasando ahora mismo en pymes españolas de todos los sectores. Las defensas básicas (backups, RDP cerrado, parches) cuestan poco y son la diferencia entre volver a funcionar en horas o en semanas. <a href="/">Analiza gratis tu exposición aquí</a> — si tienes el puerto RDP abierto, lo sabrás en 2 minutos.</p>
""".strip()
    },
    {
        "slug": "gestion-contrasenas-empresa-politica-gestores-2fa",
        "titulo": "Gestión de contraseñas en tu empresa: política, gestores y 2FA (guía práctica 2026)",
        "excerpt": "El 81% de las brechas de seguridad en empresas involucran contraseñas débiles o robadas. Te damos la política de contraseñas que deberías tener, los mejores gestores para equipos y cómo implantar 2FA sin que el equipo proteste.",
        "tags": "contraseñas,2FA,gestion,seguridad,pyme,passwords",
        "contenido": """
<h2>El problema con las contraseñas en las pymes</h2>
<p>Según el informe <em>Data Breach Investigations Report</em> de Verizon, el <strong>81&nbsp;% de las brechas de seguridad en empresas</strong> involucran contraseñas débiles, reutilizadas o robadas. Y en las pymes la situación es peor: la misma contraseña en el email, el ERP y el banco; post-its con credenciales pegados al monitor; contraseñas compartidas por WhatsApp.</p>
<p>La buena noticia: esto tiene solución sin necesitar conocimientos técnicos, con herramientas gratuitas o de bajo coste.</p>

<h2>La política de contraseñas que deberías tener</h2>
<p>Olvida las reglas antiguas de "mayúscula + número + símbolo cada 90 días". El NIST (el estándar de facto global) cambió sus recomendaciones en 2024:</p>
<ul>
  <li><strong>Longitud mínima: 12 caracteres</strong> (no 8). La longitud es más importante que la complejidad.</li>
  <li><strong>Sin caducidad periódica obligatoria</strong> salvo que haya evidencia de compromiso. Cambiar contraseñas cada 90 días genera contraseñas peores (<code>Empresa2024!</code> → <code>Empresa2025!</code>).</li>
  <li><strong>No reutilizar contraseñas</strong> entre servicios. Si filtran LinkedIn y usas la misma en el email de empresa, tienes un problema.</li>
  <li><strong>Verificar contra listas de contraseñas filtradas</strong>: servicios como HaveIBeenPwned tienen APIs para esto.</li>
</ul>
<p>Escribe esta política en un documento de una página y comunícala al equipo. No necesita ser más complicada.</p>

<h2>Gestores de contraseñas para equipos: comparativa</h2>
<p>Un gestor de contraseñas genera y almacena contraseñas únicas por servicio. El empleado solo memoriza una contraseña maestra.</p>

<h3>Bitwarden (recomendado para pymes)</h3>
<ul>
  <li>Plan Teams: <strong>4&nbsp;€/usuario/mes</strong>. Plan gratuito individual ilimitado.</li>
  <li>Open source, auditorías de seguridad públicas.</li>
  <li>Compartir contraseñas entre departamentos con permisos granulares.</li>
  <li>Extensiones para Chrome, Firefox, Safari, app móvil.</li>
</ul>

<h3>1Password Business</h3>
<ul>
  <li><strong>7,99&nbsp;€/usuario/mes</strong>. Más caro, mejor UX.</li>
  <li>Travel Mode (oculta bóvedas sensibles al cruzar fronteras).</li>
  <li>Integración con SSO corporativo (Okta, Azure AD).</li>
</ul>

<h3>KeePass (gratuito, on-premise)</h3>
<ul>
  <li>Gratuito y open source. La base de datos se guarda en tu servidor.</li>
  <li>Más complejo de gestionar. Adecuado si tienes sysadmin interno.</li>
</ul>

<h2>Autenticación en dos pasos (2FA): cómo implantarla sin fricciones</h2>
<p>El 2FA añade una segunda verificación (código de 6 dígitos que cambia cada 30 segundos) después de la contraseña. Incluso si la contraseña está filtrada, el atacante no puede entrar.</p>

<h3>¿Qué servicios deben tener 2FA sí o sí?</h3>
<ol>
  <li>Email corporativo (Gmail Workspace, Microsoft 365)</li>
  <li>Banca online</li>
  <li>ERP / CRM</li>
  <li>Panel de hosting y DNS (si alguien entra aquí, controla toda tu web)</li>
  <li>Gestor de contraseñas</li>
  <li>Acceso remoto / VPN</li>
</ol>

<h3>Tipos de 2FA ordenados de mejor a peor</h3>
<ol>
  <li><strong>Llaves físicas (YubiKey):</strong> lo más seguro. Resistente a phishing. Coste ~50&nbsp;€/unidad.</li>
  <li><strong>App TOTP (Google Authenticator, Authy, Aegis):</strong> muy seguro, gratuito. Recomendado para la mayoría.</li>
  <li><strong>Push notification (Duo, Microsoft Authenticator):</strong> cómodo, pero vulnerable a "MFA fatigue" (el atacante envía 50 notificaciones hasta que el usuario acepta una).</li>
  <li><strong>SMS:</strong> funciona pero es el más débil (SIM swapping). Mejor que nada, pero evitar si hay alternativa.</li>
</ol>

<h3>Cómo convencer al equipo</h3>
<p>La resistencia habitual: "es un paso más, me ralentiza". La respuesta: Authy y Google Authenticator toman <strong>3 segundos por login</strong>. El tiempo perdido en un año es inferior al tiempo perdido en un solo incidente de seguridad.</p>
<p>Implántalo gradualmente: primero los accesos más críticos (email, banca), luego el resto. Da una semana de margen para que el equipo configure las apps.</p>

<h2>Checklist rápido</h2>
<ul>
  <li>☐ Política de contraseñas documentada y comunicada</li>
  <li>☐ Gestor de contraseñas implantado para todo el equipo</li>
  <li>☐ 2FA activado en email, banca y ERP</li>
  <li>☐ Emails corporativos comprobados en HaveIBeenPwned</li>
  <li>☐ Contraseñas de router/WiFi cambiadas (no dejar las de fábrica)</li>
</ul>

<h2>Conclusión</h2>
<p>Las contraseñas débiles son el vector de entrada más común en ciberataques a pymes — y el más fácil de cerrar. Con Bitwarden gratuito y Google Authenticator ya cubres el 80&nbsp;% del riesgo. <a href="/">Comprueba gratis si los emails de tu empresa han aparecido en filtraciones</a> y empieza a actuar hoy.</p>
""".strip()
    },
    {
        "slug": "nis2-espana-empresas-obligadas-como-cumplir-2026",
        "titulo": "NIS2 en España: qué empresas están obligadas y cómo cumplir (guía práctica 2026)",
        "excerpt": "La directiva NIS2 ya es de obligado cumplimiento en España. Te explicamos qué empresas están dentro del ámbito, qué obligaciones reales tienen y cómo empezar a cumplir sin volverte loco.",
        "tags": "NIS2,normativa,ciberseguridad,pyme,RGPD,INCIBE,2026",
        "contenido": """
<h2>NIS2: la normativa que muchas pymes ignoran y les va a costar caro</h2>
<p>La Directiva (UE) 2022/2555, más conocida como <strong>NIS2</strong>, es la nueva normativa europea de ciberseguridad. Reemplaza a la antigua NIS y amplía MUCHO el número de empresas obligadas a cumplir. En España se transpuso mediante el Real Decreto-ley aprobado en 2025 y desde entonces es legalmente exigible.</p>
<p>El problema: <strong>el 70&nbsp;% de las pymes españolas afectadas no saben que están afectadas</strong>. Y los reguladores (INCIBE-CERT y CCN-CERT) ya pueden imponer multas de hasta <strong>10 millones de euros o el 2&nbsp;% de la facturación global</strong>, lo que sea mayor.</p>

<h2>¿Qué empresas están obligadas a cumplir NIS2?</h2>
<p>NIS2 distingue dos categorías:</p>

<h3>Entidades esenciales (las grandes)</h3>
<ul>
  <li>Empresas con <strong>más de 250 empleados</strong> o <strong>50 M€ de facturación</strong> que operen en sectores críticos.</li>
  <li>Sectores: energía, transporte, banca, salud, agua potable, infraestructuras digitales, administración pública.</li>
</ul>

<h3>Entidades importantes (donde caen MUCHAS pymes)</h3>
<ul>
  <li>Empresas con <strong>más de 50 empleados</strong> o <strong>10 M€ de facturación</strong> en sectores ampliados.</li>
  <li>Sectores: <strong>servicios postales y mensajería, gestión de residuos, química, alimentación, fabricación industrial, proveedores digitales (SaaS, marketplaces, redes sociales), investigación.</strong></li>
</ul>

<p>👉 Si eres un <strong>SaaS, una empresa de logística, una fábrica con más de 50 empleados o un proveedor de servicios digitales</strong>, lo más probable es que NIS2 te aplique aunque no te lo hayan dicho.</p>

<h2>Las 4 obligaciones reales que tienes que cumplir</h2>

<h3>1. Gestión de riesgos de ciberseguridad</h3>
<p>Tener una <strong>política de seguridad documentada</strong> que cubra: análisis de riesgos, política de control de accesos, gestión de incidentes, continuidad de negocio, cifrado, formación al personal y seguridad en la cadena de suministro.</p>
<p><em>En pyme:</em> un documento de 8-15 páginas firmado por dirección. No hace falta una novela.</p>

<h3>2. Notificación de incidentes en 24h</h3>
<p>Si sufres un incidente significativo (ransomware, exfiltración de datos, indisponibilidad de servicios), <strong>tienes 24h para notificar al INCIBE-CERT</strong>, 72h para un informe inicial y 1 mes para el informe final. Saltarte este plazo es lo que más multas está generando.</p>

<h3>3. Responsabilidad directa de la dirección</h3>
<p>NIS2 introduce una novedad importante: <strong>los administradores y directivos pueden ser personalmente responsables</strong> de las multas si no han aprobado e implementado las medidas. No vale con "es cosa de IT". El consejo / gerencia tiene que recibir formación en ciberseguridad y aprobar formalmente el plan.</p>

<h3>4. Auditorías y supervisión</h3>
<p>El regulador puede pedirte una <strong>auditoría externa de ciberseguridad</strong> en cualquier momento. Si no la tienes y no puedes demostrar tu cumplimiento, multa al canto.</p>

<h2>Cómo empezar a cumplir NIS2 sin volverte loco</h2>
<p>Plan de 90 días realista para una pyme de 50-200 empleados:</p>

<ol>
  <li><strong>Días 1-15 — Diagnóstico:</strong> haz un inventario de activos (servidores, SaaS, dominios, datos personales) y una <strong>auditoría externa de tu superficie de exposición</strong>. <a href="/">Con ReconBase tienes un análisis inicial gratis</a> que cubre puertos abiertos, certificados SSL, configuración DNS/email y filtraciones de credenciales — los hallazgos te valen como evidencia inicial de "due diligence".</li>
  <li><strong>Días 16-30 — Política de seguridad:</strong> redacta el documento marco con plantillas. INCIBE publica un kit gratis en su web para pymes.</li>
  <li><strong>Días 31-60 — Implementación técnica:</strong> 2FA en todo, gestor de contraseñas, copias de seguridad cifradas y offline, parches al día, formación obligatoria al personal.</li>
  <li><strong>Días 61-75 — Plan de respuesta a incidentes:</strong> protocolo de qué hacer si te atacan, con teléfonos del INCIBE-CERT (017) y de tu asesoría legal.</li>
  <li><strong>Días 76-90 — Aprobación formal:</strong> el plan se eleva a dirección, se firma en acta y se programa una revisión cada 6 meses.</li>
</ol>

<h2>Cuánto cuesta cumplir NIS2 en una pyme</h2>
<p>Rangos reales del mercado en España (2026):</p>
<ul>
  <li><strong>DIY con kit de INCIBE + herramientas gratuitas:</strong> 0&nbsp;€ + 80-120 horas de trabajo interno.</li>
  <li><strong>Consultoría externa para redacción de la política:</strong> 3.000-8.000 €.</li>
  <li><strong>Auditoría técnica externa anual:</strong> 5.000-15.000 € según tamaño.</li>
  <li><strong>SOC gestionado / monitorización 24/7:</strong> desde 1.500 €/mes (pyme).</li>
</ul>
<p>Es una inversión, pero <strong>las multas son de 5 a 6 cifras</strong>. Y los ataques que NIS2 quiere evitar cuestan, en media, <strong>105.000 €</strong> a una pyme española (datos del Observatorio del INCIBE 2025).</p>

<h2>Errores típicos que cometen las pymes con NIS2</h2>
<ul>
  <li>❌ Pensar que "como soy pequeño no me aplica". Si estás en un sector ampliado y pasas de 50 empleados, te aplica.</li>
  <li>❌ Comprar un seguro de ciberriesgo y pensar que ya estás cubierto. El seguro paga el daño, pero no te exime de las multas regulatorias.</li>
  <li>❌ Delegar todo al departamento de IT sin involucrar a dirección. NIS2 obliga a la dirección a aprobar y formarse.</li>
  <li>❌ No formar a empleados. El 80% de los incidentes empiezan por un click humano en un phishing.</li>
  <li>❌ Dejar la cadena de suministro fuera. Si tu proveedor de cloud / software cae, tu obligación de notificar sigue siendo tuya.</li>
</ul>

<h2>Conclusión</h2>
<p>NIS2 no es una recomendación: es ley vigente en España y los inspectores del INCIBE ya están actuando. Si tu pyme está en alguno de los sectores ampliados (SaaS, logística, fabricación, alimentación, gestión de residuos, química) y supera los 50 empleados, <strong>tienes que actuar ya</strong>.</p>
<p>Lo primero — y más barato — es saber qué tienes expuesto. <a href="/">Lanza una auditoría gratuita de tu dominio en 2 minutos</a> y empieza a documentar tu postura de seguridad. Es el primer paso de cualquier plan de cumplimiento serio.</p>
""".strip()
    },
    {
        "slug": "como-detectar-web-hackeada-7-senales-2026",
        "titulo": "Cómo detectar si tu web ha sido hackeada: 7 señales claras (guía 2026)",
        "excerpt": "Si sospechas que tu web está comprometida pero no sabes por dónde empezar, estos 7 indicadores te lo confirmarán en 10 minutos. Incluye comandos copy-paste y qué hacer si confirmas el ataque.",
        "tags": "hackeo,web,seguridad,wordpress,malware,SEO spam,2026",
        "contenido": """
<h2>Tu web va lenta, recibes emails raros y Google te ha avisado. ¿Estás hackeado?</h2>
<p>Muchas pymes descubren que su web está comprometida <strong>cuando ya es demasiado tarde</strong>: aparecen en la lista negra de Google, los clientes reciben emails fraudulentos en su nombre o el hosting les cierra la cuenta. La realidad es que la mayoría de ataques son detectables en una hora si sabes qué buscar.</p>
<p>Esta guía te da las <strong>7 señales más claras</strong> de que tu web ha sido hackeada, con los comandos exactos para verificarlas. Si ves alguna de ellas, actúa hoy.</p>

<h2>Señal 1: Google Search Console te ha enviado un aviso</h2>
<p>Es el indicador más fiable. Google escanea tu web constantemente y, si detecta malware, contenido pirateado o redirecciones sospechosas, te envía un email desde <code>noreply@google.com</code> con el asunto "Detectados problemas de seguridad" o "Hackeo de sitio web".</p>
<p><strong>Verificar ahora:</strong> entra en <a href="https://search.google.com/search-console" target="_blank" rel="noopener">Google Search Console</a> → menú "Seguridad y acciones manuales" → "Problemas de seguridad". Si pone "No hay problemas detectados" en verde, este punto está OK. Si hay aviso, lee el detalle y sigue las instrucciones.</p>

<h2>Señal 2: Páginas extrañas en los resultados de Google</h2>
<p>Una técnica muy común se llama <strong>SEO spam</strong>: el atacante inyecta cientos de páginas con contenido de farmacia online, casinos, o productos falsos. Estas páginas posicionan en Google bajo tu dominio.</p>
<p><strong>Verificar ahora:</strong> abre Google y busca:</p>
<pre><code>site:tudominio.com viagra OR casino OR cialis OR "rolex replica"</code></pre>
<p>Si te aparecen resultados con URLs raras tipo <code>tudominio.com/wp-content/uploads/2024/01/cheap-meds-here.html</code>, estás hackeado. Variantes para probar: cambia las palabras por idioma o producto que no vendas.</p>

<h2>Señal 3: Modificaciones recientes que tú no has hecho</h2>
<p>Si gestionas tu web por FTP/SSH, conéctate y mira qué archivos se han modificado en las últimas 48h:</p>
<pre><code>find /var/www/tudominio -type f -mtime -2 -ls</code></pre>
<p>Si ves archivos modificados en directorios como <code>wp-content/uploads/</code>, <code>wp-includes/</code> o <code>wp-admin/</code> y tú no has tocado nada esos días, hay 90&nbsp;% de probabilidad de que sea una backdoor.</p>

<h2>Señal 4: Usuarios admin que no creaste</h2>
<p>El primer movimiento de un atacante en WordPress es crearse un usuario administrador propio. Comprueba en <code>Usuarios → Todos los usuarios</code> en tu wp-admin. Cualquier nombre tipo <code>admin2</code>, <code>support</code>, <code>wpsystem</code>, <code>1qaz2wsx</code> o un email random con dominio raro es señal clara de compromiso.</p>
<p><strong>Bonus:</strong> nuestra <a href="/">auditoría gratuita</a> detecta si tu instalación de WordPress expone usuarios públicamente vía la API REST (<code>/wp-json/wp/v2/users</code>). Si es así, los atacantes ya tienen una lista priorizada de cuentas a atacar.</p>

<h2>Señal 5: Tráfico súbito en horas raras</h2>
<p>Si miras Google Analytics o tu panel de hosting y ves picos de tráfico desde países donde no operas (Rusia, China, Indonesia, Brasil) o a horas en las que no debería haber nadie (3 AM), es porque tu web está siendo usada como:</p>
<ul>
  <li><strong>Servidor de phishing</strong> alojando páginas falsas de bancos.</li>
  <li><strong>Proxy de spam</strong> enviando correos en masa.</li>
  <li><strong>Servidor de mando y control (C2)</strong> coordinando otros malware.</li>
</ul>
<p>En todos los casos: hostings serios cierran la cuenta en cuanto detectan el patrón.</p>

<h2>Señal 6: Tu web redirige a sitios extraños desde móvil pero no desde escritorio</h2>
<p>Ataque clásico llamado <strong>cloaking</strong>: el código malicioso detecta si entras desde Google + móvil y, solo en ese caso, te redirige a un sitio de spam. Desde tu PC en la oficina parece todo normal.</p>
<p><strong>Verificar ahora:</strong> abre Chrome → F12 → modo dispositivo móvil → entra a tu web desde una búsqueda de Google (no escribiéndola directamente). Si te redirige a algo raro, estás comprometido.</p>

<h2>Señal 7: El antivirus o el navegador bloquean tu web</h2>
<p>Si tus clientes te dicen <em>"me sale una pantalla roja al entrar"</em>, tu dominio ha entrado en alguna blocklist (Google Safe Browsing, Norton Safe Web, etc.). En este momento estás <strong>perdiendo el 70&nbsp;% del tráfico</strong> porque ningún navegador deja entrar.</p>
<p><strong>Verificar ahora:</strong> tu dominio en <a href="https://transparencyreport.google.com/safe-browsing/search" target="_blank" rel="noopener">Google Safe Browsing</a>. Si sale "No safe" o "Some pages are dangerous", tienes confirmación oficial.</p>

<h2>Comprobación en 2 minutos: la versión rápida</h2>
<p>Si quieres una comprobación rápida y profesional sin tocar nada, lanza un <a href="/">escaneo gratuito en ReconBase</a>. En 90 segundos te dice:</p>
<ul>
  <li>Si tu certificado SSL está caducado o mal configurado.</li>
  <li>Si tu WordPress tiene una versión vulnerable o plugins inseguros.</li>
  <li>Si la API REST está expuesta y filtra usuarios.</li>
  <li>Si tu dominio aparece en listas negras de spam.</li>
  <li>Si tu DNS permite suplantación por email.</li>
</ul>

<h2>Qué hacer si confirmas el hackeo</h2>
<p>Paso a paso, en este orden:</p>
<ol>
  <li><strong>NO borres nada todavía.</strong> Hacer una copia forense antes te permitirá entender cómo entraron.</li>
  <li><strong>Cambia todas las contraseñas</strong> desde un equipo limpio: hosting, wp-admin, FTP, base de datos, email asociado al dominio.</li>
  <li><strong>Restaura desde una copia de seguridad anterior al hackeo.</strong> Si no tienes backup, contrata un servicio de limpieza profesional (Sucuri, Wordfence, o un MSSP español como S2 Grupo).</li>
  <li><strong>Aplica todas las actualizaciones</strong>: WordPress core, todos los plugins, todos los themes. Borra los que no uses.</li>
  <li><strong>Solicita revisión en Google Search Console</strong> una vez limpia la web, para que te quiten de la lista negra.</li>
  <li><strong>Audita la causa raíz</strong>: ¿entraron por una contraseña filtrada? ¿por un plugin vulnerable? ¿por una contraseña FTP por defecto del hosting? Sin saber la causa, te volverán a hackear en semanas.</li>
  <li><strong>Notifica si es necesario.</strong> Si hubo exfiltración de datos personales, tienes 72h para notificar a la AEPD (RGPD). Si estás bajo NIS2, también al INCIBE-CERT en 24h.</li>
</ol>

<h2>Conclusión</h2>
<p>Detectar un hackeo a tiempo puede ahorrarte miles de euros en multas, recuperación y pérdida de reputación. Las 7 señales de esta guía las puedes comprobar tú mismo en menos de una hora. Y si quieres una segunda opinión profesional sin tocar tu web, <a href="/">lanza un escaneo gratuito en ReconBase</a> y consulta el informe.</p>
""".strip()
    },
    {
        "slug": "skimmers-digitales-prestashop-magecart-2026",
        "titulo": "Skimmers digitales en PrestaShop: qué son, cómo detectarlos y cómo limpiarlos (guía 2026)",
        "excerpt": "Los skimmers digitales (Magecart) son la amenaza número uno contra tiendas online en 2026. Te explico cómo funcionan, cómo detectarlos en tu PrestaShop y qué hacer si encuentras uno.",
        "tags": "prestashop,skimmer,magecart,ecommerce,seguridad,checkout,PCI-DSS,2026",
        "contenido": """
<h2>El robo silencioso que está vaciando tiendas PrestaShop en España</h2>
<p>En 2025, el CCN-CERT registró un <strong>aumento del 340%</strong> en incidentes de robo de datos de tarjeta en tiendas online españolas (vs 2024). El vector dominante: <strong>skimmers digitales</strong>, también conocidos como <em>Magecart</em>, <em>web skimmers</em> o <em>e-skimmers</em>. Y PrestaShop está entre los CMS más afectados.</p>
<p>Lo más peligroso es que <strong>no tienes ni idea de que estás afectado hasta semanas después</strong>. Tu tienda funciona normal, tus clientes pagan normal, tú vendes normal. Y mientras tanto, los datos de tarjeta de cada compra llegan al servidor de un atacante en Rusia, Ucrania o Vietnam.</p>

<h2>¿Qué es exactamente un skimmer digital?</h2>
<p>Un skimmer digital es <strong>código JavaScript malicioso</strong> que un atacante inyecta en la página de checkout de tu tienda. Cuando un cliente rellena el formulario de pago (número de tarjeta, fecha, CVV), el JavaScript captura esos datos antes de que se envíen a la pasarela legítima y los envía también al servidor del atacante.</p>
<p>Es la versión digital del skimmer físico de los cajeros: un dispositivo invisible que copia tu tarjeta mientras la usas con normalidad. La diferencia es que aquí cada visita al checkout es un robo, y nadie nota nada.</p>

<h2>Cómo entran en tu PrestaShop</h2>
<p>Los 5 vectores más comunes en 2026:</p>
<ol>
  <li><strong>Módulos vulnerables sin actualizar.</strong> CVEs públicos en módulos populares (blockwishlist, ps_facetedsearch, gamification antiguos). El atacante explota la vulnerabilidad y obtiene acceso al back office.</li>
  <li><strong>Panel admin sin renombrar.</strong> Si tu URL de admin sigue siendo /admin/, fuerza bruta automatizada con listas de contraseñas filtradas → entrada en pocos días.</li>
  <li><strong>Credenciales filtradas en HaveIBeenPwned.</strong> El email de tu admin aparece en alguna brecha (LinkedIn 2021, Adobe 2013, etc.). La gente reusa contraseñas. Login en el back office.</li>
  <li><strong>Hosting compartido comprometido.</strong> Otro cliente del mismo hosting está infectado y la infección se mueve lateralmente a través de directorios mal aislados.</li>
  <li><strong>Cadena de suministro.</strong> Un módulo de terceros pirateado en el propio mercado de PrestaShop Addons o descargado de sitios "nulled". El skimmer viene preinstalado.</li>
</ol>

<h2>Las 6 señales claras de que tienes un skimmer</h2>

<h3>1. JavaScript en el HTML del checkout que no pusiste tú</h3>
<p>Abre tu tienda en Chrome → F12 → pestaña Sources → archivo de la página /order. Si ves un bloque grande de código JavaScript con eval(), atob() o unescape() y no recuerdas haberlo puesto, sospecha.</p>

<h3>2. Llamadas a dominios externos extraños</h3>
<p>En F12 → Network → recarga el checkout → filtra por "JS". Mira los dominios. ¿Hay alguno que no reconozcas? Especialmente sospechosos: <code>googie-analytics.com</code> (con i en vez de l), <code>stripe-cdn.com</code>, <code>jqueryxcdn.com</code>, dominios .io o .live nuevos.</p>

<h3>3. Quejas de clientes con cargos fraudulentos</h3>
<p>Si recibes 2-3 emails en una semana de clientes diciendo que les llegaron cargos fraudulentos después de comprar en tu tienda, no es coincidencia. <strong>Es la pista más fiable</strong>.</p>

<h3>4. Aumento de chargebacks de tu pasarela</h3>
<p>Mira el panel de Redsys, Stripe o tu banco. Si los chargebacks suben un 20-30% sin explicación, podrías tener un skimmer activo desde hace meses.</p>

<h3>5. Archivos PHP modificados en /modules/ o /themes/</h3>
<p>Conéctate por SSH/FTP y mira los timestamps:</p>
<pre><code>find /var/www/tutienda/modules -type f -name "*.php" -mtime -30 -ls
find /var/www/tutienda/themes -type f -name "*.tpl" -mtime -30 -ls</code></pre>
<p>Archivos modificados en los últimos 30 días que tú no has tocado = probable backdoor o skimmer.</p>

<h3>6. ReconBase te alerta de patrón sospechoso</h3>
<p>El <a href="/auditoria-prestashop">escáner gratuito de PrestaShop</a> analiza el JavaScript del checkout y te avisa si encuentra dominios en blocklists Magecart, código ofuscado o referencias a campos de tarjeta sospechosas. Es la primera línea de defensa para detectar el problema antes de que se prolongue.</p>

<h2>Cómo limpiar tu PrestaShop si encuentras un skimmer</h2>
<p>El orden importa. Cualquier paso fuera de orden puede destruir evidencia o avisar al atacante.</p>

<ol>
  <li><strong>NO toques nada en producción todavía.</strong> Haz una copia forense completa: snapshot del servidor (filesystem), dump de la base de datos, HTML completo del checkout actual. Esto te servirá como evidencia si hay denuncia.</li>
  <li><strong>Cambia las contraseñas desde un equipo limpio</strong>, no desde el infectado: admin PrestaShop, FTP/SSH, panel del hosting, MySQL, email asociado.</li>
  <li><strong>Identifica el archivo infectado.</strong> Compara los archivos modificados con un backup limpio anterior. Foco en /modules/[nombre]/[nombre].php, /themes/[tema]/templates/checkout/, /classes/PaymentModule.php.</li>
  <li><strong>Restaura desde un backup anterior al ataque</strong> si lo tienes. Si no, contrata un servicio profesional (Sucuri, Sansec, S2 Grupo).</li>
  <li><strong>Actualiza TODO</strong>: core PrestaShop, todos los módulos, theme. Elimina módulos que no uses.</li>
  <li><strong>Renombra el panel de administración</strong> a algo aleatorio: /admin-x7K9pQ por ejemplo.</li>
  <li><strong>Elimina /install/</strong> si sigue ahí.</li>
  <li><strong>Activa autenticación en dos factores</strong> para todos los usuarios admin.</li>
  <li><strong>Notifica a la AEPD en 72h</strong> (obligatorio RGPD art. 33). Si estás bajo NIS2 también al INCIBE-CERT en 24h.</li>
  <li><strong>Avisa a tu pasarela de pago.</strong> Pueden ayudarte a identificar el rango de fechas afectado y notificar a las tarjetas comprometidas.</li>
  <li><strong>Si has perdido la certificación PCI-DSS</strong>: contacta con tu QSA (Qualified Security Assessor) para recertificación. Sin esto no puedes vender online.</li>
</ol>

<h2>Cómo prevenir nuevos skimmers</h2>
<ul>
  <li><strong>Mantén PrestaShop y módulos al día.</strong> El 80% de skimmers entran por vulnerabilidades conocidas que tienen parche.</li>
  <li><strong>Audita mensualmente con ReconBase</strong> o herramientas equivalentes. El coste de la suscripción Pro es 50x más barato que limpiar un incidente.</li>
  <li><strong>Activa CSP (Content Security Policy)</strong> con allowlist de dominios. Impide que JavaScript externo cargue desde dominios no autorizados — el ataque Magecart deja de funcionar.</li>
  <li><strong>Subresource Integrity (SRI)</strong> en los scripts externos. Garantiza que el JS no haya sido modificado en tránsito.</li>
  <li><strong>Logs centralizados</strong> con alerta automática si cambian archivos PHP en producción.</li>
  <li><strong>Auditoría manual del checkout</strong> después de cualquier actualización de módulos, theme o PrestaShop.</li>
  <li><strong>Hosting dedicado</strong> en lugar de shared, si tu volumen lo permite. Menos vectores laterales.</li>
</ul>

<h2>Conclusión</h2>
<p>Los skimmers digitales son la amenaza nº1 contra tiendas PrestaShop en 2026 y la mayoría de propietarios no saben que están infectados. La detección temprana ahorra multas RGPD, chargebacks y pérdida del sello PCI-DSS. <a href="/auditoria-prestashop">Lanza una auditoría gratuita de tu PrestaShop ahora</a> y comprueba si el detector de skimmers de ReconBase encuentra algo sospechoso. Si lo encuentra, sigue el protocolo de esta guía.</p>
""".strip()
    },
    {
        "slug": "auditoria-wordpress-12-checks-reconbase",
        "titulo": "Auditoría WordPress: los 12 checks de seguridad que hace ReconBase gratis en 60 segundos",
        "excerpt": "Repasamos uno a uno los 12 chequeos técnicos que ReconBase ejecuta en cualquier WordPress: qué busca, por qué importa, qué hacer si falla. Sin instalar plugins, sin compartir credenciales.",
        "tags": "wordpress,auditoria,seguridad,wp-scan,plugins,xmlrpc,wp-json,2026",
        "contenido": """
<h2>Por qué necesitas auditar tu WordPress (aunque tu web vaya bien)</h2>
<p>WordPress es el CMS más usado del mundo: el 43% de toda Internet corre sobre él. Eso lo convierte también en el <strong>objetivo más atacado</strong>. El 90% de los hackeos a webs WordPress se producen por tres causas: <strong>versión obsoleta, plugin vulnerable o credenciales filtradas</strong>. Las tres son detectables sin tocar el sitio, simplemente analizando lo que se ve desde fuera.</p>
<p>Esa es exactamente la idea de la <a href="/auditoria-wordpress">auditoría gratuita de ReconBase</a>: 12 chequeos en 60 segundos, sin instalar nada, sin compartir el wp-admin. Te explico qué hace cada uno.</p>

<h2>1. Detección de la versión del core</h2>
<p>Buscamos la versión de WordPress por cuatro caminos: <code>&lt;meta name="generator"&gt;</code> en el HTML de la home, generator del feed RSS (<code>/feed/</code>), API JSON (<code>/wp-json/</code>) y el archivo <code>/readme.html</code>. Si todos coinciden con la última versión estable, OK. Si detectamos una versión inferior, te marcamos cuántas minor o major versiones llevas de retraso.</p>
<p><strong>Por qué importa:</strong> el equipo de WordPress publica parches de seguridad cada pocas semanas. Versiones >12 meses antiguas suelen tener al menos 1-2 CVEs públicos explotables.</p>

<h2>2. xmlrpc.php expuesto</h2>
<p>Comprobamos si <code>/xmlrpc.php</code> responde 200 con cabecera XML-RPC. Si responde, está abierto.</p>
<p><strong>Por qué importa:</strong> xmlrpc.php permite hacer login con una única petición HTTP (en vez de pasar por el formulario de wp-login.php) y, peor aún, soporta el método <code>system.multicall</code> que ejecuta cientos de logins en una sola petición. Resultado: fuerza bruta acelerada 100x. Además es un vector clásico de amplificación pingback DDoS.</p>
<p><strong>Cómo arreglarlo:</strong> si no usas Jetpack ni edición móvil remota, bloquéalo en .htaccess o nginx. Una sola línea.</p>

<h2>3. Enumeración de usuarios vía wp-json</h2>
<p>Hacemos GET a <code>/wp-json/wp/v2/users</code>. Si responde con una lista de usuarios, los enumeramos (hasta los 5 primeros, sin recoger emails ni datos sensibles).</p>
<p><strong>Por qué importa:</strong> cualquier atacante puede leer los nombres de usuario reales de tus administradores sin necesidad de adivinar. Combinado con xmlrpc abierto o con un wp-login.php sin captcha = fuerza bruta dirigida en horas.</p>
<p><strong>Cómo arreglarlo:</strong> plugin "Stop User Enumeration" o regla nginx que bloquee la ruta. Lleva 5 minutos.</p>

<h2>4. Plugins activos y cruce con CVEs conocidos</h2>
<p>Extraemos los slugs de plugin de las URLs <code>/wp-content/plugins/[slug]/</code> presentes en el HTML. Cruzamos con nuestra lista interna de plugins con vulnerabilidades públicas conocidas (WP File Manager RCE pre-auth, Duplicator antiguos, Elementor con XSS, Contact Form 7 con upload vulnerable, etc.).</p>
<p><strong>Por qué importa:</strong> el plugin obsoleto es el vector #1 de hackeo de WordPress en 2026. Algunos CVEs son tan graves que permiten ejecución remota de código sin autenticación.</p>
<p><strong>Limitación:</strong> solo detectamos plugins que dejan rastro en el HTML público. Los plugins de admin-only no los vemos (es esperado).</p>

<h2>5. Theme activo y versión</h2>
<p>Identificamos el theme por la ruta <code>/wp-content/themes/[slug]/</code>. Conocer el theme ayuda a detectar themes premium descontinuados o themes nulled (piratas) con backdoors preinstaladas.</p>

<h2>6. Archivos sensibles expuestos</h2>
<p>Probamos seis rutas típicas que <strong>nunca deberían estar accesibles desde el navegador</strong>:</p>
<ul>
  <li><code>/wp-config.php.bak</code> y <code>/wp-config.php~</code>: backups con credenciales DB en claro.</li>
  <li><code>/.wp-config.php.swp</code>: archivo swap de vim — credenciales DB recuperables.</li>
  <li><code>/wp-admin/install.php</code>: permite reinstalar la web con credenciales del atacante.</li>
  <li><code>/readme.html</code>: filtra versión exacta de WordPress.</li>
  <li><code>/wp-content/debug.log</code>: errores y paths internos.</li>
</ul>
<p><strong>Cómo arreglarlo:</strong> borrar los archivos. Si no puedes borrarlos, bloquearlos por .htaccess.</p>

<h2>7. SSL/TLS y caducidad del certificado</h2>
<p>Comprobamos si tu dominio tiene HTTPS, si el certificado es válido y cuántos días faltan para que expire. Si caduca en <30 días, te avisamos. Si ya caducó, alerta crítica.</p>

<h2>8. Puertos críticos abiertos</h2>
<p>Escaneo de puertos críticos (MySQL, RDP, MongoDB, Redis, PostgreSQL, MSSQL). Tu hosting nunca debería exponer estos puertos al exterior — si responden, hay un riesgo real de robo de base de datos.</p>

<h2>9. Configuración DNS (SPF + DMARC)</h2>
<p>Comprobamos SPF y DMARC de tu dominio. Si faltan, cualquiera puede enviar emails haciéndose pasar por tu empresa — vector clásico de Business Email Compromise.</p>

<h2>10. Cabeceras HTTP de seguridad</h2>
<p>Verificamos las cabeceras críticas: <code>Content-Security-Policy</code>, <code>X-Frame-Options</code>, <code>Strict-Transport-Security</code>, <code>X-Content-Type-Options</code>, <code>Referrer-Policy</code>. Configurarlas no requiere tocar WordPress, solo tu nginx/Apache.</p>

<h2>11. Subdominios visibles</h2>
<p>Análisis pasivo de subdominios. Te mostramos los detectados. Útil para encontrar entornos de staging, paneles internos o servicios olvidados que también deberían auditarse.</p>

<h2>12. Filtraciones de credenciales asociadas al dominio</h2>
<p>Cuando proporcionas un email empresarial, cruzamos con HaveIBeenPwned para ver si las credenciales asociadas han aparecido en alguna brecha pública (LinkedIn 2021, Adobe, Dropbox, etc.). Si tu admin reusa contraseña, esta es la entrada que un atacante encontrará primero.</p>

<h2>Cómo se ve el resultado</h2>
<p>El informe que recibes tiene:</p>
<ul>
  <li><strong>Riesgo global (0-100%)</strong> con código de color: verde si <40, ámbar si 40-69, rojo si ≥70.</li>
  <li><strong>Tarjetas por categoría</strong>: una por cada uno de los 12 checks, con severidad y descripción del hallazgo.</li>
  <li><strong>Desglose de penalizaciones</strong>: cuánto pesa cada hallazgo en el riesgo total.</li>
  <li><strong>Plan de remediación</strong> con pasos concretos por cada problema detectado.</li>
</ul>
<p>Y, si te registras gratis, también recibes:</p>
<ul>
  <li>PDF ejecutivo profesional para mandar a dirección o cumplir RGPD/NIS2.</li>
  <li>Monitorización 24/7: reescaneo automático y alerta inmediata si aparece un problema nuevo.</li>
  <li>Histórico de escaneos para ver evolución.</li>
  <li>Verificación de filtraciones de email contra HaveIBeenPwned ilimitada.</li>
</ul>

<h2>Limitaciones honestas</h2>
<p>Esta auditoría externa cubre el 80% del riesgo común de WordPress, pero <strong>no es un pentest</strong>. No detecta:</p>
<ul>
  <li>Plugins instalados sin rastro en HTML público (raros).</li>
  <li>Vulnerabilidades específicas de tu código personalizado (custom plugins/themes).</li>
  <li>Backdoors que se camuflen perfectamente en archivos PHP del core.</li>
  <li>Configuraciones inseguras del wp-admin (capacidades de roles, etc.).</li>
</ul>
<p>Para eso necesitas un escáner interno como Wordfence o Sucuri, o una auditoría manual por un pentester. Pero <strong>la mayoría de hackeos detectables se previenen con esta capa externa</strong> — porque la mayoría de atacantes usan exactamente los mismos vectores que nuestros 12 checks miran.</p>

<h2>Conclusión</h2>
<p>La auditoría WordPress de ReconBase es lo que harías tú mismo si fueras pentester y tuvieras 60 segundos. <a href="/auditoria-wordpress">Pásala ahora a tu dominio</a> y mira el informe. Si todo sale en verde, perfecto — tienes evidencia de "due diligence" para auditorías de cumplimiento. Si sale algo en rojo, mejor lo arreglas antes de que un atacante lo encuentre.</p>
""".strip()
    },
]

with app.app_context():
    try:
        for _seed in _BLOG_SEEDS:
            existing = BlogPost.query.filter_by(slug=_seed["slug"]).first()
            if existing:
                continue
            _bp = BlogPost(
                slug=_seed["slug"],
                titulo=_seed["titulo"],
                excerpt=_seed["excerpt"],
                contenido=_seed["contenido"],
                tags=_seed["tags"],
                publicado=True,
                autor="ReconBase",
            )
            db.session.add(_bp)
        db.session.commit()
        logger.info(f"[Bootstrap] Blog seeds OK ({len(_BLOG_SEEDS)} verificados)")
    except Exception as _bse:
        logger.warning(f"[Bootstrap] blog seeds: {_bse}")
        db.session.rollback()


# ─── Bootstrap de admin: marcar como admin los emails listados en ADMIN_EMAILS ───
# Uso: en Railway define ADMIN_EMAILS="lucas@example.com,otro@example.com"
# Se ejecuta en cada arranque, es idempotente.
with app.app_context():
    try:
        _admin_emails_raw = os.getenv("ADMIN_EMAILS", "")
        _admin_emails = [e.strip().lower() for e in _admin_emails_raw.split(",") if e.strip()]
        if _admin_emails:
            for _ae in _admin_emails:
                _u = User.query.filter_by(email=_ae).first()
                if _u and not _u.is_admin:
                    _u.is_admin = True
                    db.session.commit()
                    logger.info(f"[Bootstrap] Usuario {_ae} promovido a admin via ADMIN_EMAILS")
    except Exception as _bae:
        logger.warning(f"[Bootstrap] ADMIN_EMAILS: {_bae}")
        db.session.rollback()

# ─── Exentar rutas /api/* del CSRF ───
# Las protegemos con SameSite=Lax + HttpOnly + mismo origen (fetch AJAX).
# El webhook de Stripe (/api/webhook) también queda exento — usa verificación por firma.
for _rule in app.url_map.iter_rules():
    if _rule.rule.startswith('/api/'):
        _view = app.view_functions.get(_rule.endpoint)
        if _view is not None:
            csrf.exempt(_view)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Demasiadas peticiones. Espera un momento e inténtalo de nuevo."}), 429

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({"ok": False, "error": "Not found"}), 404
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Error 500: {e}")
    if request.path.startswith('/api/'):
        return jsonify({"ok": False, "error": "Internal server error"}), 500
    return render_template("500.html"), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
