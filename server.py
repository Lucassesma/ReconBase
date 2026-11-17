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
                    ProcessedWebhook, AnonymousScan, LoginAttempt, ScanOptOut)
import reconbase_engine as engine
import os, io, json, stripe, threading, logging, urllib.request, urllib.error, hashlib, hmac, base64, secrets
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
    # En desarrollo local permitimos un fallback, pero en producción lo exigimos.
    # Detectamos producción por Railway, FLASK_ENV o la variable genérica PRODUCTION.
    _is_prod = (
        os.getenv("RAILWAY_ENVIRONMENT_NAME")
        or os.getenv("RAILWAY_ENVIRONMENT")
        or os.getenv("FLASK_ENV", "").lower() == "production"
        or os.getenv("PRODUCTION", "").lower() in ("1", "true", "yes")
    )
    if _is_prod:
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

# ─── IP real del cliente (Cloudflare → Railway → app) ───
# request.remote_addr es la IP del proxy de Railway, la misma para todos los
# visitantes. CF-Connecting-IP la fija Cloudflare, pero cualquiera puede
# falsificarla entrando directamente al origen (*.up.railway.app). Solo nos
# fiamos de ella si la petición trae la cabecera secreta que añade nuestra regla
# de Cloudflare (Transform Rule "X-Origin-Secret").
ORIGIN_SECRET = os.getenv("ORIGIN_SECRET", "")
# Con ORIGIN_LOCK=1 se rechaza todo lo que no venga por Cloudflare (impide saltarse
# el WAF entrando al origen). Activar solo tras comprobar /admin/origen-check.
ORIGIN_LOCK = os.getenv("ORIGIN_LOCK", "") == "1"


def _via_cloudflare():
    if not ORIGIN_SECRET:
        return False
    import hmac as _hmac
    return _hmac.compare_digest(request.headers.get("X-Origin-Secret", ""), ORIGIN_SECRET)


def _ip_cliente():
    """Clave del rate limit: IP real del visitante si se puede verificar."""
    if _via_cloudflare():
        return request.headers.get("CF-Connecting-IP") or get_remote_address()
    return get_remote_address()


limiter = Limiter(
    key_func=_ip_cliente,
    app=app,
    default_limits=[],
    storage_uri=os.getenv("REDIS_URL", "memory://")
)
if not ORIGIN_SECRET:
    logging.getLogger("reconbase").warning(
        "[RateLimit] ORIGIN_SECRET no configurado: todos los visitantes comparten "
        "contador (IP del proxy). Configura la regla de Cloudflare + ORIGIN_SECRET.")


@app.before_request
def _bloquear_acceso_directo_al_origen():
    if not (ORIGIN_LOCK and ORIGIN_SECRET):
        return None
    # Stripe firma sus webhooks; el healthcheck de Railway no pasa por Cloudflare.
    if request.path == "/api/webhook" or (request.host or "").split(":")[0] == "healthcheck.railway.app":
        return None
    if not _via_cloudflare():
        abort(403)
    return None

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
        'camera=(), microphone=(), geolocation=(), payment=()'
    )
    # CSP relajada pero razonable (el sitio usa inline JS/CSS, Google Fonts y Chart.js CDN)
    resp.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://plausible.io https://www.googletagmanager.com https://*.googletagmanager.com https://www.google-analytics.com https://*.google-analytics.com https://challenges.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://plausible.io https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com; "
        "frame-src https://www.googletagmanager.com https://challenges.cloudflare.com; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    return resp

# ─── Anti-SSRF en la entrada de los endpoints de escaneo ───────────────────────
def _rechazar_si_interno(objetivo):
    """Respuesta 400 si el objetivo apunta a una red interna/privada; None si se
    puede analizar. Un dominio que no resuelve se deja pasar: los módulos que no
    conectan (HIBP, SPF/DMARC) siguen siendo útiles y el motor no conectará."""
    from urllib.parse import urlsplit
    try:
        host = urlsplit("//" + (objetivo or "").strip()).hostname or ""
    except ValueError:
        return jsonify({"ok": False, "error": "Dominio inválido"}), 400
    if engine.es_destino_interno(host):
        return jsonify({"ok": False, "error": "Ese destino apunta a una red interna o privada y no se puede analizar."}), 400
    return None


# ─── Dominios: normalización, verificación de titularidad y exclusiones ────────
_RE_DOMINIO = re.compile(r"^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


def _normalizar_dominio(raw):
    """'https://www.Ejemplo.com/ruta' o 'ana@ejemplo.com' → 'ejemplo.com'.
    Devuelve '' si no es un dominio o una IPv4 válidos."""
    d = (raw or "").strip().lower()
    d = d.split("@")[-1]
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
    if d.startswith("[") or d.count(":") == 1:
        d = d.split(":")[0]
    if d.startswith("www."):
        d = d[4:]
    if engine.es_ip(d) or _RE_DOMINIO.match(d):
        return d
    return ""


def _dominio_verificado_de(user, dominio):
    """Domain verificado del usuario que cubre `dominio`, o None. La verificación
    por DNS cubre también los subdominios; la de meta o fichero, solo ese host."""
    if not user or not getattr(user, "is_authenticated", False):
        return None
    dominio = _normalizar_dominio(dominio)
    if not dominio:
        return None
    for d in Domain.query.filter_by(user_id=user.id, verificado=True).all():
        base = (d.dominio or "").lower()
        if dominio == base:
            return d
        if d.verif_metodo == "dns" and dominio.endswith("." + base):
            return d
    return None


def _modo_para(user, dominio):
    return engine.MODO_COMPLETO if _dominio_verificado_de(user, dominio) else engine.MODO_PASIVO


def _excluido_por_titular(dominio):
    """True si el titular de `dominio` (o de un dominio padre) pidió no ser analizado."""
    dominio = _normalizar_dominio(dominio)
    if not dominio:
        return False
    partes = dominio.split(".")
    candidatos = [".".join(partes[i:]) for i in range(len(partes) - 1)] or [dominio]
    return db.session.query(ScanOptOut.id).filter(
        ScanOptOut.confirmado.is_(True), ScanOptOut.dominio.in_(candidatos)
    ).first() is not None


def _validar_objetivo(dominio, user=None):
    """Respuesta de error si no se puede analizar `dominio`; None si se puede.
    El titular que ha verificado su dominio puede analizarlo aunque lo excluyera."""
    bloqueo = _rechazar_si_interno(dominio)
    if bloqueo:
        return bloqueo
    if _excluido_por_titular(dominio) and not _dominio_verificado_de(user, dominio):
        return jsonify({"ok": False, "excluido": True,
                        "error": "El titular de este dominio ha pedido que ReconBase no lo analice."}), 403
    return None


def _email_hibp_permitido(user, email):
    """HIBP solo para el email del propio usuario o emails de un dominio que ha
    verificado: así no se consultan datos personales de terceros."""
    email = (email or "").strip().lower()
    if not user or not getattr(user, "is_authenticated", False) or "@" not in email:
        return False
    if email == (user.email or "").lower():
        return True
    return _dominio_verificado_de(user, email.split("@")[-1]) is not None


HIBP_ATRIBUCION = "Datos de filtraciones: Have I Been Pwned (haveibeenpwned.com), licencia CC BY 4.0"


def _ejecutar_analisis(objetivo, dominio, user=None, subdominios=True):
    """Análisis único para todos los endpoints: el modo depende de si `user` ha
    verificado el dominio; HIBP solo se consulta si el email está permitido."""
    modo = _modo_para(user, dominio)
    resultado = engine.analizar(dominio, modo=modo, subdominios=subdominios)
    resultado["objetivo"] = objetivo
    leaks, estado_hibp = [], "no_aplica"
    if "@" in objetivo:
        if not _email_hibp_permitido(user, objetivo):
            estado_hibp = "no_permitido"
        elif not API_KEY:
            estado_hibp = "no_disponible"
        else:
            leaks = engine.check_leaks_real(objetivo, API_KEY)
            estado_hibp = "consultado" if leaks is not None else "no_disponible"
            leaks = leaks or []
    resultado["leaks_raw"] = leaks
    resultado["leaks"] = len(leaks)
    resultado["hibp_estado"] = estado_hibp
    if estado_hibp == "consultado":
        resultado["hibp_atribucion"] = HIBP_ATRIBUCION
    return engine.puntuar(resultado)


from html import escape as _html_escape


def _slack_escape(texto):
    """Slack interpreta <...> como enlaces/menciones: se escapan & < > (formato oficial de Slack)."""
    return str(texto).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class _SinRedirecciones(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# Para webhooks de usuario: una redirección podría apuntar a la red interna.
_opener_sin_redirecciones = urllib.request.build_opener(_SinRedirecciones)


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
        {"loc": base + "/herramientas",         "priority": "0.9", "changefreq": "weekly",  "lastmod": today},
        {"loc": base + "/escaner-info",         "priority": "0.4", "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/auditoria-wordpress",  "priority": "0.9", "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/auditoria-prestashop", "priority": "0.9", "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/auditoria-rapida",     "priority": "0.9", "changefreq": "monthly", "lastmod": today},
        {"loc": base + "/skimmer-check",        "priority": "0.85","changefreq": "monthly", "lastmod": today},
        {"loc": base + "/comprobar-cabeceras-http", "priority": "0.85","changefreq": "monthly", "lastmod": today},
        {"loc": base + "/comprobar-lista-negra",    "priority": "0.85","changefreq": "monthly", "lastmod": today},
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
    real_ip = _ip_cliente() or ""
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

@app.route("/auditoria-rapida")
def auditoria_rapida():
    """Landing de auditoría rápida: SPF/DMARC + cabeceras HTTP + reputación."""
    user = current_user if current_user.is_authenticated else None
    return render_template("auditoria_rapida.html", user=user)

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

@app.route("/herramientas")
def hub_herramientas():
    """Hub SEO que agrupa todas las herramientas gratuitas. Mejora el
    interlinking interno y capta búsquedas tipo 'herramientas seguridad web gratis'."""
    return render_template("herramientas.html", lista_negra_disponible=bool(WEB_RISK_API_KEY))

@app.route("/comprobar-cabeceras-http")
def tool_headers():
    """Herramienta gratuita: comprobar cabeceras de seguridad HTTP.
    SEO: 'comprobar cabeceras seguridad', 'security headers test español'."""
    return render_template("tool_headers.html")

@app.route("/comprobar-lista-negra")
def tool_blacklist():
    """Herramienta gratuita: comprobar si un dominio está en listas negras
    de malware/phishing. SEO: 'comprobar lista negra google', 'mi web marcada
    como insegura', 'verificar sitio seguro'."""
    return render_template("tool_blacklist.html", disponible=bool(WEB_RISK_API_KEY))

# ─── Registro anónimo de uso de las herramientas públicas ──────────────────────
# La IP no se guarda: solo un HMAC truncado con una clave derivada del secreto de
# la app y de la fecha. Sirve para contar visitantes únicos del día y no permite
# relacionar visitas de días distintos ni recuperar la IP sin el secreto.
_IP_HASH_SECRET = (os.getenv("IP_HASH_SECRET") or app.secret_key or "").encode()


def _hash_ip_visitante():
    ip = _ip_cliente()
    if not ip:
        return None
    clave_dia = hmac.new(_IP_HASH_SECRET, datetime.utcnow().strftime("%Y-%m-%d").encode(), hashlib.sha256).digest()
    return hmac.new(clave_dia, ip.encode(), hashlib.sha256).hexdigest()[:16]


def _registrar_escaneo_anonimo(dominio, riesgo, label):
    try:
        db.session.add(AnonymousScan(
            dominio=(dominio or "")[:255], riesgo=int(riesgo or 0), label=(label or "")[:20],
            ip_hash=_hash_ip_visitante(),
            referer=(request.headers.get("Referer") or "")[:255],
            user_agent=(request.headers.get("User-Agent") or "")[:100],
            es_logged=bool(getattr(current_user, "is_authenticated", False)),
        ))
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"[AnonScan] no se pudo guardar: {e}")


WEB_RISK_API_KEY = os.getenv("WEB_RISK_API_KEY", "")
_LISTA_NEGRA_NO_DISPONIBLE = ("La comprobación de listas negras no está disponible en este momento. "
                              "Vuelve a intentarlo más tarde.")


@app.route("/api/check-blacklist", methods=["POST"])
@limiter.limit("30 per hour")
def api_check_blacklist():
    """¿Está el dominio en las listas de Google Web Risk? No contacta con el dominio."""
    data = request.get_json(silent=True) or {}
    dominio = _normalizar_dominio((data.get("dominio") or "")[:255])
    if not dominio or engine.es_ip(dominio):
        return jsonify({"error": "Introduce un dominio válido"}), 400
    if not WEB_RISK_API_KEY:
        return jsonify({"error": _LISTA_NEGRA_NO_DISPONIBLE, "disponible": False}), 503
    res = engine.check_blacklist(dominio, web_risk_key=WEB_RISK_API_KEY)
    if not res.get("disponible"):
        return jsonify({"error": _LISTA_NEGRA_NO_DISPONIBLE, "disponible": False}), 503
    res["timestamp"] = datetime.utcnow().strftime("%d/%m/%Y %H:%M")
    _registrar_escaneo_anonimo(dominio, 100 if res.get("listed") else 0,
                               "BLACKLIST" if res.get("listed") else "LIMPIO")
    return jsonify(res)

@app.route("/api/check-headers", methods=["POST"])
@limiter.limit("30 per hour")
def api_check_headers():
    """Comprueba las cabeceras de seguridad HTTP de un dominio. Público, sin login."""
    data = request.get_json(silent=True) or {}
    dominio = _normalizar_dominio((data.get("dominio") or "")[:255])
    if not dominio:
        return jsonify({"error": "Introduce un dominio válido"}), 400
    _bloqueo = _validar_objetivo(dominio, current_user)
    if _bloqueo:
        return _bloqueo
    try:
        headers = engine.check_security_headers(dominio)
    except Exception as e:
        logger.warning(f"[check-headers] error {dominio}: {e}")
        return jsonify({"error": "No se pudo conectar con el dominio"}), 500
    # headers es {nombre_amigable: bool}. Calcular nota A-F.
    total = len(headers) if headers else 6
    presentes = sum(1 for v in headers.values() if v)
    pct = round(presentes / total * 100) if total else 0
    if   pct >= 95: nota = "A"
    elif pct >= 80: nota = "B"
    elif pct >= 60: nota = "C"
    elif pct >= 40: nota = "D"
    elif pct >= 20: nota = "E"
    else:           nota = "F"
    # Mapa de explicaciones por cabecera
    explica = {
        "HSTS": "Fuerza HTTPS en todas las conexiones. Sin ella, un atacante puede degradar a HTTP y espiar.",
        "Anti-Clickjacking": "Impide que tu web se cargue dentro de un iframe malicioso (clickjacking).",
        "MIME-Sniffing": "Evita que el navegador interprete archivos como un tipo distinto al declarado.",
        "CSP": "La defensa más potente contra XSS e inyección de scripts. Define qué recursos pueden cargarse.",
        "Referrer-Policy": "Controla cuánta información de tu URL se envía al navegar a otros sitios.",
        "Permissions-Policy": "Limita el acceso a cámara, micrófono, geolocalización, etc. desde tu web.",
    }
    detalle = [{"nombre": k, "presente": bool(v), "explica": explica.get(k, "")} for k, v in headers.items()]
    _registrar_escaneo_anonimo(dominio, 100 - pct, f"HDR-{nota}")
    return jsonify({
        "dominio": dominio, "nota": nota, "porcentaje": pct,
        "presentes": presentes, "total": total, "detalle": detalle,
        "timestamp": datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
    })

@app.route("/api/skimmer-check", methods=["POST"])
@limiter.limit("20 per hour")
def api_skimmer_check():
    """Detector público de skimmers: analiza la tienda pública (home, páginas de
    pedido y scripts que cargan). Sin registro, siempre en modo pasivo."""
    data = request.get_json(silent=True) or {}
    dominio = _normalizar_dominio((data.get("dominio") or "")[:255])
    if not dominio:
        return jsonify({"error": "Introduce un dominio válido"}), 400
    _bloqueo = _validar_objetivo(dominio, current_user)
    if _bloqueo:
        return _bloqueo
    if engine.es_ip(dominio):
        return jsonify({"error": "Introduce un dominio, no una IP"}), 400

    try:
        ps = engine.prestashop_audit(dominio, modo=_modo_para(current_user, dominio))
    except Exception as e:
        logger.warning(f"[skimmer-check] error en {dominio}: {e}")
        return jsonify({"error": "No se pudo escanear el dominio (timeout o respuesta inválida)"}), 500

    response = {
        "dominio": dominio,
        "is_prestashop": ps.get("is_prestashop", False),
        "version": ps.get("version"),
        "skimmer_suspect": ps.get("skimmer_suspect", False),
        "skimmer_evidence": ps.get("skimmer_evidence", []),
        "modo": ps.get("modo", engine.MODO_PASIVO),
        "timestamp": datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
    }
    if not ps.get("is_prestashop"):
        response["note"] = ("No se detectó PrestaShop en este dominio. El detector de skimmers de ReconBase "
                            "está optimizado para tiendas PrestaShop. Para análisis genérico usa la auditoría completa.")
    label = "SKIMMER" if ps.get("skimmer_suspect") else ("PS-OK" if ps.get("is_prestashop") else "NO-PS")
    _registrar_escaneo_anonimo(dominio, 100 if ps.get("skimmer_suspect") else 0, label)
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

    dominio = _normalizar_dominio(raw)
    if not dominio or engine.es_ip(dominio):
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


# ─── Transparencia del escáner y exclusión de dominios ────────────────────────
@app.route("/escaner-info")
def escaner_info():
    return render_template("escaner_info.html", user_agent=engine.USER_AGENT)


@app.route("/api/excluir-dominio", methods=["POST"])
@limiter.limit("5 per hour")
def api_excluir_dominio():
    """El titular de un dominio pide que no lo analicemos. Se confirma con un
    enlace enviado a un email de ese mismo dominio."""
    data = request.get_json(silent=True) or {}
    dominio = _normalizar_dominio((data.get("dominio") or "")[:255])
    email = (data.get("email") or "").strip().lower()[:120]
    if not dominio or engine.es_ip(dominio):
        return jsonify({"ok": False, "error": "Introduce un dominio válido."}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+$", email):
        return jsonify({"ok": False, "error": "Introduce un email válido."}), 400
    dominio_email = email.split("@")[-1]
    if dominio_email != dominio and not dominio_email.endswith("." + dominio):
        return jsonify({"ok": False, "error": f"El email debe ser de {dominio} (por ejemplo, admin@{dominio})."}), 400
    if _excluido_por_titular(dominio):
        return jsonify({"ok": True})
    peticion = ScanOptOut.query.filter_by(dominio=dominio, email=email, confirmado=False).first()
    if not peticion:
        peticion = ScanOptOut(dominio=dominio, email=email, token=secrets.token_urlsafe(32))
        db.session.add(peticion)
        db.session.commit()
    try:
        send_html_email(
            email, f"Confirma que ReconBase no debe analizar {dominio}",
            "Confirma la exclusión de tu dominio",
            f"<p>Hemos recibido una petición para que ReconBase no analice <strong>{_html_escape(dominio)}</strong> "
            "ni sus subdominios.</p><p>Si la has hecho tú, confírmala con el botón. Si no, ignora este email: "
            "no cambiará nada.</p>",
            f"{BASE_URL}/excluir-dominio/confirmar/{peticion.token}", "Confirmar exclusión")
    except Exception as e:
        logger.warning(f"[Exclusión] no se pudo enviar el email a {email}: {e}")
        return jsonify({"ok": False, "error": "No pudimos enviar el email. Escríbenos a hola@reconbase.es."}), 502
    return jsonify({"ok": True})


@app.route("/excluir-dominio/confirmar/<token>")
@limiter.limit("30 per hour")
def confirmar_exclusion(token):
    peticion = ScanOptOut.query.filter_by(token=(token or "")[:64]).first()
    if not peticion:
        return render_template("verify_result.html", ok=False, titulo_pagina="Exclusión del escáner",
                               msg="El enlace no es válido. Vuelve a pedir la exclusión desde /escaner-info."), 404
    if not peticion.confirmado:
        peticion.confirmado = True
        peticion.confirmado_at = datetime.utcnow()
        db.session.commit()
        logger.info(f"[Exclusión] confirmada para {peticion.dominio}")
    return render_template("verify_result.html", ok=True, titulo_pagina="Exclusión del escáner",
                           titulo="Exclusión confirmada",
                           msg=f"ReconBase no analizará {peticion.dominio} ni sus subdominios. "
                               "Si cambias de opinión, escríbenos a hola@reconbase.es.")


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
            "features": ["SSL y cabeceras", "SPF y DMARC", "CMS y plugins"],
        },
        "pricing": {
            "title": "RECONBASE",
            "sub": "Gratis \u2014 Ciberseguridad para PYMEs",
            "features": ["Todas las funciones", "Sin tarjeta", "Sin planes de pago"],
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
    # ── ¿El usuario ha escaneado alguna vez? (histórico total, no del mes) ──
    # Sirve para ocultar los banners de bienvenida/primeros pasos en cuanto
    # hace su primer escaneo, sin depender de que pulse la X.
    ha_escaneado = False
    if current_user.is_authenticated:
        try:
            ha_escaneado = Scan.query.filter_by(user_id=current_user.id).count() > 0
        except Exception:
            db.session.rollback()
            ha_escaneado = False
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
    stats_scans   = Scan.query.count() + AnonymousScan.query.count()  # análisis reales: guardados + herramientas públicas
    stats_breaches = User.query.count()
    resp = make_response(render_template("landing.html", user=current_user,
                           plan=plan, scans_mes=scans_mes,
                           ultimo_auto=ultimo_auto,
                           api_key_ok=bool(API_KEY),
                           scan_hora=scan_hora, scan_dias=scan_dias,
                           stats_scans=stats_scans,
                           stats_breaches=stats_breaches,
                           tiene_ps_sin_vigilancia=tiene_ps_sin_vigilancia,
                           ps_dominios_sample=ps_dominios_sample,
                           ha_escaneado=ha_escaneado,
                           turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY", "")))
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
    """ReconBase es gratuito: la antigua página de pago redirige a la home."""
    return redirect(url_for("index"))

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
    return render_template("pricing.html")

# ── AUTH API ──
def _track_login_attempt(email, exito, razon):
    """Guarda un intento de login (éxito o fallo) en la tabla login_attempts.
    Silencioso ante errores — nunca debe romper el login."""
    try:
        ip_real = _ip_cliente() or ""
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
        ip_real = _ip_cliente() or ""
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
        session["2fa_pending_ts"] = time.time()  # TTL: expira en 5 min (ver totp_verify_login)
        return jsonify({"ok": True, "requires_2fa": True})
    # Sesión persistente: sobrevive a cerrar el navegador hasta 30 días
    session.permanent = True
    login_user(user, remember=True, duration=timedelta(days=30))
    _marcar_login_exitoso(user)
    _track_login_attempt(email, exito=True, razon="ok")
    _registrar_audit(user.id, 'login', "Login correcto")
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
        # Fail-open: si Cloudflare está down no bloqueamos registros legítimos,
        # pero lo registramos con ERROR para detectar abuso o degradación sostenida.
        logger.error(f"[Turnstile] FAIL-OPEN — verify falló, permitiendo paso sin captcha: {e}")
        try:
            import sentry_sdk as _sentry
            _sentry.capture_message(f"[Turnstile] fail-open: {e}", level="warning")
        except Exception:
            pass
        return True


@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")
def api_register():
    data     = request.get_json(silent=True) or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    empresa  = (data.get("empresa") or "").strip()
    ts_token = data.get("cf-turnstile-response", "")
    if not email or not password:
        return jsonify({"ok": False, "error": "Email y contraseña son obligatorios"}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "La contraseña debe tener al menos 8 caracteres"}), 400
    # Anti-bot: verificar Turnstile (si está configurado)
    if not _verify_turnstile(ts_token, _ip_cliente()):
        return jsonify({"ok": False, "error": "Verificación anti-bot fallida. Recarga la página e inténtalo de nuevo."}), 403
    if User.query.filter_by(email=email).first():
        return jsonify({"ok": False, "error": "Este email ya está registrado"}), 400
    # Si no rellenan empresa, fallback al nombre antes del @ (capitalizado).
    # Lo pueden cambiar luego en /perfil.
    if not empresa:
        empresa = email.split("@")[0].replace(".", " ").replace("_", " ").title()[:120] or "Tu empresa"
    user = User(email=email, empresa=empresa,
                acepta_comercial=data.get("acepta_comercial") is True,
                comercial_actualizado_at=datetime.utcnow())
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

def require_verified(f):
    """Decorador: bloquea el acceso si el usuario no ha verificado su email.
    Permite que usuarios recién registrados vean el dashboard sin verificar,
    pero impide que lancen escaneos o accedan a funciones de pago."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not getattr(current_user, 'email_verified', True):
            return jsonify({
                "ok": False,
                "error": "Verifica tu email antes de usar esta función. "
                         "Revisa tu bandeja de entrada.",
                "needs_verification": True,
            }), 403
        return f(*args, **kwargs)
    return decorated

@app.route("/api/stripe-portal", methods=["POST"])
@login_required
@require_verified
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
@limiter.limit("30 per hour")
def scan_demo():
    """Análisis rápido de la home. Sin cuenta, o sobre un dominio que el usuario
    no ha verificado, es pasivo (solo información pública). No guarda resultados."""
    data     = request.get_json(silent=True) or {}
    objetivo = (data.get("objetivo") or "").strip()[:200]
    if not objetivo:
        return jsonify({"error": "Introduce un dominio"}), 400
    dominio = _normalizar_dominio(objetivo)
    if not dominio:
        return jsonify({"error": "Dominio inválido"}), 400
    _bloqueo = _validar_objetivo(dominio, current_user)
    if _bloqueo:
        return _bloqueo
    objetivo = objetivo.lower() if "@" in objetivo else dominio

    resultado = _ejecutar_analisis(objetivo, dominio, current_user)
    resultado["demo"] = True
    _registrar_escaneo_anonimo(dominio, resultado["riesgo"], resultado["label"])
    return jsonify(resultado)


@app.route("/api/auditar-cms", methods=["POST"])
@limiter.limit("20 per hour")
def auditar_cms():
    """Auditoría de las landings /auditoria-wordpress y /auditoria-prestashop.
    Pasiva para visitantes y dominios sin verificar; completa si el usuario ha
    verificado el dominio."""
    data     = request.get_json(silent=True) or {}
    objetivo = (data.get("objetivo") or "").strip()[:200]
    if not objetivo:
        return jsonify({"error": "Introduce un dominio"}), 400
    dominio = _normalizar_dominio(objetivo)
    if not dominio:
        return jsonify({"error": "Dominio inválido"}), 400
    _bloqueo = _validar_objetivo(dominio, current_user)
    if _bloqueo:
        return _bloqueo

    resultado = _ejecutar_analisis(dominio, dominio, current_user, subdominios=False)
    resultado["demo"] = True
    _registrar_escaneo_anonimo(dominio, resultado["riesgo"], resultado["label"])
    return jsonify(resultado)


@app.route("/api/lead-unlock", methods=["POST"])
@limiter.limit("10 per hour")
def lead_unlock():
    """Envía por email el informe pasivo de un dominio. El seguimiento comercial
    solo si el visitante marca la casilla (desmarcada por defecto)."""
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()[:120]
    objetivo = (data.get("objetivo") or "").strip()[:200]
    acepta_comercial = data.get("acepta_comercial") is True

    if not email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Email inválido"}), 400
    if not objetivo:
        return jsonify({"error": "Introduce un dominio"}), 400
    if not _verify_turnstile(data.get("cf-turnstile-response", ""), _ip_cliente()):
        return jsonify({"error": "Verificación anti-bot fallida. Recarga la página e inténtalo de nuevo."}), 403
    # Nadie puede usar el formulario para inundar de emails una dirección ajena.
    hace_un_dia = datetime.utcnow() - timedelta(days=1)
    if Lead.query.filter(Lead.email == email, Lead.created_at >= hace_un_dia).count() >= 3:
        return jsonify({"error": "Ya hemos enviado varios informes a este email hoy. Inténtalo mañana."}), 429

    dominio = _normalizar_dominio(objetivo)
    if not dominio:
        return jsonify({"error": "Dominio inválido"}), 400
    _bloqueo = _validar_objetivo(dominio)
    if _bloqueo:
        return _bloqueo

    # Lo pide un visitante sin cuenta: siempre análisis pasivo.
    resultado = engine.puntuar(engine.analizar(dominio, modo=engine.MODO_PASIVO, subdominios=False))
    resultado["objetivo"] = dominio
    resultado["demo"] = True
    riesgo, label = resultado["riesgo"], resultado["label"]
    puertos, dns, ssl_info = resultado["puertos"], resultado["dns"], resultado["ssl"]

    # Guardar lead (no bloquea si falla)
    try:
        ya_user = User.query.filter_by(email=email).first()
        lead = Lead(
            email=email, objetivo=objetivo, dominio=dominio,
            riesgo=riesgo, resultado=resultado,
            ip=_hash_ip_visitante(),
            user_agent=(request.headers.get('User-Agent') or '')[:255],
            convertido=bool(ya_user),
            acepta_comercial=acepta_comercial,
            consentimiento_at=datetime.utcnow() if acepta_comercial else None,
        )
        db.session.add(lead)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"No se pudo guardar el lead: {e}")

    # Email con el informe pedido
    try:
        enviar_email_lead(email, dominio, riesgo, label, puertos, dns, ssl_info,
                          es_followup=False, acepta_comercial=acepta_comercial)
    except Exception as e:
        logger.warning(f"No se pudo enviar el email al lead: {e}")

    return jsonify(resultado)

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
    """Derecho de acceso y portabilidad (RGPD arts. 15 y 20): todos los datos de la cuenta en JSON."""
    user = current_user
    uid = user.id

    def fila(obj, campos):
        return {c: (getattr(obj, c).isoformat() if isinstance(getattr(obj, c), datetime) else getattr(obj, c))
                for c in campos}

    scans = Scan.query.filter_by(user_id=uid).order_by(Scan.timestamp.desc()).all()
    data = {
        "exportado_en": datetime.utcnow().isoformat() + "Z",
        "usuario": {
            "id": user.id, "email": user.email, "empresa": user.empresa,
            "email_verified": user.email_verified,
            "fecha_registro": user.created_at.isoformat() if user.created_at else None,
            "ultimo_acceso": user.last_login.isoformat() if user.last_login else None,
            "ultima_ip_acceso": user.last_login_ip,
            "acepta_comercial": bool(user.acepta_comercial),
            "scan_hora": user.scan_hora, "scan_dias": user.scan_dias,
            "slack_webhook_configurado": bool(user.slack_webhook),
            "webhook_configurado": bool(user.custom_webhook),
            "2fa_activado": bool(user.totp_enabled),
        },
        "dominios": [fila(d, ["dominio", "activo", "added_at", "autorizacion_at", "verificado", "verif_metodo", "verificado_at"])
                     for d in Domain.query.filter_by(user_id=uid).all()],
        "escaneos": [{"id": s.id, "objetivo": s.objetivo, "dominio": s.dominio, "riesgo": s.riesgo,
                      "label": s.label, "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                      "resultado": s.resultado} for s in scans],
        "notificaciones": [fila(n, ["tipo", "titulo", "mensaje", "leida", "created_at"])
                           for n in Notification.query.filter_by(user_id=uid).all()],
        "registro_de_actividad": [fila(a, ["evento", "ip", "user_agent", "detalles", "created_at"])
                                  for a in AuditLog.query.filter_by(user_id=uid).all()],
        "intentos_de_acceso": [fila(l, ["ip", "user_agent", "exito", "razon", "created_at"])
                               for l in LoginAttempt.query.filter_by(email=user.email).all()],
        "facturas": [fila(f, ["numero", "concepto", "importe", "moneda", "estado", "created_at"])
                     for f in Invoice.query.filter_by(user_id=uid).all()],
    }
    buf = io.BytesIO(json.dumps(data, indent=2, ensure_ascii=False, default=str).encode("utf-8"))
    nombre = f"reconbase_mis_datos_{datetime.utcnow().strftime('%Y%m%d')}.json"
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name=nombre)


def _borrar_datos_usuario(user):
    """Borra la cuenta y todos sus datos en UNA transacción (RGPD art. 17).
    Las facturas emitidas se conservan (obligación legal de conservación),
    desvinculadas de la cuenta y con una copia de los datos del cliente."""
    uid, email = user.id, (user.email or "").lower()
    for factura in Invoice.query.filter_by(user_id=uid).all():
        factura.cliente_email = factura.cliente_email or email
        factura.cliente_nombre = factura.cliente_nombre or user.empresa
        factura.user_id = None
    for modelo in (Scan, Domain, SSLCheck, UptimeCheck, Notification, DNSRecord,
                   TechDetection, IPReputation, AuditLog):
        modelo.query.filter_by(user_id=uid).delete(synchronize_session=False)
    LoginAttempt.query.filter(db.func.lower(LoginAttempt.email) == email).delete(synchronize_session=False)
    Lead.query.filter(db.func.lower(Lead.email) == email).delete(synchronize_session=False)
    db.session.delete(user)


# ── GDPR: eliminar cuenta (derecho al olvido) ──
@app.route("/api/eliminar-cuenta", methods=["POST"])
@login_required
@limiter.limit("3 per hour")
def eliminar_cuenta():
    """Derecho de supresión (RGPD art. 17): cancela la suscripción antigua si la
    hubiera y borra la cuenta con todos sus datos."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    confirmacion = (data.get("confirmacion") or "").strip().upper()
    if confirmacion != "ELIMINAR":
        return jsonify({"ok": False, "error": "Debes escribir ELIMINAR para confirmar"}), 400
    if not current_user.check_password(password):
        return jsonify({"ok": False, "error": "Contraseña incorrecta"}), 400

    user_id = current_user.id
    email = current_user.email

    # Suscripciones de pago antiguas (ReconBase ya es gratuito): mejor esfuerzo.
    if stripe.api_key:
        try:
            customers = stripe.Customer.list(email=email, limit=1)
            if customers.data:
                subs = stripe.Subscription.list(customer=customers.data[0].id, status="active", limit=10)
                for sub in subs.data:
                    try:
                        stripe.Subscription.delete(sub.id)
                    except Exception as e:
                        logger.error(f"[RGPD] Error cancelando la suscripción {sub.id}: {e}")
        except Exception as e:
            logger.error(f"[RGPD] Error de Stripe al eliminar la cuenta {user_id}: {e}")

    try:
        user = db.session.get(User, user_id)
        logout_user()
        _borrar_datos_usuario(user)
        db.session.commit()
        logger.info(f"[RGPD] Cuenta {user_id} eliminada con todos sus datos")
    except Exception as e:
        db.session.rollback()
        logger.exception(f"[RGPD] Error eliminando la cuenta {user_id}: {e}")
        return jsonify({"ok": False, "error": "No se pudo eliminar la cuenta. Escríbenos a hola@reconbase.es y la eliminamos nosotros."}), 500

    return jsonify({"ok": True, "msg": "Cuenta eliminada"})

# ── APP ──
@app.route("/app")
def dashboard():
    return redirect(url_for('index'))

# ── SCAN ──
calcular_riesgo = engine.calcular_riesgo
label_riesgo = engine.label_riesgo

# El motor guarda las cabeceras con nombre corto (engine.CABECERAS): HSTS, CSP...
def _cabecera_presente(headers, nombre):
    headers = headers or {}
    return bool(headers.get(nombre) or headers.get(engine.CABECERAS.get(nombre, nombre)))

def sanitizar(texto):
    return str(texto).encode("ascii","ignore").decode("ascii")

def enviar_email_onboarding(destinatario):
    def _send():
        try:
            cuerpo = (
                "Hola,\n\n"
                "Te registraste en ReconBase hace 2 dias y todavia no has analizado tu dominio.\n\n"
                "En unos minutos puedes saber:\n"
                "  - Si tu dominio puede ser suplantado para enviar emails falsos (SPF y DMARC)\n"
                "  - Como estan tu certificado SSL y tus cabeceras de seguridad\n"
                "  - Si verificas el dominio, tambien sus puertos y ficheros expuestos\n\n"
                "Entra y analiza tu dominio gratis:\n"
                f"{BASE_URL}/\n\n"
                "--\nReconBase\n"
                + _pie_comercial_texto(destinatario, "Recibes este email porque tienes cuenta en ReconBase y aceptaste recibir consejos.")
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
                f"Si el dominio es tuyo, verificalo en tu perfil para hacer el analisis completo y activar la vigilancia automatica (gratis):\n"
                f"{BASE_URL}/perfil#dominios\n\n"
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

# ─── Comunicaciones comerciales (LSSI art. 21) ────────────────────────────────
# · Leads: solo reciben el informe que piden; el seguimiento, solo si marcaron
#   la casilla (desmarcada por defecto).
# · Usuarios: emails de servicio siempre; los comerciales (consejos, reenganche)
#   solo si no se opusieron en el registro o en su perfil.
# · Cada email comercial lleva un enlace de baja firmado.
from itsdangerous import URLSafeSerializer, BadSignature

_firmante_baja = URLSafeSerializer(app.secret_key, salt="baja-comercial")


def _url_baja(email):
    return f"{BASE_URL}/baja/{_firmante_baja.dumps((email or '').strip().lower())}"


def _pie_comercial_html(email, motivo):
    return (f"<p style='font-size:.75rem;color:#64748B;margin-top:1.5rem'>{motivo} "
            f"<a href='{_url_baja(email)}' style='color:#64748B'>Darme de baja de estos emails</a>.</p>")


def _pie_comercial_texto(email, motivo):
    return f"\n\n{motivo} Para darte de baja: {_url_baja(email)}\n"


def _dar_de_baja(email):
    email = (email or "").strip().lower()
    n = 0
    for lead in Lead.query.filter_by(email=email).all():
        lead.unsubscribed = True
        lead.acepta_comercial = False
        n += 1
    user = User.query.filter_by(email=email).first()
    if user:
        user.acepta_comercial = False
        user.comercial_actualizado_at = datetime.utcnow()
        n += 1
    db.session.commit()
    return n


def _problemas_resumen(puertos, dns_info, ssl_info, modo=None):
    problemas = []
    crit = [p for p in (puertos or []) if p.get('servicio') in engine.SERVICIOS_CRITICOS]
    if crit:
        problemas.append(f"🔴 <strong>{len(crit)} servicio(s) crítico(s) expuesto(s)</strong>: "
                         + ", ".join(_html_escape(f"{p['puerto']}/{p['servicio']}") for p in crit[:4]))
    if dns_info:
        if not dns_info.get('SPF') and not dns_info.get('DMARC'):
            problemas.append("🔴 <strong>Sin SPF ni DMARC</strong>: es fácil enviar emails haciéndose pasar por tu dominio")
        elif not dns_info.get('DMARC'):
            problemas.append("🟡 <strong>DMARC no configurado</strong>: riesgo de suplantación de tu dominio")
        elif not dns_info.get('SPF'):
            problemas.append("🟡 <strong>SPF no configurado</strong>: riesgo de suplantación de tu dominio")
    if ssl_info and ssl_info.get('caducado'):
        problemas.append("🔴 <strong>Certificado SSL caducado</strong>: los navegadores avisan de inseguridad")
    elif ssl_info and ssl_info.get('pronto_a_caducar'):
        problemas.append(f"🟡 <strong>El SSL caduca en {ssl_info.get('dias_restantes', '?')} días</strong>")
    return problemas


def enviar_email_lead(destinatario, objetivo, riesgo, label, puertos, dns_info, ssl_info,
                      es_followup=False, acepta_comercial=False):
    """Informe pedido desde la home (transaccional). Con es_followup=True es el
    recordatorio de las 48 h, que solo se envía a leads con consentimiento."""
    def _send():
        try:
            from urllib.parse import quote
            color = "#EF4444" if riesgo >= 70 else "#F59E0B" if riesgo >= 40 else "#22C55E"
            obj = _html_escape(objetivo)
            problemas = _problemas_resumen(puertos, dns_info, ssl_info)
            problemas_html = ("<ul style='margin:.5rem 0 1rem;padding-left:1.2rem;line-height:1.8'>"
                              + "".join(f"<li>{p}</li>" for p in problemas[:5]) + "</ul>") if problemas else \
                "<p style='color:#22C55E'>✓ No hemos encontrado problemas en lo analizado.</p>"
            if es_followup:
                subject = f"¿Has podido revisar la seguridad de {objetivo}?"
                titulo = f"Recordatorio: el análisis de {obj}"
                intro = (f"Hace un par de días analizaste <strong>{obj}</strong> en ReconBase "
                         f"(riesgo <strong style='color:{color}'>{riesgo}%</strong>). Estos eran los puntos a revisar:")
            else:
                subject = f"Tu análisis de {objetivo} — riesgo {riesgo}%"
                titulo = f"Análisis de {obj}: {riesgo}% de riesgo"
                intro = (f"Este es el resumen del análisis de <strong>{obj}</strong> que has pedido en ReconBase "
                         f"(nivel de riesgo <strong style='color:{color}'>{riesgo}% — {_html_escape(label)}</strong>).")
            cuerpo = (
                f"<p>{intro}</p>{problemas_html}"
                "<p style='font-size:.85rem;color:#64748B'>Ha sido un análisis pasivo: solo información pública "
                "(DNS, certificado, cabeceras y lo que la web publica). Si el dominio es tuyo, con una cuenta gratuita "
                "puedes verificarlo y hacer el análisis completo, guardar el historial y recibir alertas.</p>"
            )
            if acepta_comercial:
                cuerpo += _pie_comercial_html(destinatario, "Recibes este email porque pediste el informe en reconbase.es y aceptaste recibir consejos.")
            else:
                cuerpo += ("<p style='font-size:.75rem;color:#64748B;margin-top:1.5rem'>Recibes este email porque pediste "
                           "este informe en reconbase.es. No te enviaremos nada más.</p>")
            cta_url = f"{BASE_URL}/register?email={quote(destinatario)}&target={quote(objetivo)}"
            with app.app_context():
                send_html_email(destinatario, subject, titulo, cuerpo, cta_url=cta_url, cta_text="Crear cuenta gratis")
                logger.info(f"[Lead{'Followup' if es_followup else ''}] Email enviado · {objetivo}")
        except Exception as e:
            logger.warning(f"[Lead email] Error: {e}")
    threading.Thread(target=_send, daemon=True).start()


def enviar_email_lead_dia7(destinatario, objetivo, riesgo, problemas_lista):
    """Día 7 (solo con consentimiento): por qué importan SPF y DMARC y cómo configurarlos."""
    def _send():
        try:
            from urllib.parse import quote
            problemas_html = ""
            if problemas_lista:
                problemas_html = ("<p>En tu análisis de <strong>" + _html_escape(objetivo) + "</strong> vimos:</p>"
                                  "<ul style='margin:.6rem 0 1rem;padding-left:1.2rem;line-height:1.8;color:#94A3B8'>"
                                  + "".join(f"<li>{p}</li>" for p in problemas_lista[:3]) + "</ul>")
            cuerpo = (
                "<p>Una de las estafas más habituales contra pequeñas empresas es el email que parece venir de un "
                "proveedor o de tu propia empresa y pide un pago o unas credenciales.</p>"
                "<p>Los registros <strong>SPF</strong> y <strong>DMARC</strong> de tu DNS ayudan a que los servidores de "
                "correo rechacen esos emails falsos. Configurarlos suele llevar pocos minutos.</p>"
                f"{problemas_html}"
                f"<p>Puedes comprobar tu dominio y ver qué registros añadir en <a href='{BASE_URL}/comprobar-dmarc-spf'>nuestra herramienta gratuita</a>.</p>"
                + _pie_comercial_html(destinatario, "Recibes este email porque aceptaste recibir consejos de ReconBase.")
            )
            with app.app_context():
                send_html_email(destinatario, "Cómo evitar que suplanten el email de tu empresa",
                                "SPF y DMARC: 5 minutos que evitan muchos fraudes", cuerpo,
                                cta_url=f"{BASE_URL}/register?email={quote(destinatario)}&target={quote(objetivo)}",
                                cta_text="Crear cuenta gratis")
                logger.info("[LeadDia7] Email enviado")
        except Exception as e:
            logger.warning(f"[LeadDia7] Error: {e}")
    threading.Thread(target=_send, daemon=True).start()


@app.route("/baja/<token>")
@limiter.limit("60 per hour")
def baja_comercial(token):
    try:
        email = _firmante_baja.loads(token)
    except BadSignature:
        return render_template("verify_result.html", ok=False, titulo_pagina="Baja",
                               msg="El enlace no es válido. Escríbenos a hola@reconbase.es y te damos de baja."), 400
    try:
        _dar_de_baja(email)
    except Exception as e:
        db.session.rollback()
        logger.warning(f"[Baja] error: {e}")
    return render_template("verify_result.html", ok=True, titulo_pagina="Baja", titulo="Te hemos dado de baja",
                           msg="No recibirás más consejos ni novedades de ReconBase. Seguirás recibiendo los emails "
                               "necesarios del servicio si tienes cuenta. Si fue un error, puedes volver a activarlos en tu perfil.")


@app.route("/api/unsubscribe", methods=["GET"])
@limiter.limit("60 per hour")
def api_unsubscribe():
    """Enlace de baja de los emails enviados antes de los enlaces firmados.
    Se mantiene para que esos enlaces sigan funcionando."""
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        return ("Falta email", 400)
    try:
        _dar_de_baja(email)
    except Exception as e:
        db.session.rollback()
        logger.warning(f"[Unsubscribe] error: {e}")
    return render_template("verify_result.html", ok=True, titulo_pagina="Baja", titulo="Te hemos dado de baja",
                           msg="No recibirás más emails de seguimiento de ReconBase.")


@app.route("/api/preferencias", methods=["GET", "POST"])
@login_required
def preferencias_comerciales():
    user = db.session.get(User, current_user.id)
    if request.method == "POST":
        user.acepta_comercial = bool((request.get_json(silent=True) or {}).get("acepta_comercial"))
        user.comercial_actualizado_at = datetime.utcnow()
        db.session.commit()
        _registrar_audit(user.id, "preferencias_email", "acepta" if user.acepta_comercial else "rechaza")
    return jsonify({"ok": True, "acepta_comercial": bool(user.acepta_comercial)})


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
                f"<td style='padding:8px 12px;color:#E2EDF8;font-weight:700'>{_html_escape(objetivo)}</td></tr>"
                f"<tr><td style='padding:8px 12px;color:#64748B;font-size:13px'>Riesgo</td>"
                f"<td style='padding:8px 12px;color:{color_riesgo};font-weight:700;font-size:18px'>{riesgo}% — {nivel}</td></tr>"
                f"</table><br>"
                f"{cambio_html}"
                f"{'<p><strong>Puntos a revisar:</strong></p><ul>' + desglose_html + '</ul>' if desglose_html else ''}"
                f"{'<p style=\"color:#94A3B8;font-size:12px\">' + HIBP_ATRIBUCION + '.</p>' if desglose.get('Filtraciones') else ''}"
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
@require_verified
@limiter.limit("20 per hour")
def scan():
    data     = request.get_json(silent=True) or {}
    raw      = (data.get("objetivo") or "").strip()[:200]
    if not raw:
        return jsonify({"error": "Objetivo vacío"}), 400
    dominio = _normalizar_dominio(raw)
    if not dominio:
        return jsonify({"error": "Dominio no válido"}), 400
    _bloqueo = _validar_objetivo(dominio, current_user)
    if _bloqueo:
        return _bloqueo
    objetivo = raw.lower() if "@" in raw else dominio
    es_ip = engine.es_ip(dominio)

    resultado = _ejecutar_analisis(objetivo, dominio, current_user)
    riesgo, label, desglose = resultado["riesgo"], resultado["label"], resultado["desglose"]
    puertos, subs = resultado["puertos"], resultado["subs"]

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
    q = Scan.query.filter_by(user_id=current_user.id)
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
    return jsonify({**(scan.resultado or {}), "scan_id": scan.id})

@app.route("/api/pdf", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def generar_pdf():
    """Informe ejecutivo de seguridad — diseño profesional con todos los módulos
    del escáner (puertos, DNS, headers, SSL, CMS/WordPress, filtraciones,
    subdominios, OS) + cálculo de riesgo desglosado + plan de remediación."""
    if not PDF_OK:
        return jsonify({"error": "fpdf2 no instalado"}), 500
    # El informe se genera SIEMPRE a partir del escaneo guardado: si aceptáramos
    # los datos del navegador, cualquiera podría fabricar un PDF con la marca de
    # ReconBase y resultados inventados.
    try:
        scan_id = int((request.get_json(silent=True) or {}).get("scan_id") or 0)
    except (TypeError, ValueError):
        scan_id = 0
    scan_obj = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first() if scan_id else None
    if not scan_obj or not scan_obj.resultado:
        return jsonify({"error": "Escaneo no encontrado. Lanza un análisis desde el escáner para generar el informe."}), 404
    datos = dict(scan_obj.resultado)
    datos.setdefault("timestamp", scan_obj.timestamp.strftime("%d/%m/%Y %H:%M") if scan_obj.timestamp else "")

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

    if datos.get('modo') == 'pasivo':
        pdf.set_x(75)
        pdf.cell(0, 5, sanitizar("Análisis pasivo (parcial): no incluye puertos, rutas ni ficheros"), ln=1)

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
    miss_h = [k for k in ['Content-Security-Policy','X-Frame-Options','X-Content-Type-Options'] if not _cabecera_presente(headers, k)]
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
    if datos.get('modo') == 'pasivo':
        body("No comprobados: el escaneo de puertos solo se hace en dominios cuyo titular los ha verificado.")
    elif puertos:
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
        present = _cabecera_presente(headers, hname)
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
    hibp_estado = datos.get('hibp_estado') or ('consultado' if leaks_n else 'no_aplica')
    if hibp_estado != 'consultado':
        body("No consultadas: solo se comprueban el email del propio usuario o emails de un dominio verificado.")
    elif leaks_n > 0:
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
    if hibp_estado == 'consultado':
        body(HIBP_ATRIBUCION + ".")
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
    pdf.set_fill_color(*BG_SOFT)
    pdf.set_draw_color(*BORDER)
    y0 = pdf.get_y()
    pdf.rect(15, y0, 180, 24, "DF")
    pdf.set_xy(20, y0 + 4)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*TEXT_DARK)
    pdf.cell(0, 5, sanitizar("Alcance de este informe"), ln=1)
    pdf.set_x(20)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.multi_cell(170, 4, sanitizar(
        "Análisis automático y externo realizado en la fecha indicada. Detecta problemas habituales, "
        "pero no garantiza la ausencia de vulnerabilidades ni sustituye a una auditoría profesional. "
        "¿Dudas? Escríbenos a hola@reconbase.es."))

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
                f"--\nReconBase - Vigilancia automatica\n"
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

        for user in User.query.all():
            # Global schedule defaults
            user_dias_str = user.scan_dias or ''
            user_dias = [int(d) for d in user_dias_str.split(',') if d.strip()] if user_dias_str else []
            user_hora = user.scan_hora

            # Solo dominios activos y VERIFICADOS: la vigilancia hace el análisis
            # completo (puertos, rutas no enlazadas) y eso exige la autorización
            # del titular. Los no verificados siguen con la monitorización pasiva.
            dominios_user = Domain.query.filter_by(user_id=user.id, activo=True, verificado=True).all()

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
                    resultado = engine.puntuar(engine.analizar(dominio, modo=engine.MODO_COMPLETO))
                    resultado["objetivo"] = objetivo
                    resultado["automatico"] = True
                    riesgo, label, desglose = resultado["riesgo"], resultado["label"], resultado["desglose"]
                    puertos, subs, ps_audit = resultado["puertos"], resultado["subs"], resultado["ps"]
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
                                        f"<p><strong>Evidencia detectada:</strong><br>{_html_escape(ev)}</p>"
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
                f"--\nReconBase - Vigilancia automática\n"
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
    """Alerta cuando el SSL del último dominio analizado caduca en ≤30 días."""
    with app.app_context():
        for user in User.query.all():
            ultimo = Scan.query.filter_by(user_id=user.id).order_by(Scan.timestamp.desc()).first()
            if not ultimo or not ultimo.resultado:
                continue
            ssl_info = ultimo.resultado.get('ssl', {})
            dias = ssl_info.get('dias_restantes')
            if dias is not None and dias in (1, 3, 7, 14, 30):
                enviar_alerta_ssl(user.email, ultimo.dominio, dias)

def cron_resumen_semanal():
    """Cada lunes a las 8:00 envía resumen de la semana anterior a usuarios activos."""
    with app.app_context():
        ahora = datetime.utcnow()
        if ahora.weekday() != 0:   # 0 = lunes
            return
        desde = ahora - timedelta(days=7)
        usuarios = User.query.all()
        for user in usuarios:
            scans = Scan.query.filter(
                Scan.user_id == user.id,
                Scan.timestamp >= desde,
                Scan.timestamp <= ahora
            ).all()
            if not scans:
                continue
            riesgo_prom = int(sum(s.riesgo for s in scans) / len(scans))
            dominios = list({s.dominio for s in scans})
            problemas = [s for s in scans if s.riesgo >= 40]

            def _send(email, empresa, n_scans, r_prom, doms, n_prob):
                try:
                    cuerpo = (
                        f"Hola {empresa},\n\n"
                        f"Resumen de seguridad de esta semana en ReconBase.\n\n"
                        f"{'='*50}\n"
                        f"ESCANEOS ESTA SEMANA: {n_scans}\n"
                        f"RIESGO PROMEDIO:      {r_prom}%\n"
                        f"DOMINIOS ANALIZADOS:  {', '.join(doms[:5]) if doms else 'Ninguno'}\n"
                        + (f"ALERTAS DETECTADAS:   {n_prob} escaneo(s) con riesgo ≥40%\n" if n_prob else "")
                        + f"{'='*50}\n\n"
                        f"Entra al dashboard para ver el historial completo:\n"
                        f"{BASE_URL}/\n\n"
                        f"--\nReconBase - Resumen semanal de seguridad\n"
                        f"Para no recibir estos emails, ajusta tus notificaciones en el perfil.\n"
                    )
                    with app.app_context():
                        mail.send(Message(
                            subject=f"[ReconBase] Resumen semanal de {empresa} — {ahora.strftime('%d/%m/%Y')}",
                            recipients=[email],
                            body=cuerpo
                        ))
                        logger.info(f"[Semanal] Resumen enviado a {email}")
                except Exception as e:
                    logger.warning(f"[Semanal] Error resumen semanal {email}: {e}")

            import threading as _th
            _th.Thread(target=_send, args=(user.email, user.empresa, len(scans),
                                           riesgo_prom, dominios, len(problemas)),
                       daemon=True).start()

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

def enviar_email_reengagement(user):
    email_destino  = user.email
    nombre_empresa = user.empresa
    base_url       = BASE_URL
    def _send(email, empresa):
        try:
            cuerpo = (
                f"Hola {empresa},\n\n"
                f"Hace tiempo que no analizas tu dominio en ReconBase.\n\n"
                f"En unas semanas pueden cambiar cosas: un certificado a punto de caducar, un cambio en el DNS\n"
                f"o un plugin que ha quedado desactualizado.\n\n"
                f"Un analisis tarda un par de minutos y es gratis:\n"
                f"{base_url}/\n\n"
                f"--\nReconBase\n"
                + _pie_comercial_texto(email, "Recibes este email porque tienes cuenta en ReconBase y aceptaste recibir consejos.")
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
            if user.acepta_comercial and ultimo_scan and limite - timedelta(days=1) <= ultimo_scan.timestamp <= limite:
                enviar_email_reengagement(user)

def cron_lead_followup():
    """Seguimiento de leads que ACEPTARON recibir comunicaciones comerciales:
       Stage 1 (48 h): recordatorio del informe
       Stage 2 (7 d):  consejo sobre SPF/DMARC
    Nunca a leads sin consentimiento, dados de baja o que ya tienen cuenta."""
    with app.app_context():
        ahora = datetime.utcnow()
        try:
            todos = Lead.query.filter(
                Lead.acepta_comercial.is_(True),
                Lead.unsubscribed.is_(False),
                Lead.convertido.is_(False),
                Lead.followup_stage < 2,
            ).all()
        except Exception as e:
            logger.warning(f"[LeadFollowup] Query error: {e}")
            return

        for lead in todos:
            try:
                if User.query.filter_by(email=lead.email).first():
                    lead.convertido = True
                    db.session.commit()
                    continue
                dias = (ahora - lead.created_at).total_seconds() / 86400.0
                stage = lead.followup_stage or 0
                next_stage = None
                if stage == 0 and 2.0 <= dias < 3.0:
                    next_stage = 1
                elif stage == 1 and 7.0 <= dias < 8.0:
                    next_stage = 2
                if next_stage is None:
                    continue
                r = lead.resultado or {}
                if next_stage == 1:
                    enviar_email_lead(lead.email, lead.objetivo, lead.riesgo, r.get('label', ''),
                                      r.get('puertos', []), r.get('dns', {}), r.get('ssl', {}),
                                      es_followup=True, acepta_comercial=True)
                else:
                    enviar_email_lead_dia7(lead.email, lead.objetivo, lead.riesgo,
                                           _problemas_resumen([], r.get('dns') or {}, {}))
                lead.followup_stage = next_stage
                lead.followup_sent = True
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
            if user.acepta_comercial and Scan.query.filter_by(user_id=user.id).count() == 0:
                enviar_email_onboarding(user.email)

scheduler = BackgroundScheduler(timezone="Europe/Madrid")
scheduler.add_job(escaneo_automatico,   'cron', minute=0)
scheduler.add_job(cron_onboarding,      'cron', hour=10, minute=0)
scheduler.add_job(cron_ssl_alerts,      'cron', hour=9,  minute=0)
scheduler.add_job(cron_resumen_mensual, 'cron', hour=8,  minute=0)
scheduler.add_job(cron_resumen_semanal, 'cron', hour=8,  minute=5)
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
    max_calls = 100
    if (user.api_calls_month or 0) >= max_calls:
        return jsonify({"error": f"Límite mensual alcanzado ({max_calls} llamadas)"}), 429

    data = request.get_json(silent=True) or {}
    dominio = _normalizar_dominio((data.get("dominio") or "")[:255])
    if not dominio:
        return jsonify({"error": "Dominio no válido"}), 400
    _bloqueo = _validar_objetivo(dominio, user)
    if _bloqueo:
        return _bloqueo

    try:
        # Completo solo si el dueño de la API key ha verificado el dominio.
        resultado = _ejecutar_analisis(dominio, dominio, user, subdominios=False)
        resultado["timestamp"] = datetime.utcnow().isoformat() + "Z"
        scan = Scan(user_id=user.id, objetivo=dominio, dominio=dominio,
                    riesgo=resultado["riesgo"], label=resultado["label"], resultado=resultado)
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
    """Desactiva 2FA (requiere contraseña + código TOTP actual para evitar que
    una sesión robada pueda desactivar el segundo factor sin el dispositivo)."""
    try:
        import pyotp as _pyotp
    except ImportError:
        return jsonify({"ok": False, "error": "pyotp no instalado"}), 500
    data = request.get_json() or {}
    password = data.get("password", "")
    code     = (data.get("code") or "").strip()
    if not current_user.check_password(password):
        return jsonify({"ok": False, "error": "Contraseña incorrecta"}), 400
    if not code:
        return jsonify({"ok": False, "error": "Introduce el código de tu app de autenticación"}), 400
    totp = _pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"ok": False, "error": "Código 2FA incorrecto"}), 400
    user = db.session.get(User, current_user.id)
    user.totp_enabled = False
    user.totp_secret = None
    db.session.commit()
    _registrar_audit(current_user.id, '2fa_disable', "2FA desactivado por el usuario")
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
    # Expirar el desafío 2FA si han pasado más de 5 minutos
    pending_ts = session.get("2fa_pending_ts", 0)
    if time.time() - pending_ts > 300:
        session.pop("2fa_pending_user", None)
        session.pop("2fa_pending_ts", None)
        return jsonify({"ok": False, "error": "El código 2FA expiró. Vuelve a iniciar sesión."}), 400
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
    session.pop("2fa_pending_ts", None)
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
    return render_template(
        "admin.html", aviso_pendientes=len(_usuarios_sin_aviso()), aviso_vigor=AVISO_TERMINOS_VIGOR,
        total_users=total_users, total_scans=total_scans,
        users_pro=users_pro, users_trial=users_trial,
        scans_hoy=scans_hoy, scans_mes=scans_mes,
        users_verified=users_verified,
        recent_users=recent_users, recent_scans=recent_scans,
        now=now)

@app.route("/admin/origen-check")
@login_required
@admin_required
def admin_origen_check():
    """Comprueba si la cabecera secreta de Cloudflare llega bien, antes de activar ORIGIN_LOCK."""
    return jsonify({
        "origin_secret_configurado": bool(ORIGIN_SECRET),
        "peticion_via_cloudflare_verificada": _via_cloudflare(),
        "ip_usada_para_rate_limit": _ip_cliente(),
        "cf_connecting_ip": request.headers.get("CF-Connecting-IP"),
        "remote_addr_proxy": request.remote_addr,
        "origin_lock_activo": ORIGIN_LOCK and bool(ORIGIN_SECRET),
        "redis_configurado": bool(os.getenv("REDIS_URL")),
    })


@app.route("/admin/stripe-check")
@login_required
@admin_required
def admin_stripe_check():
    """Diagnóstico rápido: consulta a Stripe el precio REAL que se está
    cobrando por los price_id configurados y lo compara con lo que anuncia
    la web (9€/mes, 90€/año). Sirve para verificar que web y cobro coinciden."""
    from flask import Response
    ESPERADO_MES  = 9.0
    ESPERADO_ANIO = 90.0
    filas = []
    def _precio(label, price_id, esperado):
        if not price_id:
            return {"label": label, "price_id": "(no configurado)", "importe": None,
                    "moneda": "", "esperado": esperado, "ok": False, "error": "Variable de entorno vacía"}
        try:
            p = stripe.Price.retrieve(price_id)
            importe = (p.get("unit_amount") or 0) / 100.0
            moneda  = (p.get("currency") or "eur").upper()
            return {"label": label, "price_id": price_id, "importe": importe,
                    "moneda": moneda, "esperado": esperado,
                    "ok": abs(importe - esperado) < 0.01, "error": None}
        except Exception as e:
            return {"label": label, "price_id": price_id, "importe": None,
                    "moneda": "", "esperado": esperado, "ok": False, "error": str(e)[:120]}
    if not stripe.api_key:
        cuerpo = "<p style='color:#DC2626'>STRIPE_SECRET_KEY no configurada — no se puede consultar Stripe.</p>"
    else:
        filas.append(_precio("Pro mensual", STRIPE_PRICE_PRO, ESPERADO_MES))
        filas.append(_precio("Pro anual",   STRIPE_PRICE_PRO_ANUAL, ESPERADO_ANIO))
        rows = ""
        for f in filas:
            if f["error"]:
                estado = f"<span style='color:#DC2626'>⚠ {f['error']}</span>"
                cobra  = "—"
            elif f["ok"]:
                estado = "<span style='color:#16A34A;font-weight:700'>✓ CORRECTO</span>"
                cobra  = f"{f['importe']:.2f} {f['moneda']}"
            else:
                estado = f"<span style='color:#DC2626;font-weight:700'>✗ NO COINCIDE (esperado {f['esperado']:.2f}€)</span>"
                cobra  = f"<strong style='color:#DC2626'>{f['importe']:.2f} {f['moneda']}</strong>"
            rows += (f"<tr><td style='padding:.6rem 1rem;border-bottom:1px solid #E2E8F0'>{f['label']}</td>"
                     f"<td style='padding:.6rem 1rem;border-bottom:1px solid #E2E8F0;font-family:monospace;font-size:.8rem'>{f['price_id']}</td>"
                     f"<td style='padding:.6rem 1rem;border-bottom:1px solid #E2E8F0'>{cobra}</td>"
                     f"<td style='padding:.6rem 1rem;border-bottom:1px solid #E2E8F0'>{estado}</td></tr>")
        cuerpo = (f"<table style='border-collapse:collapse;width:100%;max-width:820px'>"
                  f"<thead><tr style='background:#F1F5F9'>"
                  f"<th style='text-align:left;padding:.6rem 1rem'>Plan</th>"
                  f"<th style='text-align:left;padding:.6rem 1rem'>price_id (Stripe)</th>"
                  f"<th style='text-align:left;padding:.6rem 1rem'>Cobra realmente</th>"
                  f"<th style='text-align:left;padding:.6rem 1rem'>Estado</th></tr></thead>"
                  f"<tbody>{rows}</tbody></table>")
    html = (f"<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Stripe check — ReconBase Admin</title>"
            f"<style>body{{font-family:Inter,system-ui,sans-serif;background:#F8FAFC;color:#0F172A;padding:2.5rem 6%;line-height:1.6}}"
            f"h1{{font-size:1.4rem}}a{{color:#16A34A}}</style></head><body>"
            f"<h1>Comprobación de precios en Stripe</h1>"
            f"<p>Compara el precio real que cobra Stripe con lo que anuncia la web (<strong>9€/mes · 90€/año</strong>).</p>"
            f"{cuerpo}"
            f"<p style='margin-top:1.5rem;font-size:.85rem;color:#64748B'>Si aparece <strong>NO COINCIDE</strong>: crea el precio correcto en el panel de Stripe y actualiza la variable de Railway "
            f"(<code>STRIPE_PRICE_PRO</code> / <code>PRICE_PRO_ANUAL</code>). Luego recarga esta página.</p>"
            f"<p style='margin-top:1rem'><a href='/admin/metricas'>← Volver a métricas</a></p>"
            f"</body></html>")
    return Response(html, mimetype="text/html")


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


# ─── Aviso a los usuarios del cambio de términos (nov. 2026) ──────────────────
# Lo envía el administrador a mano desde /admin. Cada envío queda en el registro
# de auditoría del usuario, así nadie lo recibe dos veces.
AVISO_TERMINOS_EVENTO = "aviso_terminos_2026_11"
AVISO_TERMINOS_VIGOR = "2 de diciembre de 2026"


def _enviar_aviso_terminos(user):
    cuerpo = (
        f"<p>Hola,</p>"
        f"<p>Te escribimos porque tienes una cuenta en ReconBase. Hemos actualizado los "
        f"<a href='{BASE_URL}/terms'>Términos de Servicio</a> y la <a href='{BASE_URL}/privacy'>Política de Privacidad</a>. "
        f"Los cambios entran en vigor el <strong>{AVISO_TERMINOS_VIGOR}</strong>. Lo principal:</p>"
        "<ul>"
        "<li><strong>ReconBase es gratuito.</strong> Ya no hay planes de pago: todas las cuentas tienen todas las funciones. "
        "Si tenías una suscripción activa, puedes cancelarla desde tu perfil.</li>"
        "<li><strong>Verificación de dominios.</strong> Las comprobaciones activas (puertos, rutas no enlazadas y ficheros expuestos) "
        "y la vigilancia automática solo se hacen en dominios que verifiques como tuyos (con un registro DNS, una etiqueta en tu web "
        "o un fichero). En el resto hacemos un análisis pasivo con información pública. Si tenías la vigilancia activa, "
        "<strong>verifica tus dominios desde tu perfil</strong> para que siga funcionando.</li>"
        "<li><strong>Filtraciones (Have I Been Pwned):</strong> solo se consulta tu propio email o los de tus dominios verificados.</li>"
        "<li><strong>Emails:</strong> puedes decidir en tu perfil si quieres recibir consejos y novedades. Los avisos del servicio "
        "te seguirán llegando.</li>"
        "<li><strong>Privacidad:</strong> tus datos se alojan en la UE (Ámsterdam) y explicamos con detalle qué guardamos y durante cuánto tiempo.</li>"
        "</ul>"
        "<p>Si no estás de acuerdo, puedes eliminar tu cuenta desde tu perfil en cualquier momento. "
        "Si tienes dudas, responde a este email o escribe a hola@reconbase.es.</p>"
    )
    send_html_email(user.email, "Cambios en ReconBase: ahora es gratis y actualizamos los términos",
                    "Actualizamos los términos de ReconBase", cuerpo,
                    BASE_URL + "/perfil#dominios", "Verificar mis dominios")


def _usuarios_sin_aviso():
    avisados = db.session.query(AuditLog.user_id).filter(AuditLog.evento == AVISO_TERMINOS_EVENTO)
    return User.query.filter(~User.id.in_(avisados)).all()


@app.route("/api/admin/aviso-terminos", methods=["POST"])
@login_required
@admin_required
@limiter.limit("10 per hour")
def admin_aviso_terminos():
    data = request.get_json(silent=True) or {}
    if data.get("prueba"):
        try:
            _enviar_aviso_terminos(current_user)
        except Exception as e:
            return jsonify({"ok": False, "error": f"No se pudo enviar: {e}"}), 502
        return jsonify({"ok": True, "enviados": 1, "prueba": True})
    if (data.get("confirmacion") or "").strip().upper() != "ENVIAR":
        return jsonify({"ok": False, "error": "Escribe ENVIAR para confirmar el envío a todos los usuarios"}), 400
    enviados, fallidos = 0, 0
    for user in _usuarios_sin_aviso():
        try:
            _enviar_aviso_terminos(user)
            db.session.add(AuditLog(user_id=user.id, evento=AVISO_TERMINOS_EVENTO, detalles="Aviso de cambio de términos enviado"))
            db.session.commit()
            enviados += 1
        except Exception as e:
            db.session.rollback()
            fallidos += 1
            logger.warning(f"[AvisoTérminos] usuario {user.id}: {e}")
    return jsonify({"ok": True, "enviados": enviados, "fallidos": fallidos})


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
    try:
        _borrar_datos_usuario(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.exception(f"[Admin] Error borrando usuario {uid}: {e}")
        return jsonify({"ok": False, "error": "No se pudo borrar"}), 500
    return jsonify({"ok": True})

# ── MULTI-DOMINIO Y VERIFICACIÓN DE TITULARIDAD ──
VERIF_PREFIJO = "reconbase-verificacion"
VERIF_RUTA_FICHERO = "/.well-known/reconbase-verificacion.txt"
VERIF_DIAS_REVALIDAR = 30


def _instrucciones_verificacion(d):
    token = d.verif_token or ""
    return {
        "dns": {"tipo": "TXT", "nombre": d.dominio, "valor": f"{VERIF_PREFIJO}={token}",
                "nota": "Cubre también los subdominios. Puede tardar unos minutos en propagarse."},
        "meta": {"etiqueta": f'<meta name="{VERIF_PREFIJO}" content="{token}">',
                 "nota": "Dentro del <head> de la página de inicio."},
        "fichero": {"ruta": VERIF_RUTA_FICHERO, "contenido": token,
                    "url": f"https://{d.dominio}{VERIF_RUTA_FICHERO}",
                    "nota": "Un fichero de texto con el código como único contenido."},
    }


def _dominio_json(d):
    return {
        "id": d.id, "dominio": d.dominio, "activo": d.activo,
        "added_at": d.added_at.strftime("%d/%m/%Y") if d.added_at else None,
        "verificado": bool(d.verificado),
        "verif_metodo": d.verif_metodo,
        "verificado_at": d.verificado_at.strftime("%d/%m/%Y") if d.verificado_at else None,
        "instrucciones": None if d.verificado else _instrucciones_verificacion(d),
    }


def _respuesta_del_dominio(url_respuesta, dominio):
    """La página que contiene el código debe ser del propio dominio (o su www),
    no de otro sitio al que redirija."""
    from urllib.parse import urlsplit
    host = (urlsplit(url_respuesta or "").hostname or "").lower()
    return host in (dominio, "www." + dominio)


_RE_META_VERIF = re.compile(r'<meta[^>]+name=["\']reconbase-verificacion["\'][^>]*>', re.I)


def _comprobar_verificacion(dominio, token, metodo):
    """True si el código `token` está publicado en el dominio con `metodo`."""
    if not token or not dominio:
        return False
    if metodo == "dns":
        if engine.es_ip(dominio):
            return False
        esperado = f"{VERIF_PREFIJO}={token}"
        try:
            import dns.resolver as _resolver
            res = _resolver.Resolver()
            res.lifetime = 6
            for rd in res.resolve(dominio, "TXT"):
                if b"".join(rd.strings).decode("utf-8", errors="ignore").strip() == esperado:
                    return True
        except Exception:
            return False
        return False
    if metodo == "meta":
        for scheme in ("https", "http"):
            try:
                r = engine.get_seguro(f"{scheme}://{dominio}/", timeout=8)
            except Exception:
                continue
            if not _respuesta_del_dominio(r.url, dominio):
                return False
            for etiqueta in _RE_META_VERIF.findall((r.text or "")[:300000]):
                m = re.search(r'content=["\']([^"\']+)["\']', etiqueta, re.I)
                if m and m.group(1).strip() == token:
                    return True
            return False
        return False
    if metodo == "fichero":
        for scheme in ("https", "http"):
            try:
                r = engine.peticion_segura(f"{scheme}://{dominio}{VERIF_RUTA_FICHERO}", timeout=8, stream=True)
                contenido = r.raw.read(1024, decode_content=True) or b""
                r.close()
            except Exception:
                continue
            if r.status_code == 200 and _respuesta_del_dominio(r.url, dominio):
                return contenido.decode("utf-8", errors="ignore").strip() == token
        return False
    return False


@app.route("/api/dominios", methods=["GET"])
@login_required
def listar_dominios():
    doms = Domain.query.filter_by(user_id=current_user.id).order_by(Domain.added_at.desc()).all()
    cambios = False
    for d in doms:
        if not d.verif_token:
            d.verif_token = secrets.token_hex(16)
            cambios = True
    if cambios:
        db.session.commit()
    return jsonify({"dominios": [_dominio_json(d) for d in doms]})


@app.route("/api/dominios", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def anadir_dominio():
    data = request.get_json(silent=True) or {}
    dominio = _normalizar_dominio((data.get("dominio") or "")[:255])
    if not dominio:
        return jsonify({"ok": False, "error": "Dominio no válido"}), 400
    if data.get("autorizacion") is not True:
        return jsonify({"ok": False, "error": "Debes declarar que eres titular del dominio o que tienes autorización para analizarlo."}), 400
    _bloqueo = _rechazar_si_interno(dominio)
    if _bloqueo:
        return _bloqueo
    # Limites: free=10, pro=50
    max_doms = 50
    count = Domain.query.filter_by(user_id=current_user.id).count()
    if count >= max_doms:
        plan_txt = f"{max_doms} dominios"
        return jsonify({"ok": False, "error": f"Máximo {plan_txt}. Elimina uno antes de añadir otro."}), 400
    existing = Domain.query.filter_by(user_id=current_user.id, dominio=dominio).first()
    if existing:
        return jsonify({"ok": False, "error": "Este dominio ya está añadido"}), 400
    dom = Domain(user_id=current_user.id, dominio=dominio,
                 autorizacion_at=datetime.utcnow(), verif_token=secrets.token_hex(16))
    db.session.add(dom)
    db.session.commit()
    _registrar_audit(current_user.id, "dominio_anadido", f"{dominio} (declara ser titular o tener autorización)")
    return jsonify({"ok": True, **_dominio_json(dom)})


@app.route("/api/dominios/<int:dom_id>/verificar", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def verificar_dominio(dom_id):
    dom = Domain.query.filter_by(id=dom_id, user_id=current_user.id).first()
    if not dom:
        return jsonify({"ok": False, "error": "Dominio no encontrado"}), 404
    metodo = ((request.get_json(silent=True) or {}).get("metodo") or "").strip()
    if metodo not in ("dns", "meta", "fichero"):
        return jsonify({"ok": False, "error": "Método no válido"}), 400
    if metodo != "fichero" and engine.es_ip(dom.dominio):
        return jsonify({"ok": False, "error": "Las IPs solo se pueden verificar con el fichero."}), 400
    if not dom.verif_token:
        dom.verif_token = secrets.token_hex(16)
        db.session.commit()
    if not _comprobar_verificacion(dom.dominio, dom.verif_token, metodo):
        return jsonify({"ok": False, "error": "No encontramos el código de verificación. Revisa que esté publicado exactamente como se indica y vuelve a intentarlo (los cambios de DNS pueden tardar unos minutos)."}), 400
    ahora = datetime.utcnow()
    dom.verificado, dom.verif_metodo = True, metodo
    dom.verificado_at = dom.verif_comprobado_at = ahora
    if not dom.autorizacion_at:
        dom.autorizacion_at = ahora
    db.session.commit()
    _registrar_audit(current_user.id, "dominio_verificado", f"{dom.dominio} por {metodo}")
    return jsonify({"ok": True, **_dominio_json(dom)})


def cron_reverificar_dominios():
    """Cada día comprueba los dominios verificados hace más de 30 días. Si el
    código ya no está, el dominio vuelve al análisis pasivo y se avisa."""
    with app.app_context():
        limite = datetime.utcnow() - timedelta(days=VERIF_DIAS_REVALIDAR)
        pendientes = Domain.query.filter(
            Domain.verificado.is_(True),
            db.or_(Domain.verif_comprobado_at.is_(None), Domain.verif_comprobado_at < limite),
        ).limit(200).all()
        for d in pendientes:
            try:
                if _comprobar_verificacion(d.dominio, d.verif_token, d.verif_metodo):
                    d.verif_comprobado_at = datetime.utcnow()
                    db.session.commit()
                    continue
                d.verificado = False
                d.verif_comprobado_at = datetime.utcnow()
                db.session.commit()
                _crear_notificacion(d.user_id, "sistema", f"{d.dominio} ya no está verificado",
                                    "No encontramos el código de verificación. Hasta que lo vuelvas a publicar "
                                    "solo haremos el análisis pasivo y la vigilancia automática queda en pausa.",
                                    url="/perfil#dominios")
                user = db.session.get(User, d.user_id)
                if user:
                    send_html_email(
                        user.email, f"[ReconBase] {d.dominio} ya no está verificado",
                        "Tu dominio ha dejado de estar verificado",
                        f"<p>Al revisar <strong>{_html_escape(d.dominio)}</strong> no hemos encontrado el código de verificación.</p>"
                        "<p>Hasta que lo vuelvas a publicar solo haremos el análisis pasivo (información pública) "
                        "y la vigilancia automática queda en pausa.</p>",
                        BASE_URL + "/perfil#dominios", "Volver a verificar")
            except Exception as e:
                db.session.rollback()
                logger.warning(f"[Reverificación] {d.dominio}: {e}")


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
    data = request.get_json() or {}
    user = db.session.get(User, current_user.id)
    slack = (data.get("slack_webhook") or "").strip()
    custom = (data.get("custom_webhook") or "").strip()
    # Validar URLs
    if slack and not slack.startswith("https://hooks.slack.com/"):
        return jsonify({"ok": False, "error": "La URL de Slack debe empezar por https://hooks.slack.com/"}), 400
    if custom and not custom.startswith("https://"):
        return jsonify({"ok": False, "error": "El webhook debe usar HTTPS"}), 400
    if custom:
        from urllib.parse import urlsplit as _us
        try:
            _host_wh = _us(custom).hostname or ""
        except ValueError:
            _host_wh = ""
        if not engine.destino_permitido(_host_wh):
            return jsonify({"ok": False, "error": "La URL del webhook debe apuntar a un servidor público accesible desde internet."}), 400
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
                            "text": "*Evidencia:*\n" + "\n".join(f"• {_slack_escape(e)}" for e in skimmer_evidence) if skimmer_evidence else "*Evidencia:* patrones de ofuscación + referencias a campos de tarjeta"}},
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
            from urllib.parse import urlsplit as _us
            if not engine.destino_permitido(_us(custom_url).hostname or ""):
                raise ValueError("webhook apunta a un destino no permitido")
            webhook_payload = json.dumps(webhook_payload_dict).encode("utf-8")
            req = urllib.request.Request(custom_url, data=webhook_payload,
                                        headers={"Content-Type": "application/json", "User-Agent": "ReconBase/1.0"},
                                        method="POST")
            _opener_sin_redirecciones.open(req, timeout=10)
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
        ip = _ip_cliente()
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
        ip = engine.ip_publica_de(dominio, solo_ipv4=False)
        if not ip:
            raise ValueError("Destino no permitido o no resuelve")
        ctx = _ssl_mod.create_default_context()
        with socket.create_connection((ip, 443), timeout=10) as sock:
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
            r = engine.get_seguro(f"{scheme}://{dominio}", timeout=10)
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
                r = engine.get_seguro(f"{scheme}://{dominio}", timeout=12)
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


# Listas DNSBL consultadas para la reputación de IPs. Las de Spamhaus (zen, CBL)
# solo son gratuitas para uso no comercial y bloquean las consultas desde nubes
# como Railway; SORBS cerró en 2024 y Barracuda exige registro. Se pueden añadir
# otras (p. ej. Spamhaus DQS con su clave) con DNSBL_LISTAS="a.org,b.net".
DNSBL_LISTAS = [l.strip() for l in os.getenv("DNSBL_LISTAS", "bl.spamcop.net").split(",") if l.strip()]


def _check_ip_reputacion(ip):
    """Comprueba la IP contra listas negras DNS (DNSBL)."""
    try:
        import dns.resolver as _resolver
    except ImportError:
        return {'limpio': True, 'listas_negras': []}
    if not engine.es_ip(ip):
        return {'limpio': True, 'listas_negras': []}
    reversed_ip = '.'.join(reversed(ip.split('.')))
    listas = []
    for bl in DNSBL_LISTAS:
        try:
            respuestas = _resolver.resolve(f"{reversed_ip}.{bl}", 'A', lifetime=3)
        except Exception:
            continue
        # 127.0.0.x = listada. 127.255.255.x = la lista rechaza la consulta.
        if any(str(r).startswith("127.0.0.") for r in respuestas):
            listas.append(bl)
    return {'limpio': len(listas) == 0, 'listas_negras': listas}


# ─── Conservación de datos (RGPD art. 5.1.e) ──────────────────────────────────
# Plazos publicados en la política de privacidad. Un cambio aquí debe reflejarse allí.
PLAZOS_CONSERVACION = {
    "intentos_login_dias": 365,
    "audit_log_dias": 365,
    "escaneos_anonimos_dias": 365,
    "leads_sin_consentimiento_dias": 90,
    "leads_con_consentimiento_dias": 730,
    "leads_baja_dias": 30,
    "notificaciones_leidas_dias": 180,
    "uptime_dias": 90,
    "exclusiones_sin_confirmar_dias": 30,
    "webhooks_procesados_dias": 365,
}


def cron_retencion_datos():
    """Borra cada día los datos que han superado su plazo de conservación."""
    with app.app_context():
        ahora = datetime.utcnow()
        P = PLAZOS_CONSERVACION
        hace = lambda dias: ahora - timedelta(days=dias)
        borrados = {}
        try:
            borrados["login_attempts"] = LoginAttempt.query.filter(LoginAttempt.created_at < hace(P["intentos_login_dias"])).delete(synchronize_session=False)
            borrados["audit_logs"] = AuditLog.query.filter(AuditLog.created_at < hace(P["audit_log_dias"])).delete(synchronize_session=False)
            borrados["anonymous_scans"] = AnonymousScan.query.filter(AnonymousScan.created_at < hace(P["escaneos_anonimos_dias"])).delete(synchronize_session=False)
            borrados["leads_sin_consentimiento"] = Lead.query.filter(Lead.acepta_comercial.is_(False), Lead.created_at < hace(P["leads_sin_consentimiento_dias"])).delete(synchronize_session=False)
            borrados["leads_con_consentimiento"] = Lead.query.filter(Lead.acepta_comercial.is_(True), Lead.created_at < hace(P["leads_con_consentimiento_dias"])).delete(synchronize_session=False)
            borrados["leads_baja"] = Lead.query.filter(Lead.unsubscribed.is_(True), Lead.created_at < hace(P["leads_baja_dias"])).delete(synchronize_session=False)
            borrados["notificaciones"] = Notification.query.filter(Notification.leida.is_(True), Notification.created_at < hace(P["notificaciones_leidas_dias"])).delete(synchronize_session=False)
            borrados["uptime"] = UptimeCheck.query.filter(UptimeCheck.checked_at < hace(P["uptime_dias"])).delete(synchronize_session=False)
            borrados["exclusiones"] = ScanOptOut.query.filter(ScanOptOut.confirmado.is_(False), ScanOptOut.created_at < hace(P["exclusiones_sin_confirmar_dias"])).delete(synchronize_session=False)
            borrados["webhooks"] = ProcessedWebhook.query.filter(ProcessedWebhook.created_at < hace(P["webhooks_procesados_dias"])).delete(synchronize_session=False)
            db.session.commit()
            logger.info(f"[Retención] {borrados}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"[Retención] Error: {e}")
        return borrados


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
    scheduler.add_job(cron_reverificar_dominios, 'cron', hour=4, minute=15, id='reverif_dom', replace_existing=True)
    scheduler.add_job(cron_retencion_datos, 'cron', hour=4, minute=45, id='retencion', replace_existing=True)
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
        # ── Verificación de titularidad de dominios ──
        "ALTER TABLE domains ADD COLUMN IF NOT EXISTS autorizacion_at TIMESTAMP",
        "ALTER TABLE domains ADD COLUMN IF NOT EXISTS verificado BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE domains ADD COLUMN IF NOT EXISTS verif_token VARCHAR(64)",
        "ALTER TABLE domains ADD COLUMN IF NOT EXISTS verif_metodo VARCHAR(10)",
        "ALTER TABLE domains ADD COLUMN IF NOT EXISTS verificado_at TIMESTAMP",
        "ALTER TABLE domains ADD COLUMN IF NOT EXISTS verif_comprobado_at TIMESTAMP",
        "CREATE TABLE IF NOT EXISTS scan_opt_outs (id SERIAL PRIMARY KEY, dominio VARCHAR(255) NOT NULL, email VARCHAR(120) NOT NULL, token VARCHAR(64) NOT NULL UNIQUE, confirmado BOOLEAN DEFAULT FALSE NOT NULL, created_at TIMESTAMP DEFAULT NOW(), confirmado_at TIMESTAMP)",
        "CREATE INDEX IF NOT EXISTS idx_scan_opt_outs_dominio ON scan_opt_outs(dominio)",
        # ── Consentimiento de comunicaciones comerciales (LSSI art. 21) ──
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS acepta_comercial BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS comercial_actualizado_at TIMESTAMP",
        "ALTER TABLE leads ADD COLUMN IF NOT EXISTS acepta_comercial BOOLEAN DEFAULT FALSE NOT NULL",
        "ALTER TABLE leads ADD COLUMN IF NOT EXISTS consentimiento_at TIMESTAMP",
        # ── Facturas conservadas tras la baja del cliente ──
        "ALTER TABLE invoices ALTER COLUMN user_id DROP NOT NULL",
        "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS cliente_email VARCHAR(120)",
        "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS cliente_nombre VARCHAR(120)",
        "ALTER TABLE blog_posts ADD COLUMN IF NOT EXISTS seed_version INTEGER DEFAULT 1",
    ]:
        try:
            db.session.execute(text(col_sql))
            db.session.commit()
        except Exception:
            db.session.rollback()

# ─── Bootstrap de blog SEO (idempotente — solo crea si no existe el slug) ───
# Versión 2 (nov. 2026): cifras sin fuente y casos inventados eliminados; NIS2 reescrito.
BLOG_SEEDS_VERSION = 2
_BLOG_SEEDS = [
    {
        "slug": "auditoria-seguridad-pymes-espana-guia-2026",
        "titulo": "Auditoría de seguridad gratis para PYMEs en España: guía completa 2026",
        "excerpt": "Cómo hacer una auditoría de seguridad básica de tu empresa sin contratar consultores: pasos, herramientas y normativa (RGPD, ENS, ISO 27001).",
        "tags": "seguridad,pyme,RGPD,ENS,auditoria,2026",
        "contenido": """
<h2>¿Por qué tu PYME necesita una auditoría de seguridad?</h2>
<p>Las pequeñas y medianas empresas son un objetivo habitual de los ciberataques. La razón es simple: las PYMEs suelen tener menos defensas que las corporaciones grandes, pero los datos que manejan (clientes, facturas, nóminas) son igual de valiosos para los atacantes.</p>
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
<p>Una revisión hecha por ti mismo cubre los problemas más habituales. Pero si manejas datos sensibles (sanitarios, financieros, biométricos) o ya has sufrido un incidente, contrata a un profesional para una auditoría o un test de intrusión.</p>

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
<p>Por defecto, el protocolo SMTP no verifica el remitente. Eso significa que un atacante puede enviar un correo aparentando venir de <code>jefe@tuempresa.es</code> aunque no tenga acceso a tu dominio. Es la base de muchos fraudes por email dirigidos a empresas (Business Email Compromise).</p>
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
        "excerpt": "WordPress es el CMS más usado del mundo, y por eso uno de los más atacados. Te enseño los 12 checks esenciales que toda web WordPress debería pasar — con ejemplos y herramientas gratuitas para validarlos.",
        "tags": "wordpress,seguridad,auditoria,plugins,cve",
        "contenido": """
<h2>Por qué WordPress es un objetivo tan atacado</h2>
<p>WordPress es el gestor de contenidos más usado del mundo según <a href="https://w3techs.com/technologies/details/cm-wordpress" target="_blank" rel="noopener">W3Techs</a>. Eso lo convierte en un objetivo muy rentable: con un solo exploit se pueden vulnerar miles de webs. Cada año se publican miles de vulnerabilidades en plugins y temas de WordPress.</p>
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
<p>NO instales temas/plugins "premium gratis" de webs piratas. Es muy habitual que traigan <strong>malware</strong>. Usa repositorio oficial de WordPress, ThemeForest, CodeCanyon o webs reconocidas (Yoast, WP Rocket, etc.).</p>

<h3>11. Backups automáticos</h3>
<p>Plugin <strong>UpdraftPlus</strong> (gratis) → configura backup semanal a Google Drive/Dropbox. Si te hackean, restauras en 5&nbsp;min en lugar de perder todo.</p>

<h3>12. Monitor de seguridad continua</h3>
<p><strong>Wordfence</strong> (gratis) o <strong>Sucuri</strong> escanean tu WordPress cada noche en busca de archivos modificados/malware. Es la red de seguridad final.</p>

<h2>Cómo automatizar esta auditoría</h2>
<p>Hacer estos 12 checks manualmente tarda 1-2 horas. <a href="/">ReconBase</a> los pasa automáticamente en 2 minutos analizando solo tu dominio — sin acceso a tu WordPress. Detecta versión, plugins visibles, archivos sensibles expuestos y mucho más. <strong>Gratis, sin tarjeta</strong>.</p>

<h2>Conclusión</h2>
<p>WordPress es seguro <em>cuando se mantiene</em>. Muchos hackeos a webs pequeñas empiezan por un plugin desactualizado, no por un atacante sofisticado. Estos 12 checks cubren los vectores de ataque más comunes. <a href="/">Analiza tu WordPress aquí</a> y arregla lo que detecte hoy.</p>
""".strip()
    },
    {
        "slug": "ataques-bec-business-email-compromise-pymes-espana",
        "titulo": "Ataques BEC (Business Email Compromise): la estafa silenciosa que se lleva miles de euros de pymes españolas",
        "excerpt": "El fraude BEC no usa malware ni hackeo técnico: solo un email bien escrito que suplanta a un jefe o a un proveedor. Te explicamos cómo funciona, ejemplos típicos y cómo protegerte.",
        "tags": "BEC,phishing,suplantacion,SPF,DMARC,pyme",
        "contenido": """
<h2>¿Qué es un ataque BEC y por qué deberías preocuparte?</h2>
<p><strong>BEC = Business Email Compromise</strong>. El atacante envía un email haciéndose pasar por una persona de confianza (el CEO, un proveedor, el banco) y consigue que alguien de tu empresa <strong>transfiera dinero</strong> a una cuenta controlada por él.</p>
<p>No usa malware. No usa exploits. No necesita "hackear" nada. Solo necesita:</p>
<ul>
  <li>Un email convincente</li>
  <li>Que tu dominio <strong>no tenga SPF/DMARC</strong> bien configurados</li>
</ul>
<p>El BEC es uno de los fraudes que más dinero cuesta a las empresas: el <a href="https://www.ic3.gov" target="_blank" rel="noopener">IC3 del FBI</a> lo sitúa cada año entre los delitos con mayores pérdidas declaradas. Las pymes son un objetivo habitual porque a menudo no tienen procesos formales para verificar transferencias.</p>

<h2>3 ejemplos típicos (ilustrativos)</h2>

<h3>Ejemplo 1: el falso gerente</h3>
<p>Una empresa recibe un email "del gerente" pidiendo a administración que transfiera un importe a un nuevo proveedor por una "urgencia". El email venía de <code>gerente@asesoria-X.com</code> — exactamente el dominio real. Si nadie lo comprueba por teléfono, el dinero sale. El gerente nunca había mandado ese email.</p>
<p><strong>Causa raíz</strong>: el dominio no tenía DMARC configurado. Cualquier atacante podía enviar emails como <code>gerente@asesoria-X.com</code> desde un servidor externo y pasar el filtro.</p>

<h3>Ejemplo 2: el falso banco</h3>
<p>Una pyme de logística recibió un email "de su banco" pidiendo confirmar una operación. La factura adjunta venía de un dominio MUY parecido al banco real. La pyme tenía las credenciales bancarias del director financiero comprometidas (filtración antigua, no cambió la contraseña). El atacante hizo la transferencia desde la web del banco — para el banco, era una operación legítima.</p>
<p><strong>Causa raíz</strong>: credenciales filtradas + sin 2FA en banca online.</p>

<h3>Ejemplo 3: el cambio de IBAN</h3>
<p>Un email "del proveedor de material" pedía actualizar el IBAN de cobro porque "había cambiado de banco". La gestoría actualizó el IBAN en su programa de gestión sin verificar telefónicamente. La siguiente transferencia va a la cuenta del atacante.</p>
<p><strong>Causa raíz</strong>: cero proceso de verificación de cambios de IBAN.</p>

<h2>Cómo blindar tu pyme contra BEC (30 minutos)</h2>

<h3>1. Configura SPF, DKIM y DMARC (10 min)</h3>
<p>Es el bloqueo técnico número 1. Sin esto, cualquiera puede suplantar tu dominio. Tenemos una <a href="/blog/configurar-spf-dkim-dmarc-paso-a-paso">guía paso a paso</a> y una <a href="/comprobar-dmarc-spf">herramienta gratuita</a> para validar tu configuración.</p>

<h3>2. Política interna de "doble verificación" en transferencias (10 min)</h3>
<p>Establece por escrito y comunica al equipo: <strong>cualquier transferencia &gt;1.000&nbsp;€ o cambio de IBAN debe verificarse telefónicamente con un número conocido</strong> (no el que aparezca en el email). Esta política, por sí sola, frena la mayoría de estos fraudes.</p>

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
<p>El BEC funciona porque no requiere habilidad técnica: aprovecha procesos descuidados de la empresa. Las medidas son baratas (DMARC, 2FA, política de doble verificación) y reducen mucho el riesgo. <a href="/">Empieza por analizar gratis tu dominio</a> y ver si tu empresa ya está expuesta.</p>
""".strip()
    },
    {
        "slug": "ransomware-pymes-espana-como-prevenirlo-2026",
        "titulo": "Ransomware en PYMEs españolas: cómo funciona, cuánto cuesta y cómo prevenirlo en 2026",
        "excerpt": "El ransomware paralizó a más de 1.500 pymes españolas en 2024. Te explicamos cómo entra, qué hace, cuánto cuesta el rescate (spoiler: pagar no sirve) y los 7 pasos concretos para no ser la próxima víctima.",
        "tags": "ransomware,pyme,backup,seguridad,INCIBE,2026",
        "contenido": """
<h2>¿Qué es el ransomware y por qué las pymes son el objetivo favorito?</h2>
<p>El <strong>ransomware</strong> es un tipo de malware que cifra todos los archivos de tu empresa y exige un rescate (ransom) en criptomonedas para devolverte el acceso. Además del posible rescate, el coste real suele estar en el tiempo de parada, la recuperación y el daño a la reputación.</p>
<p>Las pymes son el objetivo favorito porque:</p>
<ul>
  <li>No tienen backups automatizados y verificados.</li>
  <li>Usan software desactualizado (Windows 7, Office 2010, etc.).</li>
  <li>Un solo empleado con malos hábitos puede comprometer toda la red.</li>
  <li>Pagan con más frecuencia que las grandes empresas porque no tienen alternativas.</li>
</ul>

<h2>Cómo entra el ransomware en tu empresa</h2>
<p>Los vectores de entrada más habituales son estos tres:</p>
<ol>
  <li><strong>Phishing por email:</strong> un empleado abre un adjunto (PDF, Word, ZIP) o hace clic en un enlace. El malware se instala silenciosamente y se propaga por la red.</li>
  <li><strong>RDP expuesto a internet:</strong> si tienes el puerto 3389 (Escritorio Remoto) abierto con contraseñas débiles, los atacantes lo encuentran con herramientas automáticas y entran por fuerza bruta.</li>
  <li><strong>Software sin parchear:</strong> vulnerabilidades conocidas en VPNs, servidores web o sistemas operativos sin actualizar. EternalBlue (WannaCry) sigue activo 7 años después.</li>
</ol>

<h2>¿Pagar el rescate funciona?</h2>
<p>Pagar <strong>no garantiza recuperar los archivos</strong>, y las autoridades desaconsejan hacerlo. Además:</p>
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
<p>Windows Update, Office, Adobe, Java, el firmware del router. Muchos ataques aprovechan vulnerabilidades que ya tenían parche disponible y nadie instaló.</p>

<h3>4. Formación anti-phishing para el equipo</h3>
<p>Un empleado formado es mejor que cualquier antivirus. Simula ataques de phishing con herramientas como <strong>GoPhish</strong> (gratuito) para medir y mejorar.</p>

<h3>5. Segmentación de red</h3>
<p>Si el ordenador del recepcionista se infecta, no debería poder alcanzar el servidor contable. VLANs básicas evitan la propagación lateral.</p>

<h3>6. Principio de mínimo privilegio</h3>
<p>Nadie debería tener permisos de administrador para el trabajo del día a día. Si el malware corre como usuario sin privilegios, su impacto es mucho menor.</p>

<h3>7. Plan de respuesta a incidentes escrito</h3>
<p>Decide HOY: si mañana te cifran los servidores, ¿quién llama a quién? ¿Cuándo llamas al 017 de INCIBE? ¿Tienes el contacto de tu proveedor de IT? Tener el plan escrito antes del incidente vale más que cualquier herramienta.</p>

<h2>Si ya estás infectado: pasos inmediatos</h2>
<ol>
  <li><strong>Desconecta</strong> los equipos afectados de la red (sin apagarlos).</li>
  <li><strong>Llama al 017 de INCIBE:</strong> línea gratuita y confidencial de ayuda en ciberseguridad.</li>
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
        "excerpt": "Las contraseñas débiles, reutilizadas o robadas están detrás de muchas brechas de seguridad. Te damos la política de contraseñas que deberías tener, los mejores gestores para equipos y cómo implantar 2FA sin que el equipo proteste.",
        "tags": "contraseñas,2FA,gestion,seguridad,pyme,passwords",
        "contenido": """
<h2>El problema con las contraseñas en las pymes</h2>
<p>El informe anual <a href="https://www.verizon.com/business/resources/reports/dbir/" target="_blank" rel="noopener"><em>Data Breach Investigations Report</em> de Verizon</a> sitúa año tras año el uso de credenciales robadas entre las principales vías de entrada en las brechas. En muchas pymes, además, la misma contraseña en el email, el ERP y el banco; post-its con credenciales pegados al monitor; contraseñas compartidas por WhatsApp.</p>
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
  <li>Plan para equipos de pago por usuario y plan gratuito individual (consulta precios actuales en su web).</li>
  <li>Open source, auditorías de seguridad públicas.</li>
  <li>Compartir contraseñas entre departamentos con permisos granulares.</li>
  <li>Extensiones para Chrome, Firefox, Safari, app móvil.</li>
</ul>

<h3>1Password Business</h3>
<ul>
  <li>De pago por usuario. Más caro, muy cómodo de usar.</li>
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
  <li><strong>Llaves físicas (YubiKey):</strong> lo más seguro. Resistente a phishing. Tienen un coste por unidad.</li>
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
<p>Las contraseñas débiles son el vector de entrada más común en ciberataques a pymes — y el más fácil de cerrar. Con un gestor de contraseñas y el doble factor ya reduces mucho el riesgo. <a href="/">Comprueba gratis si los emails de tu empresa han aparecido en filtraciones</a> y empieza a actuar hoy.</p>
""".strip()
    },
    {
        "slug": "nis2-espana-empresas-obligadas-como-cumplir-2026",
        "titulo": "NIS2 en España: qué es, a quién afecta y cómo prepararte (guía práctica)",
        "excerpt": "La directiva NIS2 amplía mucho las empresas obligadas a gestionar su ciberseguridad. Te explicamos qué dice, a quién afecta, en qué punto está su aplicación en España y cómo empezar a prepararte.",
        "tags": "NIS2,normativa,ciberseguridad,pyme,RGPD,2026",
        "contenido": """
<h2>Qué es NIS2</h2>
<p>La <a href="https://eur-lex.europa.eu/eli/dir/2022/2555/oj" target="_blank" rel="noopener">Directiva (UE) 2022/2555</a>, conocida como <strong>NIS2</strong>, es la norma europea que obliga a muchas empresas y organismos a gestionar los riesgos de ciberseguridad y a notificar los incidentes graves. Sustituye a la primera directiva NIS y amplía mucho los sectores afectados.</p>
<p>Al ser una <strong>directiva</strong>, no se aplica directamente a las empresas: cada Estado debe incorporarla a su legislación. El plazo terminaba el 17 de octubre de 2024. En España, la transposición se tramita mediante la <strong>Ley de Coordinación y Gobernanza de la Ciberseguridad</strong>. Antes de tomar decisiones, comprueba en el <a href="https://www.boe.es" target="_blank" rel="noopener">BOE</a> si ya está en vigor, qué plazos fija y qué autoridad te corresponde.</p>

<h2>¿A quién afecta?</h2>
<p>La directiva distingue entre <strong>entidades esenciales</strong> y <strong>entidades importantes</strong>, según el sector y el tamaño:</p>
<ul>
  <li><strong>Sectores de alta criticidad</strong> (anexo I): energía, transporte, banca, infraestructuras de mercados financieros, sanidad, agua potable y residuales, infraestructura digital, gestión de servicios TIC entre empresas, administración pública y espacio.</li>
  <li><strong>Otros sectores críticos</strong> (anexo II): servicios postales, gestión de residuos, sustancias químicas, alimentación, fabricación de determinados productos (por ejemplo, dispositivos médicos, electrónica, maquinaria y vehículos), proveedores digitales (mercados en línea, motores de búsqueda, redes sociales) e investigación.</li>
</ul>
<p>Como regla general, se aplica a <strong>medianas y grandes empresas</strong> de esos sectores (a partir de 50 empleados, o más de 10 millones de euros tanto de volumen de negocio como de balance). Las pequeñas y microempresas quedan fuera, salvo excepciones como algunos proveedores de servicios de DNS, registros de nombres de dominio o prestadores de servicios de confianza.</p>
<p>Aunque tu empresa no esté obligada, puede que te lo pidan tus clientes: las entidades obligadas deben revisar también la seguridad de su <strong>cadena de suministro</strong>.</p>

<h2>Qué obliga a hacer</h2>
<ul>
  <li><strong>Medidas de gestión de riesgos</strong> (art. 21): análisis de riesgos, gestión de incidentes, continuidad y copias de seguridad, seguridad de la cadena de suministro, gestión de vulnerabilidades, cifrado, control de accesos, autenticación multifactor y formación.</li>
  <li><strong>Responsabilidad de la dirección</strong> (art. 20): los órganos de dirección deben aprobar las medidas, supervisar su aplicación y recibir formación.</li>
  <li><strong>Notificación de incidentes significativos</strong> (art. 23) al CSIRT o autoridad que corresponda: alerta temprana en 24 horas, notificación del incidente en 72 horas e informe final en un mes.</li>
</ul>

<h2>Sanciones</h2>
<p>La directiva fija que las multas máximas deben ser de, al menos, <strong>10 millones de euros o el 2&nbsp;% del volumen de negocio mundial</strong> para las entidades esenciales y <strong>7 millones o el 1,4&nbsp;%</strong> para las importantes (art. 34). Las sanciones concretas en España dependerán de la ley de transposición y las impondrán las autoridades que esta designe.</p>

<h2>Cómo empezar a prepararte</h2>
<ol>
  <li><strong>Comprueba si estás dentro:</strong> revisa tu sector en los anexos de la directiva y tu tamaño.</li>
  <li><strong>Haz inventario</strong> de sistemas, datos y proveedores críticos.</li>
  <li><strong>Cubre lo básico:</strong> autenticación multifactor, copias de seguridad probadas, actualizaciones al día y SPF/DMARC en tu dominio.</li>
  <li><strong>Escribe un plan de respuesta a incidentes</strong> con responsables y contactos. El <a href="https://www.incibe.es/linea-de-ayuda-en-ciberseguridad" target="_blank" rel="noopener">017 de INCIBE</a> ofrece ayuda gratuita en ciberseguridad.</li>
  <li><strong>Forma a la dirección y al equipo</strong>, y deja constancia.</li>
</ol>
<p>INCIBE publica guías y recursos gratuitos para empresas en su web. Para revisar la parte externa de tu web (certificado, cabeceras, SPF/DMARC y, si verificas el dominio, puertos y ficheros expuestos) puedes usar el <a href="/">análisis gratuito de ReconBase</a>. Ten en cuenta que ninguna herramienta por sí sola te hace cumplir NIS2.</p>

<h2>Conclusión</h2>
<p>NIS2 amplía mucho las empresas que deben tomarse en serio la ciberseguridad. Comprueba si te afecta, sigue la tramitación de la ley española y empieza por las medidas básicas, que conviene tener aunque no estés obligado. Este artículo es informativo y no sustituye al asesoramiento legal.</p>
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
<p>Si ves archivos modificados en directorios como <code>wp-content/uploads/</code>, <code>wp-includes/</code> o <code>wp-admin/</code> y tú no has tocado nada esos días, investígalo: puede ser una puerta trasera.</p>

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
<p>Si tus clientes te dicen <em>"me sale una pantalla roja al entrar"</em>, tu dominio ha entrado en alguna lista de sitios peligrosos (como las de Google). Muchos navegadores muestran una advertencia y buena parte de tus visitantes no llegará a entrar.</p>
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
  <li><strong>Notifica si es necesario.</strong> Si hubo exfiltración de datos personales, tienes 72h para notificar a la AEPD (RGPD). Si tu empresa está sujeta a NIS2, revisa también sus plazos de notificación.</li>
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
<p>Los <strong>skimmers digitales</strong>, también conocidos como <em>Magecart</em>, <em>web skimmers</em> o <em>e-skimmers</em>, son una de las formas más dañinas de robar datos de tarjeta en tiendas online. Afectan a cualquier plataforma, también a PrestaShop.</p>
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
<p>Mira el panel de Redsys, Stripe o tu banco. Si los contracargos suben sin explicación, podrías tener un skimmer activo.</p>

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
  <li><strong>Notifica a la AEPD en 72h</strong> (obligatorio RGPD art. 33). Si tu empresa está sujeta a NIS2, revisa también sus plazos de notificación.</li>
  <li><strong>Avisa a tu pasarela de pago.</strong> Pueden ayudarte a identificar el rango de fechas afectado y notificar a las tarjetas comprometidas.</li>
  <li><strong>Si has perdido la certificación PCI-DSS</strong>: contacta con tu QSA (Qualified Security Assessor) para recertificación. Sin esto no puedes vender online.</li>
</ol>

<h2>Cómo prevenir nuevos skimmers</h2>
<ul>
  <li><strong>Mantén PrestaShop y módulos al día.</strong> Muchos skimmers entran por vulnerabilidades conocidas que ya tenían parche.</li>
  <li><strong>Revisa la tienda periódicamente</strong> con ReconBase (gratuito) o herramientas equivalentes.</li>
  <li><strong>Activa CSP (Content Security Policy)</strong> con allowlist de dominios. Impide que JavaScript externo cargue desde dominios no autorizados — el ataque Magecart deja de funcionar.</li>
  <li><strong>Subresource Integrity (SRI)</strong> en los scripts externos. Garantiza que el JS no haya sido modificado en tránsito.</li>
  <li><strong>Logs centralizados</strong> con alerta automática si cambian archivos PHP en producción.</li>
  <li><strong>Auditoría manual del checkout</strong> después de cualquier actualización de módulos, theme o PrestaShop.</li>
  <li><strong>Hosting dedicado</strong> en lugar de shared, si tu volumen lo permite. Menos vectores laterales.</li>
</ul>

<h2>Conclusión</h2>
<p>Los skimmers digitales son una amenaza seria para cualquier tienda online y pueden pasar mucho tiempo sin detectarse. Detectarlos pronto reduce el daño a tus clientes, los contracargos y los problemas con tu pasarela de pago. <a href="/auditoria-prestashop">Lanza una auditoría gratuita de tu PrestaShop ahora</a> y comprueba si el detector de skimmers de ReconBase encuentra algo sospechoso. Si lo encuentra, sigue el protocolo de esta guía.</p>
""".strip()
    },
    {
        "slug": "auditoria-wordpress-12-checks-reconbase",
        "titulo": "Auditoría WordPress: los 12 checks de seguridad que hace ReconBase gratis",
        "excerpt": "Repasamos uno a uno los 12 chequeos técnicos de ReconBase para WordPress: cuáles se hacen en cualquier web y cuáles solo en dominios verificados, qué buscan y qué hacer si fallan.",
        "tags": "wordpress,auditoria,seguridad,wp-scan,plugins,xmlrpc,wp-json,2026",
        "contenido": """
<h2>Por qué necesitas auditar tu WordPress (aunque tu web vaya bien)</h2>
<p>WordPress es el CMS más usado del mundo y, por eso, uno de los más atacados. Tres causas aparecen una y otra vez en los hackeos: <strong>versión obsoleta, plugin vulnerable o credenciales filtradas</strong>. Buena parte de esto se puede revisar desde fuera, sin tocar el sitio.</p>
<p>Esa es exactamente la idea de la <a href="/auditoria-wordpress">auditoría gratuita de ReconBase</a>: 12 chequeos sin instalar nada ni compartir el wp-admin. Los marcados como <strong>(dominio verificado)</strong> solo se hacen si demuestras que el dominio es tuyo, porque consisten en probar rutas que tu web no enlaza. Te explico qué hace cada uno.</p>

<h2>1. Detección de la versión del core</h2>
<p>Buscamos la versión de WordPress en la etiqueta <code>&lt;meta name="generator"&gt;</code> de la home, en el feed RSS (<code>/feed/</code>) y en la API JSON (<code>/wp-json/</code>), y la comparamos con la última versión estable. Si detectamos una versión inferior, te marcamos cuántas minor o major versiones llevas de retraso.</p>
<p><strong>Por qué importa:</strong> el equipo de WordPress publica parches de seguridad cada pocas semanas. Cuanto más antigua es la versión, más vulnerabilidades públicas acumula.</p>

<h2>2. xmlrpc.php expuesto (dominio verificado)</h2>
<p>Comprobamos si <code>/xmlrpc.php</code> responde 200 con cabecera XML-RPC. Si responde, está abierto.</p>
<p><strong>Por qué importa:</strong> xmlrpc.php permite hacer login con una única petición HTTP (en vez de pasar por el formulario de wp-login.php) y, peor aún, soporta el método <code>system.multicall</code> que ejecuta cientos de logins en una sola petición. Resultado: fuerza bruta mucho más rápida. Además es un vector clásico de amplificación pingback DDoS.</p>
<p><strong>Cómo arreglarlo:</strong> si no usas Jetpack ni edición móvil remota, bloquéalo en .htaccess o nginx. Una sola línea.</p>

<h2>3. Enumeración de usuarios vía wp-json (dominio verificado)</h2>
<p>Hacemos GET a <code>/wp-json/wp/v2/users</code>. Si responde con una lista de usuarios, los enumeramos (hasta los 5 primeros, sin recoger emails ni datos sensibles).</p>
<p><strong>Por qué importa:</strong> cualquier atacante puede leer los nombres de usuario reales de tus administradores sin necesidad de adivinar. Combinado con xmlrpc abierto o con un wp-login.php sin límite de intentos, facilita la fuerza bruta dirigida.</p>
<p><strong>Cómo arreglarlo:</strong> plugin "Stop User Enumeration" o regla nginx que bloquee la ruta. Lleva 5 minutos.</p>

<h2>4. Plugins activos y cruce con CVEs conocidos</h2>
<p>Extraemos los slugs de plugin de las URLs <code>/wp-content/plugins/[slug]/</code> presentes en el HTML. Cruzamos con nuestra lista interna de plugins con vulnerabilidades públicas conocidas (WP File Manager RCE pre-auth, Duplicator antiguos, Elementor con XSS, Contact Form 7 con upload vulnerable, etc.).</p>
<p><strong>Por qué importa:</strong> la mayoría de vulnerabilidades que se publican en el ecosistema WordPress están en plugins. Algunos CVEs son tan graves que permiten ejecución remota de código sin autenticación.</p>
<p><strong>Limitación:</strong> solo detectamos plugins que dejan rastro en el HTML público. Los plugins de admin-only no los vemos (es esperado).</p>

<h2>5. Theme activo y versión</h2>
<p>Identificamos el theme por la ruta <code>/wp-content/themes/[slug]/</code>. Conocer el theme ayuda a detectar themes premium descontinuados o themes nulled (piratas) con backdoors preinstaladas.</p>

<h2>6. Archivos sensibles expuestos (dominio verificado)</h2>
<p>Comprobamos si responden seis rutas típicas que <strong>nunca deberían estar accesibles desde el navegador</strong>. Solo miramos si responden: nunca descargamos su contenido.</p>
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

<h2>8. Puertos críticos abiertos (dominio verificado)</h2>
<p>Escaneo de puertos críticos (MySQL, RDP, MongoDB, Redis, PostgreSQL, MSSQL). Tu hosting nunca debería exponer estos puertos al exterior — si responden, hay un riesgo real de robo de base de datos.</p>

<h2>9. Configuración DNS (SPF + DMARC)</h2>
<p>Comprobamos SPF y DMARC de tu dominio. Si faltan, cualquiera puede enviar emails haciéndose pasar por tu empresa — vector clásico de Business Email Compromise.</p>

<h2>10. Cabeceras HTTP de seguridad</h2>
<p>Verificamos las cabeceras críticas: <code>Content-Security-Policy</code>, <code>X-Frame-Options</code>, <code>Strict-Transport-Security</code>, <code>X-Content-Type-Options</code>, <code>Referrer-Policy</code>. Configurarlas no requiere tocar WordPress, solo tu nginx/Apache.</p>

<h2>11. Subdominios visibles</h2>
<p>Análisis pasivo de subdominios. Te mostramos los detectados. Útil para encontrar entornos de staging, paneles internos o servicios olvidados que también deberían auditarse.</p>

<h2>12. Filtraciones de credenciales asociadas al dominio</h2>
<p>Si analizas tu propio email o uno de un dominio que has verificado, lo consultamos en <a href="https://haveibeenpwned.com" target="_blank" rel="noopener">Have I Been Pwned</a> para ver si ha aparecido en alguna brecha pública. Si tu admin reusa contraseña, esta es la entrada que un atacante encontrará primero.</p>

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
  <li>Informe PDF para compartir con dirección o con tu proveedor.</li>
  <li>Con el dominio verificado, vigilancia automática: análisis periódicos y aviso por email si aparece un problema nuevo.</li>
  <li>Histórico de escaneos para ver evolución.</li>
  <li>Consulta de filtraciones de tu email y de los de tus dominios verificados.</li>
</ul>

<h2>Limitaciones honestas</h2>
<p>Esta auditoría externa cubre los problemas más habituales de WordPress, pero <strong>no es un pentest</strong>. No detecta:</p>
<ul>
  <li>Plugins instalados sin rastro en HTML público (raros).</li>
  <li>Vulnerabilidades específicas de tu código personalizado (custom plugins/themes).</li>
  <li>Backdoors que se camuflen perfectamente en archivos PHP del core.</li>
  <li>Configuraciones inseguras del wp-admin (capacidades de roles, etc.).</li>
</ul>
<p>Para eso necesitas un escáner interno como Wordfence o Sucuri, o una auditoría manual por un pentester. Aun así, esta capa externa cubre los vectores que más usan los ataques automatizados.</p>

<h2>Conclusión</h2>
<p><a href="/auditoria-wordpress">Pasa la auditoría a tu dominio</a> y mira el informe. Si sale algo en rojo, mejor arreglarlo antes de que lo encuentre un atacante.</p>
""".strip()
    },
    {
        "slug": "wordpress-se-hackean-mas-rapido-2026-ventana-parche",
        "titulo": "Por qué los WordPress se hackean más rápido que nunca en 2026 (y cómo cerrar la ventana de exposición)",
        "excerpt": "El tiempo entre que se publica una vulnerabilidad de WordPress y los bots la explotan masivamente ha caído a horas. Te explicamos por qué pasa, cuánto tardan realmente los atacantes y cómo proteger tu web sin estar pendiente 24/7.",
        "tags": "wordpress,vulnerabilidades,parches,botnet,seguridad,CVE,2026",
        "contenido": """
<h2>La ventana entre vulnerabilidad y ataque se mide ya en horas</h2>
<p>Hace cinco años, cuando se publicaba una vulnerabilidad en un plugin popular de WordPress, los administradores tenían días — a veces semanas — para aplicar el parche antes de que alguien la explotara. Hoy esa ventana es mucho más corta: los primeros intentos de explotación automatizada pueden llegar <strong>en cuestión de horas</strong> desde que se publica la vulnerabilidad.</p>
<p>Esto cambia por completo las reglas. Ya no basta con "actualizar de vez en cuando". Si tu WordPress tiene un plugin vulnerable y tú te enteras el lunes de una vulnerabilidad publicada el viernes, es muy probable que tu web lleve el fin de semana entero siendo escaneada por botnets automatizadas.</p>

<h2>¿Por qué se ha acelerado tanto?</h2>
<p>Cuatro factores se han combinado:</p>
<ol>
  <li><strong>Automatización total del lado atacante.</strong> Los grupos de ataque ya no buscan webs a mano. Tienen botnets que monitorizan las bases de datos públicas de vulnerabilidades (CVE, WPScan, Wordfence Intelligence) y, en cuanto aparece una nueva, generan automáticamente el exploit y lo lanzan contra millones de webs WordPress indexadas.</li>
  <li><strong>WordPress es el objetivo más rentable.</strong> Al ser el CMS más usado, cualquier vulnerabilidad en un plugin con cientos de miles de instalaciones es una mina. El retorno por hora de trabajo del atacante es altísimo.</li>
  <li><strong>Inteligencia artificial en la generación de exploits.</strong> Lo que antes requería un investigador experto ahora se acelera con herramientas que convierten el aviso de seguridad (el "advisory") en código de explotación funcional en minutos.</li>
  <li><strong>El parque de WordPress está desatendido.</strong> La mayoría de pymes instalaron su WordPress hace años y nadie lo mantiene. Plugins de 2019, versiones de core sin actualizar, themes nulled. Es terreno fértil.</li>
</ol>

<h2>Qué busca exactamente una botnet en tu WordPress</h2>
<p>No es un humano mirando tu web. Es un script que, en segundos, comprueba:</p>
<ul>
  <li>La <strong>versión del core</strong> (vía readme.html, meta generator, API) para saber si es vulnerable.</li>
  <li>Los <strong>plugins activos</strong> y sus versiones (vía rutas /wp-content/plugins/) para cruzarlos con su base de CVEs.</li>
  <li>Si <strong>xmlrpc.php</strong> está abierto, para fuerza bruta acelerada.</li>
  <li>Si los <strong>usuarios son enumerables</strong> vía /wp-json/wp/v2/users, para tener la lista de logins a atacar.</li>
  <li>Si hay <strong>archivos sensibles</strong> expuestos (backups, install.php, debug.log).</li>
</ul>
<p>Es exactamente la misma información que comprueba la <a href="/auditoria-wordpress">auditoría WordPress de ReconBase</a> — porque para defenderte necesitas ver tu web con los mismos ojos que el atacante.</p>

<h2>Cómo cerrar la ventana de exposición</h2>
<p>No puedes parchear en "menos de 12 horas" si te enteras de las vulnerabilidades por casualidad. Necesitas un sistema. Por orden de impacto:</p>

<h3>1. Activa las actualizaciones automáticas de plugins críticos</h3>
<p>WordPress permite desde el panel marcar plugins para que se actualicen solos (Plugins → Activar actualizaciones automáticas). Para los plugins de seguridad, formularios y e-commerce, actívalo. El riesgo de que una actualización rompa algo es mucho menor que el de quedarte sin parchear durante el fin de semana.</p>

<h3>2. Reduce tu superficie: borra lo que no usas</h3>
<p>Cada plugin y theme instalado — aunque esté desactivado — es una puerta potencial. Un plugin desactivado con una vulnerabilidad de tipo "unauthenticated" sigue siendo explotable. Borra todo lo que no uses de verdad.</p>

<h3>3. Monitorización continua, no revisiones puntuales</h3>
<p>Aquí está la clave de 2026: como la ventana es de horas, la revisión manual mensual no sirve. Necesitas que <strong>algo vigile tu web cada día</strong> y te avise en cuanto aparezca un problema nuevo. Con tu dominio verificado, la vigilancia de ReconBase lo analiza automáticamente y te envía una alerta por email (y Slack) si detecta una versión obsoleta, un plugin que pasó a ser vulnerable o un archivo sensible recién expuesto.</p>

<h3>4. Bloquea los vectores de fuerza bruta</h3>
<p>Deshabilita xmlrpc.php si no lo usas, bloquea la enumeración de usuarios y pon un límite de intentos de login. Son tres cambios de configuración que cierran los ataques automatizados más comunes.</p>

<h3>5. Ten un backup que puedas restaurar de verdad</h3>
<p>Si todo falla y te comprometen, un backup limpio reciente es la diferencia entre 1 hora de downtime y una semana de pesadilla. Pruébalo: un backup que nunca has restaurado no es un backup, es una ilusión.</p>

<h2>El cambio de mentalidad que necesitas</h2>
<p>La seguridad de WordPress ya no es un evento ("voy a revisar la web este mes"), es un proceso continuo. La pregunta correcta no es "¿está mi web segura hoy?", sino "<strong>¿me enteraré dentro de las próximas horas si deja de estarlo?</strong>". Si la respuesta es no, tienes una ventana de exposición abierta justo del tamaño que las botnets necesitan.</p>

<h2>Conclusión</h2>
<p>Los atacantes se han automatizado y han reducido la ventana a horas. Tu defensa también tiene que automatizarse. <a href="/auditoria-wordpress">Haz una auditoría gratuita de tu WordPress ahora</a> para ver tu estado actual, y si quieres dormir tranquilo, activa la vigilancia continua: que un sistema mire tu web cada noche para que tú no tengas que hacerlo.</p>
""".strip()
    },
]

with app.app_context():
    try:
        for _seed in _BLOG_SEEDS:
            existing = BlogPost.query.filter_by(slug=_seed["slug"]).first()
            if existing:
                # Las correcciones de contenido de los seeds se aplican a los
                # posts ya publicados subiendo BLOG_SEEDS_VERSION.
                if (existing.seed_version or 1) < BLOG_SEEDS_VERSION:
                    existing.titulo = _seed["titulo"]
                    existing.excerpt = _seed["excerpt"]
                    existing.contenido = _seed["contenido"]
                    existing.tags = _seed["tags"]
                    existing.seed_version = BLOG_SEEDS_VERSION
                continue
            _bp = BlogPost(
                slug=_seed["slug"],
                titulo=_seed["titulo"],
                excerpt=_seed["excerpt"],
                contenido=_seed["contenido"],
                tags=_seed["tags"],
                publicado=True,
                autor="ReconBase",
                seed_version=BLOG_SEEDS_VERSION,
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
