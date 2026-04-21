# ReconBase v2 — build 20260414
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, Response, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from models import (db, User, Scan, Domain, BlogPost,
                    SSLCheck, UptimeCheck, Notification, DNSRecord,
                    TechDetection, IPReputation, AuditLog, Invoice, Lead)
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
app.secret_key = os.getenv("SECRET_KEY", "cambiame_por_algo_seguro")
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
                "User-Agent": "ReconBase/1.0 (+https://reconbase-production.up.railway.app)",
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
    storage_uri="memory://"
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

@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)

# ─── Cabeceras HTTP de seguridad ───
@app.after_request
def set_security_headers(resp):
    # HSTS: forzar HTTPS durante 1 año
    resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
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
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://js.stripe.com https://plausible.io https://www.googletagmanager.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.stripe.com https://plausible.io https://www.google-analytics.com; "
        "frame-src https://js.stripe.com https://checkout.stripe.com; "
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
    return User.query.get(int(user_id))

API_KEY        = os.getenv("RECONBASE_API_KEY", "")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_PRO = os.getenv("STRIPE_PRICE_PRO", "")

# ── RUTAS PÚBLICAS ──
@app.route("/sitemap.xml")
def sitemap():
    base = "https://reconbase-production.up.railway.app"
    urls = [
        {"loc": base + "/",        "priority": "1.0",  "changefreq": "weekly"},
        {"loc": base + "/login",   "priority": "0.6",  "changefreq": "monthly"},
        {"loc": base + "/register","priority": "0.8",  "changefreq": "monthly"},
        {"loc": base + "/pricing", "priority": "0.9",  "changefreq": "monthly"},
        {"loc": base + "/terms",   "priority": "0.3",  "changefreq": "yearly"},
        {"loc": base + "/privacy", "priority": "0.3",  "changefreq": "yearly"},
        {"loc": base + "/blog",    "priority": "0.7",  "changefreq": "weekly"},
    ]
    # Añadir posts del blog al sitemap
    try:
        blog_posts = BlogPost.query.filter_by(publicado=True).all()
        for bp in blog_posts:
            urls.append({"loc": f"{base}/blog/{bp.slug}", "priority": "0.6", "changefreq": "monthly"})
    except Exception:
        pass
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for u in urls:
        xml += f'  <url><loc>{u["loc"]}</loc><changefreq>{u["changefreq"]}</changefreq><priority>{u["priority"]}</priority></url>\n'
    xml += '</urlset>'
    from flask import Response
    return Response(xml, mimetype="application/xml")

@app.route("/robots.txt")
def robots():
    from flask import Response
    txt = "User-agent: *\nAllow: /\nDisallow: /app\nDisallow: /api/\nSitemap: https://reconbase-production.up.railway.app/sitemap.xml"
    return Response(txt, mimetype="text/plain")

@app.route("/google9b381a283a68cc0a.html")
def google_verify():
    return "google-site-verification: google9b381a283a68cc0a.html"

# ── OG Image (PNG dinámico para redes sociales) ──
_og_cache = {}

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
    cta = "reconbase-production.up.railway.app"
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
        scans_mes = Scan.query.filter(
            Scan.user_id == current_user.id,
            extract('month', Scan.timestamp) == now.month,
            extract('year',  Scan.timestamp) == now.year
        ).count()
        ultimo_auto = Scan.query.filter_by(user_id=current_user.id).filter(
            Scan.resultado.op('->>')('automatico') == 'true'
        ).order_by(Scan.timestamp.desc()).first()
        plan      = current_user.plan_efectivo
        scan_hora = current_user.scan_hora if current_user.scan_hora is not None else 3
        scan_dias = current_user.scan_dias.split(',') if current_user.scan_dias else []
    stats_scans   = Scan.query.count()
    stats_vulns   = max(int(stats_scans * 2.3), 12)
    stats_breaches = User.query.count()
    return render_template("landing.html", user=current_user,
                           plan=plan, scans_mes=scans_mes,
                           ultimo_auto=ultimo_auto,
                           api_key_ok=bool(API_KEY),
                           scan_hora=scan_hora, scan_dias=scan_dias,
                           stats_scans=stats_scans,
                           stats_vulns=stats_vulns,
                           stats_breaches=stats_breaches)

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
    base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
    return jsonify({"ok": True, "url": f"{base_url}/report/{scan_obj.share_token}"})

@app.route("/report/<token>")
def report_publico(token):
    scan_obj = Scan.query.filter_by(share_token=token).first()
    if not scan_obj:
        return render_template("404.html"), 404
    return render_template("report_public.html", scan=scan_obj, resultado=scan_obj.resultado)

@app.route("/pago-exito")
def pago_exito():
    return render_template("pago_exito.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/pricing")
def pricing_page():
    return render_template("pricing.html", user=current_user if current_user.is_authenticated else None)

# ── AUTH API ──
@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute; 30 per hour")
def api_login():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    user     = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"ok": False, "error": "Email o contraseña incorrectos"}), 401
    # Si tiene 2FA activado, no hacer login todavía — pedir código TOTP
    if getattr(user, 'totp_enabled', False) and user.totp_secret:
        session["2fa_pending_user"] = user.id
        return jsonify({"ok": True, "requires_2fa": True})
    login_user(user)
    _registrar_audit(user.id, 'login', f"Login exitoso desde {request.remote_addr}")
    return jsonify({"ok": True})

def enviar_email_verificacion(user):
    base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
    link = f"{base_url}/verify-email/{user.verify_token}"
    def _send():
        try:
            send_html_email(
                user.email,
                "Confirma tu email — ReconBase",
                "Verifica tu dirección de email",
                f"""<p>Hola {user.empresa},</p>
<p>Gracias por registrarte en ReconBase. Confirma tu dirección de email haciendo clic en el botón:</p>
<p>Si no has creado esta cuenta, ignora este mensaje.</p>""",
                link, "Confirmar email"
            )
            logger.info(f"[Verify] Email enviado a {user.email}")
        except Exception as e:
            # No usar exception() — es un fallo de config de proveedor, no un crash.
            # Evita ruido en Sentry y deja un log claro para el operador.
            logger.warning(f"[Verify] No se pudo enviar verificacion a {user.email}: {e}")
    threading.Thread(target=_send, daemon=True).start()
    return True

@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")
def api_register():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    empresa  = data.get("empresa", "").strip()
    if not email or not password or not empresa:
        return jsonify({"ok": False, "error": "Todos los campos son obligatorios"}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "La contraseña debe tener al menos 8 caracteres"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"ok": False, "error": "Este email ya está registrado"}), 400
    user = User(email=email, empresa=empresa)
    user.set_password(password)
    user.generate_verify_token()
    db.session.add(user)
    db.session.commit()
    login_user(user)
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
        base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
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
                return jsonify({"ok": False, "error": "El portal de facturación no está activado en Stripe. Escríbenos a soporte@reconbase.io y cancelamos tu suscripción manualmente."}), 500
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
        base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
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

    # Usuarios sin cuenta: SOLO puertos. El resto se muestra bloqueado en el frontend.
    if not current_user.is_authenticated:
        # Riesgo aproximado basado solo en puertos para mostrar algo orientativo
        critical_set = {3389, 22, 3306, 5432, 27017, 6379, 5900, 23, 21, 1433}
        crit_count = len([p for p in puertos if p.get('puerto') in critical_set])
        riesgo_aprox = min(100, crit_count * 25)
        label_aprox, color_aprox = label_riesgo(riesgo_aprox)
        return jsonify({
            "objetivo": objetivo, "dominio": dominio, "es_ip": es_ip_flag,
            "puertos": puertos,
            "riesgo": riesgo_aprox, "label": label_aprox, "color": color_aprox,
            "timestamp": datetime.utcnow().strftime("%d/%m/%Y %H:%M"),
            "demo": True, "locked": True
        })

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

    return jsonify({
        "objetivo": objetivo, "dominio": dominio, "es_ip": es_ip_flag,
        "puertos": puertos, "dns": dns,
        "headers": {k: bool(v) for k, v in headers.items()},
        "subs": [], "leaks": 0, "leaks_raw": [],
        "riesgo": riesgo, "label": label, "color": color,
        "desglose": desglose, "ssl": ssl_info,
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
def crear_checkout():
    data = request.get_json()
    plan = data.get("plan", "")
    if plan != "pro" or not STRIPE_PRICE_PRO:
        return jsonify({"error": f"Plan no valido o precio no configurado. PRICE_PRO={STRIPE_PRICE_PRO}"}), 400
    try:
        checkout_session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=current_user.email if current_user.is_authenticated else None,
            line_items=[{"price": STRIPE_PRICE_PRO, "quantity": 1}],
            success_url=request.host_url + "pago-exito",
            cancel_url=request.host_url + "#precios",
        )
        return jsonify({"url": checkout_session.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
    scan_obj = Scan.query.get(scan_id)
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
            scan_obj = Scan.query.get(int(scan_id))
            if scan_obj and scan_obj.user_id == current_user.id:
                scan_obj.pdf_unlocked = True
                db.session.commit()
                return jsonify({"ok": True})
    except Exception as e:
        print(f"[!] Error verificando informe: {e}")
    return jsonify({"ok": False})

@app.route("/api/webhook", methods=["POST"])
def stripe_webhook():
    payload    = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")
    secret     = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except Exception as e:
        print(f"[Webhook] Firma invalida: {e}")
        return jsonify({"error": "firma invalida"}), 400

    try:
        obj  = event.data.object
        tipo = event.type

        if tipo == "checkout.session.completed":
            mode = getattr(obj, "mode", None)
            if mode == "payment":
                # Pago puntual: desbloquear PDF del escaneo
                meta    = getattr(obj, "metadata", {}) or {}
                scan_id = meta.get("scan_id")
                if scan_id:
                    scan_obj = Scan.query.get(int(scan_id))
                    if scan_obj:
                        scan_obj.pdf_unlocked = True
                        db.session.commit()
                        print(f"[Webhook] PDF desbloqueado para scan {scan_id}")
            else:
                # Suscripción Pro
                email = getattr(obj, "customer_email", None)
                if not email:
                    details = getattr(obj, "customer_details", None)
                    if details:
                        email = getattr(details, "email", None)
                print(f"[Webhook] checkout Pro completado, email={email}")
                if email:
                    user = User.query.filter_by(email=email).first()
                    if user:
                        user.plan = "pro"
                        db.session.commit()
                        enviar_email_pro_activado(user)
                        print(f"[Webhook] Plan actualizado a pro para {email}")
                        # Crear factura automática
                        try:
                            desde = datetime.utcnow()
                            hasta = desde + timedelta(days=30)
                            inv = Invoice(
                                user_id=user.id,
                                numero=_generar_numero_factura(),
                                concepto="Plan Pro ReconBase — Suscripción mensual",
                                importe=29.00,
                                moneda='EUR',
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
                            logger.error(f"[Invoice] {_ie}")
                            db.session.rollback()
                    else:
                        print(f"[Webhook] Usuario no encontrado: {email}")

        elif tipo == "customer.subscription.deleted":
            # Look up the customer in Stripe to get their email
            customer_id = getattr(obj, "customer", None)
            email = None
            if customer_id:
                try:
                    customer = stripe.Customer.retrieve(customer_id)
                    email = getattr(customer, "email", None)
                except Exception as e:
                    print(f"[Webhook] Error obteniendo customer: {e}")
            if email:
                user = User.query.filter_by(email=email).first()
                if user:
                    user.plan = "free"
                    db.session.commit()
                    print(f"[Webhook] Plan degradado a free para {email}")
    except Exception as e:
        print(f"[Webhook] Error procesando evento: {e}")
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
                "https://reconbase-production.up.railway.app/app\n\n"
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
                f"https://reconbase-production.up.railway.app/\n\n"
                f"Si quieres que ReconBase vigile tu dominio automáticamente cada noche y te avise si algo cambia, activa el plan Pro:\n"
                f"https://reconbase-production.up.railway.app/#precios\n\n"
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
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
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
                logger.info(f"[Welcome] Email HTML enviado a {email}") # Cambiado
        except Exception as e:
            logger.error(f"[Welcome] Error a {email}: {e}") # Cambiado

    # 3. Lanzamos el hilo pasándole nuestros textos seguros
    threading.Thread(target=_send, args=(email_destino, nombre_empresa), daemon=True).start()

def enviar_email_pro_activado(user):
    # 1. Sacamos los textos MIENTRAS la base de datos está activa
    email_destino = user.email
    nombre_empresa = user.empresa

    # 2. La función ahora recibe esos textos
    def _send(email, empresa):
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
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
            logger.error(f"[Pro] Error a {email}: {e}")
            
    # 3. Arrancamos el hilo pasándole LAS DOS variables seguras
    threading.Thread(target=_send, args=(email_destino, nombre_empresa), daemon=True).start()

def enviar_email_trial_expirando(user, dias_restantes):
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
            dias_txt = f"{dias_restantes} día{'s' if dias_restantes != 1 else ''}"
            with app.app_context():
                send_html_email(
                    user.email,
                    f"Tu trial Pro termina en {dias_txt} — ReconBase",
                    f"⏳ Tu trial termina en {dias_txt}",
                    f"Hola <strong>{user.empresa}</strong>,<br><br>"
                    f"Tu periodo de prueba Pro termina en <strong>{dias_txt}</strong>.<br><br>"
                    f"Cuando expire perderás acceso a: vigilancia nocturna, alertas, filtraciones y PDFs.<br><br>"
                    f"Suscríbete ahora para mantener la protección completa.",
                    cta_url=f"{base_url}/#precios",
                    cta_text="Suscribirme a Pro — 29€/mes"
                )
                logger.info(f"[Trial] Aviso HTML a {user.email} ({dias_restantes}d)")
        except Exception as e:
            logger.error(f"[Trial] Error a {user.email}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_reset(user):
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
            link = f"{base_url}/reset-password/{user.reset_token}"
            with app.app_context():
                send_html_email(
                    user.email,
                    "Restablece tu contraseña — ReconBase",
                    "Restablecer contraseña",
                    "Has solicitado restablecer tu contraseña en ReconBase.<br><br>"
                    "El enlace es válido durante <strong>1 hora</strong>. Si no lo solicitaste, ignora este email.",
                    cta_url=link,
                    cta_text="Restablecer contraseña"
                )
                logger.info(f"[Reset] Email HTML enviado a {user.email}")
        except Exception as e:
            logger.error(f"[Reset] Error a {user.email}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_limite_free(destinatario):
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
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
            logger.error(f"[Limite] Error a {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_lead(destinatario, objetivo, riesgo, label, puertos, dns_info, ssl_info, es_followup=False):
    """Email tras desbloquear informe con email (lead magnet). Si es_followup=True, es el recordatorio 48h."""
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
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
            logger.error(f"[Lead email] Error a {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()


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
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
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
            logger.error(f"[Alerta] Error a {destinatario}: {e}")
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
    objetivo = data.get("objetivo","").strip().replace("https://","").replace("http://","").rstrip("/")
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
    if not es_ip:
        dns     = engine.check_email_spoofing(dominio)
        headers = engine.check_security_headers(dominio)
        subs    = engine.scan_subdomains(dominio)
        cms     = engine.detect_cms(dominio)
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

    # Notificar integraciones (Slack / webhook) en segundo plano
    threading.Thread(target=notificar_integraciones, args=(current_user, resultado), daemon=True).start()

    return jsonify(resultado)

@app.route("/api/historial", methods=["GET"])
@login_required
def historial():
    limite = 3 if current_user.plan == 'free' else 50
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).limit(limite).all()
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
    if not PDF_OK:
        return jsonify({"error": "fpdf2 no instalado"}), 500
    datos = request.get_json()
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_fill_color(8,12,20)
    pdf.rect(0,0,210,40,"F")
    pdf.set_font("Helvetica","B",22)
    w_recon = pdf.get_string_width("RECON")
    w_base  = pdf.get_string_width("BASE")
    x_logo  = (210 - w_recon - w_base) / 2
    pdf.set_y(11)
    pdf.set_x(x_logo)
    pdf.set_text_color(226,237,248)
    pdf.cell(w_recon, 12, "RECON")
    pdf.set_text_color(59,130,246)
    pdf.cell(w_base,  12, "BASE", ln=True)
    pdf.set_font("Helvetica",size=10)
    pdf.set_text_color(71,85,105)
    pdf.cell(0,6,"Informe de Auditoria de Seguridad",ln=True,align="C")
    pdf.ln(15)
    pdf.set_text_color(30,30,30)
    pdf.set_font("Helvetica","B",11)
    pdf.cell(0,8,sanitizar(f"Objetivo: {datos.get('objetivo','')}"),ln=True)
    pdf.set_font("Helvetica",size=10)
    pdf.set_text_color(71,85,105)
    pdf.cell(0,6,sanitizar(f"Fecha: {datos.get('timestamp','')}"),ln=True)
    pdf.cell(0,6,sanitizar(f"Nivel de riesgo: {datos.get('riesgo',0)}% - {datos.get('label','')}"),ln=True)
    pdf.ln(4)
    pdf.set_draw_color(30,45,74)
    pdf.line(10,pdf.get_y(),200,pdf.get_y())
    pdf.ln(5)

    def sec(titulo, contenido):
        pdf.set_font("Helvetica","B",11)
        pdf.set_text_color(30,30,30)
        pdf.cell(0,8,sanitizar(titulo),ln=True)
        pdf.set_font("Helvetica",size=10)
        pdf.set_text_color(71,85,105)
        pdf.multi_cell(0,6,sanitizar(contenido))
        pdf.ln(3)

    puertos = datos.get("puertos",[])
    if puertos:
        lista = ", ".join([f"{p['puerto']}/{p['servicio']}" for p in puertos])
        sec("Red - Puertos Expuestos", f"{len(puertos)} puerto(s): {lista}. Revise el firewall.")
    else:
        sec("Red", "No se detectan puertos expuestos al exterior.")

    dns = datos.get("dns",{})
    sec("Autenticacion de Correo", f"SPF: {'OK' if dns.get('SPF') else 'AUSENTE'}  |  DMARC: {'OK' if dns.get('DMARC') else 'AUSENTE'}.")
    sec("Filtraciones OSINT", f"Registros encontrados: {datos.get('leaks',0)}.")
    subs = datos.get("subs",[])
    sec("Subdominios", f"Total detectados: {len(subs)}." + (f" {', '.join([s['subdominio'] for s in subs[:8]])}" if subs else ""))

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
                f"https://reconbase-production.up.railway.app/app\n\n"
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
                    riesgo, desglose = calcular_riesgo(puertos, dns, [], headers)
                    label, color     = label_riesgo(riesgo)
                    resultado = {
                        "objetivo": objetivo, "dominio": dominio,
                        "puertos": puertos, "dns": dns,
                        "headers": {k: bool(v) for k, v in headers.items()},
                        "subs": subs, "leaks": 0, "leaks_raw": [],
                        "riesgo": riesgo, "label": label, "color": color,
                        "desglose": desglose,
                        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
                        "automatico": True
                    }
                    scan = Scan(user_id=user.id, objetivo=objetivo, dominio=dominio,
                                riesgo=riesgo, label=label, resultado=resultado)
                    db.session.add(scan)
                    db.session.commit()
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
                f"https://reconbase-production.up.railway.app/\n\n"
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
                f"https://reconbase-production.up.railway.app/\n\n"
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
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
            cuerpo = (
                f"Hola {user.empresa},\n\n"
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
                    subject=f"Hace 2 semanas que no revisas la seguridad de {user.empresa} — ReconBase",
                    recipients=[user.email],
                    body=cuerpo
                ))
                print(f"[Reengage] Email enviado a {user.email}")
        except Exception as e:
            print(f"[!] Error reengage {user.email}: {e}")
    threading.Thread(target=_send, daemon=True).start()

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
    """Envía email recordatorio a leads capturados hace 48-72h que aún no han creado cuenta."""
    with app.app_context():
        ahora = datetime.utcnow()
        ventana_ini = ahora - timedelta(hours=72)
        ventana_fin = ahora - timedelta(hours=48)
        try:
            candidatos = Lead.query.filter(
                Lead.created_at >= ventana_ini,
                Lead.created_at <  ventana_fin,
                Lead.followup_sent == False,
                Lead.convertido == False
            ).all()
        except Exception as e:
            logger.warning(f"[LeadFollowup] Query error (tabla nueva?): {e}")
            return

        for lead in candidatos:
            try:
                # Si ya creó cuenta entre medias, marcar convertido y saltar
                if User.query.filter_by(email=lead.email).first():
                    lead.convertido = True
                    lead.followup_sent = True
                    db.session.commit()
                    continue
                r = lead.resultado or {}
                enviar_email_lead(
                    lead.email, lead.objetivo, lead.riesgo,
                    r.get('label', ''), r.get('puertos', []),
                    r.get('dns', {}), r.get('ssl', {}),
                    es_followup=True
                )
                lead.followup_sent = True
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"[LeadFollowup] Error con lead {lead.id}: {e}")

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
    img.save(buf, format="PNG")
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
        return jsonify({"ok": False, "error": "Código 2FA incorrecto"}), 400
    session.pop("2fa_pending_user", None)
    login_user(user)
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
def cookie_consent():
    """Registra el consentimiento de cookies (para cumplir con la ley)."""
    resp = jsonify({"ok": True})
    resp.set_cookie("cookie_consent", "accepted", max_age=365*24*3600, httponly=True, samesite="Lax")
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
          <a href="https://reconbase-production.up.railway.app" style="color:#22C55E;text-decoration:none">reconbase-production.up.railway.app</a>
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
                "User-Agent": "ReconBase/1.0 (+https://reconbase-production.up.railway.app)",
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
    # Limites: free=1, pro=10
    max_doms = 1 if current_user.plan_efectivo == 'free' else 10
    count = Domain.query.filter_by(user_id=current_user.id).count()
    if count >= max_doms:
        plan_txt = "1 dominio en plan Gratis" if max_doms == 1 else f"{max_doms} dominios en plan Pro"
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
    """Envía notificación de resultado de escaneo a Slack y/o webhook custom del usuario."""
    dominio = resultado.get("dominio", "")
    riesgo  = resultado.get("riesgo", 0)
    label   = resultado.get("label", "")
    puertos = resultado.get("puertos", [])
    base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")

    # Slack
    if user.slack_webhook:
        try:
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
            req = urllib.request.Request(user.slack_webhook, data=payload,
                                        headers={"Content-Type": "application/json", "User-Agent": "ReconBase/1.0"},
                                        method="POST")
            urllib.request.urlopen(req, timeout=10)
            logger.info(f"[Slack] Notificación enviada a {user.email}")
        except Exception as e:
            logger.error(f"[Slack] Error para {user.email}: {e}")

    # Custom webhook
    if user.custom_webhook:
        try:
            webhook_payload = json.dumps({
                "event": "scan_completed",
                "dominio": dominio,
                "riesgo": riesgo,
                "label": label,
                "puertos": len(puertos),
                "timestamp": resultado.get("timestamp", ""),
                "url": base_url,
            }).encode("utf-8")
            req = urllib.request.Request(user.custom_webhook, data=webhook_payload,
                                        headers={"Content-Type": "application/json", "User-Agent": "ReconBase/1.0"},
                                        method="POST")
            urllib.request.urlopen(req, timeout=10)
            logger.info(f"[Webhook] Notificación enviada a {user.email}")
        except Exception as e:
            logger.error(f"[Webhook] Error para {user.email}: {e}")

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
                    "https://reconbase-production.up.railway.app/",
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
            "https://reconbase-production.up.railway.app/",
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
        pdf.cell(0, 6, 'reconbase-production.up.railway.app', ln=True)
        pdf.cell(0, 6, 'hola@reconbase.io', ln=True)
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
    ]:
        try:
            db.session.execute(text(col_sql))
            db.session.commit()
        except Exception:
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
