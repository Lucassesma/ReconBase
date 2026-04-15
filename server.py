# ReconBase v2 — build 20260414
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db, User, Scan
import reconbase_engine as engine
import os, io, json, stripe, threading, logging, urllib.request, urllib.error
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

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

db.init_app(app)
mail = Mail(app)

# ─── Wrapper de envío con fallback a Resend (HTTPS) ───
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM    = os.getenv("RESEND_FROM", "ReconBase <onboarding@resend.dev>")

def send_email(to, subject, body):
    """Envía un email. Usa Resend (HTTPS) si RESEND_API_KEY está configurado,
    si no cae a SMTP via Flask-Mail. Lanza excepción si falla para que el caller decida."""
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
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read().decode("utf-8", errors="ignore")
                logger.info(f"[Resend] OK a {to}: {resp_body[:100]}")
                return True
        except urllib.error.HTTPError as he:
            err = he.read().decode("utf-8", errors="ignore")
            logger.error(f"[Resend] HTTPError {he.code} a {to}: {err}")
            raise RuntimeError(f"Resend {he.code}: {err[:200]}")
        except Exception as e:
            logger.exception(f"[Resend] Fallo a {to}: {e}")
            raise
    else:
        # Fallback a SMTP
        mail.send(Message(
            subject=subject,
            recipients=[to] if isinstance(to, str) else to,
            body=body,
        ))
        return True

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

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
    ]
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
    login_user(user)
    return jsonify({"ok": True})

def enviar_email_verificacion(user):
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        logger.error(f"[Verify] MAIL_USER/MAIL_PASS no configurados — no se envía email a {user.email}")
        return False
    email_destino = user.email
    token = user.verify_token
    empresa = user.empresa
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
            link = f"{base_url}/verify-email/{token}"
            cuerpo = (
                f"Hola {empresa},\n\n"
                f"Gracias por registrarte en ReconBase.\n\n"
                f"Confirma tu direccion de email haciendo clic en el siguiente enlace:\n"
                f"{link}\n\n"
                f"Si no has creado esta cuenta, ignora este mensaje.\n\n"
                f"--\nReconBase - Seguridad perimetral para PYMEs\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject="Confirma tu email — ReconBase",
                    recipients=[email_destino],
                    body=cuerpo
                ))
                logger.info(f"[Verify] Email enviado a {email_destino}")
        except Exception as e:
            logger.exception(f"[Verify] Error enviando a {email_destino}: {e}")
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
            session = stripe.billing_portal.Session.create(
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
        return jsonify({"ok": True, "url": session.url})
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
                headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
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
        cuerpo = (
            f"Hola {current_user.empresa},\n\n"
            f"Confirma tu direccion de email haciendo clic en el siguiente enlace:\n"
            f"{link}\n\n"
            f"Si no has solicitado esto, ignora este mensaje.\n\n"
            f"--\nReconBase\n"
        )
        send_email(current_user.email, "Confirma tu email — ReconBase", cuerpo)
        return jsonify({
            "ok": True,
            "msg": f"Email enviado a {current_user.email}. Revisa tu bandeja (y carpeta de spam, puede tardar 1-2 min)."
        })
    except Exception as e:
        logger.exception(f"[Reverify] Fallo a {current_user.email}: {e}")
        err_str = str(e)[:300]
        if "Network is unreachable" in err_str:
            msg = "Railway bloquea SMTP saliente. Añade RESEND_API_KEY en Railway (gratis en resend.com)."
        elif "Username and Password not accepted" in err_str or "534" in err_str:
            msg = "Gmail rechaza las credenciales. Usa una 'contraseña de aplicación' (myaccount.google.com/apppasswords)."
        else:
            msg = f"Error al enviar: {err_str}"
        return jsonify({"ok": False, "error": msg}), 500

@app.route("/api/activar-trial", methods=["POST"])
@login_required
def activar_trial():
    if current_user.trial_end is not None or current_user.plan == 'pro':
        return jsonify({"ok": False, "error": "Ya usaste el periodo de prueba o tienes plan Pro"}), 400
    current_user.trial_end = datetime.utcnow() + timedelta(days=7)
    db.session.commit()
    return jsonify({"ok": True, "trial_end": current_user.trial_end.strftime("%d/%m/%Y")})

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
        crit_count = len([p for p in puertos if p in critical_set])
        riesgo_aprox = min(100, crit_count * 25)
        label_aprox, color_aprox = label_riesgo(riesgo_aprox)
        return jsonify({
            "objetivo": objetivo, "dominio": dominio, "es_ip": es_ip_flag,
            "puertos": puertos,
            "riesgo": riesgo_aprox, "label": label_aprox, "color": color_aprox,
            "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M"),
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
        "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "demo": True, "locked": False
    })

@app.route("/api/checkout", methods=["POST"])
def crear_checkout():
    data = request.get_json()
    plan = data.get("plan", "")
    if plan != "pro" or not STRIPE_PRICE_PRO:
        return jsonify({"error": f"Plan no valido o precio no configurado. PRICE_PRO={STRIPE_PRICE_PRO}"}), 400
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=current_user.email if current_user.is_authenticated else None,
            line_items=[{"price": STRIPE_PRICE_PRO, "quantity": 1}],
            success_url=request.host_url + "pago-exito",
            cancel_url=request.host_url + "#precios",
        )
        return jsonify({"url": session.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/checkout-informe", methods=["POST"])
@login_required
def checkout_informe():
    data    = request.get_json()
    scan_id = data.get("scan_id")
    if not scan_id:
        return jsonify({"error": "scan_id requerido"}), 400
    scan_obj = Scan.query.get(int(scan_id))
    if not scan_obj or scan_obj.user_id != current_user.id:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    try:
        session = stripe.checkout.Session.create(
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
        return jsonify({"url": session.url})
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
    return render_template("perfil.html", user=current_user,
                           scans_mes=scans_mes, total_scans=total_scans,
                           scan_hora=scan_hora, scan_dias=scan_dias)

@app.route("/api/cambiar-password", methods=["POST"])
@login_required
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
    return jsonify({"ok": True})

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
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
            cuerpo = (
                f"Hola {user.empresa},\n\n"
                f"Bienvenido a ReconBase. Tu cuenta está lista.\n\n"
                f"Qué puedes hacer ahora:\n"
                f"  1. Escanear tu dominio para ver tu nivel de riesgo actual\n"
                f"  2. Revisar si tu correo aparece en filtraciones conocidas\n"
                f"  3. Descargar un informe PDF con los hallazgos\n\n"
                f"Empieza ahora:\n"
                f"{base_url}/\n\n"
                f"Si tienes cualquier duda, responde a este email.\n\n"
                f"--\nReconBase - Seguridad perimetral para PYMEs\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject=f"Bienvenido a ReconBase, {user.empresa}",
                    recipients=[user.email],
                    body=cuerpo
                ))
                print(f"[Welcome] Email enviado a {user.email}")
        except Exception as e:
            print(f"[!] Error welcome email {user.email}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_pro_activado(user):
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
            cuerpo = (
                f"Hola {user.empresa},\n\n"
                f"Tu plan Pro de ReconBase está activo. Ahora tienes acceso a:\n\n"
                f"  - Escaneos ilimitados\n"
                f"  - Vigilancia nocturna automática de tu dominio\n"
                f"  - Alertas por email cuando se detecta algo nuevo\n"
                f"  - Búsqueda de filtraciones en bases de datos filtradas\n"
                f"  - Informes PDF ejecutivos completos\n"
                f"  - Historial ilimitado de escaneos\n\n"
                f"Configura la vigilancia nocturna desde el escáner > pestaña Vigilancia:\n"
                f"{base_url}/\n\n"
                f"Gracias por confiar en nosotros.\n\n"
                f"--\nReconBase - Tu seguridad, vigilada 24/7\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject="Tu plan Pro está activo — ReconBase",
                    recipients=[user.email],
                    body=cuerpo
                ))
                print(f"[Pro] Email activación enviado a {user.email}")
        except Exception as e:
            print(f"[!] Error pro email {user.email}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_trial_expirando(user, dias_restantes):
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
            cuerpo = (
                f"Hola {user.empresa},\n\n"
                f"Tu periodo de prueba de ReconBase Pro termina en {dias_restantes} día{'s' if dias_restantes != 1 else ''}.\n\n"
                f"Cuando termine, perderás acceso a:\n"
                f"  - Vigilancia nocturna automática\n"
                f"  - Alertas por email\n"
                f"  - Búsqueda de filtraciones\n"
                f"  - Informes PDF ejecutivos\n\n"
                f"Si quieres mantener la protección completa, suscríbete antes de que expire:\n"
                f"{base_url}/#precios\n\n"
                f"Si no haces nada, tu cuenta pasará automáticamente al plan gratuito.\n\n"
                f"--\nReconBase\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject=f"Tu trial Pro termina en {dias_restantes} día{'s' if dias_restantes != 1 else ''} — ReconBase",
                    recipients=[user.email],
                    body=cuerpo
                ))
                print(f"[Trial] Aviso enviado a {user.email} ({dias_restantes}d)")
        except Exception as e:
            print(f"[!] Error trial email {user.email}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_reset(user):
    def _send():
        try:
            base_url = os.getenv("BASE_URL", "https://reconbase-production.up.railway.app")
            link = f"{base_url}/reset-password/{user.reset_token}"
            cuerpo = (
                f"Hola,\n\n"
                f"Has solicitado restablecer tu contraseña en ReconBase.\n\n"
                f"Haz clic en el siguiente enlace (válido 1 hora):\n"
                f"{link}\n\n"
                f"Si no has solicitado esto, ignora este mensaje.\n\n"
                f"--\nReconBase\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject="Restablece tu contraseña — ReconBase",
                    recipients=[user.email],
                    body=cuerpo
                ))
                print(f"[Reset] Email enviado a {user.email}")
        except Exception as e:
            print(f"[!] Error reset email {user.email}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_email_limite_free(destinatario):
    def _send():
        try:
            cuerpo = (
                "Hola,\n\n"
                "Has usado todos tus escaneos gratuitos de este mes.\n\n"
                "Tu empresa puede seguir expuesta a amenazas que no puedes revisar ahora.\n\n"
                "Con el plan Pro a 29 euros al mes tienes:\n"
                "  - Escaneos ilimitados\n"
                "  - Vigilancia nocturna automatica cada dia\n"
                "  - Alertas por email cuando se detecta algo nuevo\n"
                "  - Informes PDF ejecutivos completos\n"
                "  - Historial completo de todos tus escaneos\n\n"
                "Activa el plan Pro ahora:\n"
                "https://reconbase-production.up.railway.app/#precios\n\n"
                "--\nReconBase - Seguridad perimetral para PYMEs\n"
            )
            with app.app_context():
                mail.send(Message(
                    subject="Has agotado tus escaneos gratuitos este mes — ReconBase",
                    recipients=[destinatario],
                    body=cuerpo
                ))
                print(f"[Limite] Email enviado a {destinatario}")
        except Exception as e:
            print(f"[!] Error limite email {destinatario}: {e}")
    threading.Thread(target=_send, daemon=True).start()

def enviar_alerta_email(destinatario, objetivo, riesgo, label, desglose, riesgo_anterior=None):
    def _send():
        try:
            nivel = "CRITICO" if riesgo >= 70 else "MODERADO" if riesgo >= 40 else "BAJO"
            consejos = {
                "Red":            "Tienes puertos de red expuestos al exterior. Contacta con tu proveedor de hosting para cerrarlos.",
                "SPF ausente":    "Tu dominio no tiene proteccion SPF. Añade un registro SPF en tu DNS.",
                "DMARC ausente":  "Tu dominio no tiene DMARC configurado. Añade un registro DMARC en tu DNS.",
                "Filtraciones":   "Se han encontrado datos en filtraciones conocidas. Cambia las contraseñas afectadas.",
                "CMS desactualizable": "Se ha detectado un CMS que puede tener vulnerabilidades. Mantén siempre la ultima version.",
            }
            desglose_txt = ""
            for k, v in desglose.items():
                if v > 0:
                    consejo = consejos.get(k, "Revisa este punto en tu dashboard.")
                    desglose_txt += f"  - {k}: {consejo}\n"

            subida_txt = ""
            if riesgo_anterior is not None:
                subida_txt = f"CAMBIO RESPECTO AL ANTERIOR: {riesgo_anterior}% -> {riesgo}% (+{riesgo - riesgo_anterior}%)\n\n"

            cuerpo = (
                f"Hola,\n\n"
                f"ReconBase ha detectado un aumento en el nivel de riesgo de tu dominio.\n\n"
                f"DOMINIO: {objetivo}\n"
                f"RIESGO ACTUAL: {riesgo}% - {label} ({nivel})\n"
                f"{subida_txt}"
                f"PUNTOS A REVISAR:\n{desglose_txt}\n"
                f"Ver informe completo:\n"
                f"https://reconbase-production.up.railway.app/app\n\n"
                f"--\nReconBase - Seguridad perimetral para PYMEs\n"
            )
            with app.app_context():
                msg = Message(
                    subject=f"[ReconBase] Alerta de seguridad en {objetivo} - {nivel}",
                    recipients=[destinatario],
                    body=cuerpo
                )
                mail.send(msg)
                print(f"[Alerta] Email enviado a {destinatario} ({objetivo} {riesgo}%)")
        except Exception as e:
            print(f"[!] Error enviando email: {e}")
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
        "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M"),
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
    if riesgo_anterior is None:
        # Primer escaneo: enviar si riesgo es alto
        if riesgo >= 50:
            enviar_alerta_email(current_user.email, objetivo, riesgo, label, desglose, riesgo_anterior)
    elif riesgo > riesgo_anterior:
        enviar_alerta_email(current_user.email, objetivo, riesgo, label, desglose, riesgo_anterior)

    return jsonify(resultado)

@app.route("/api/historial", methods=["GET"])
@login_required
def historial():
    limite = 3 if current_user.plan == 'free' else 50
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).limit(limite).all()
    result = []
    for s in scans:
        r = dict(s.resultado)
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
    return jsonify(scan.resultado)

@app.route("/api/pdf", methods=["POST"])
@login_required
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
            if not user.scan_dias:
                continue  # vigilancia desactivada
            dias = [int(d) for d in user.scan_dias.split(',') if d.strip()]
            if not dias:
                continue
            if user.scan_hora != hora_actual:
                continue
            if dia_actual not in dias:
                continue
            ultimo = Scan.query.filter_by(user_id=user.id).order_by(Scan.timestamp.desc()).first()
            if not ultimo:
                continue
            dominio  = ultimo.dominio
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
            if dias is not None and 0 < dias <= 30:
                # Solo avisar una vez por umbral (7 días y 30 días)
                if dias <= 7 or (dias <= 30 and dias > 7):
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
scheduler.start()

@app.route("/api/horario", methods=["POST"])
@login_required
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
    ]:
        try:
            db.session.execute(text(col_sql))
            db.session.commit()
        except Exception:
            db.session.rollback()

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Demasiadas peticiones. Espera un momento e inténtalo de nuevo."}), 429

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Error 500: {e}")
    return render_template("500.html"), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
