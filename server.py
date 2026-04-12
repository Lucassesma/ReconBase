from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from models import db, User, Scan
import reconbase_engine as engine
import os, io, json, stripe, threading
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
    stats_scans   = Scan.query.count()
    stats_vulns   = int((db.session.query(db.func.sum(Scan.riesgo)).scalar() or 0) / 10)
    stats_breaches = User.query.count()
    return render_template("landing.html", user=current_user,
                           stats_scans=stats_scans,
                           stats_vulns=stats_vulns,
                           stats_breaches=stats_breaches)

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

# ── AUTH API ──
@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    user     = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"ok": False, "error": "Email o contraseña incorrectos"}), 401
    login_user(user)
    return jsonify({"ok": True})

@app.route("/api/register", methods=["POST"])
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
    db.session.add(user)
    db.session.commit()
    login_user(user)
    return jsonify({"ok": True})

@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    logout_user()
    return jsonify({"ok": True})

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
            success_url=request.host_url + "app?pago=ok",
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
                        print(f"[Webhook] Plan actualizado a pro para {email}")
                    else:
                        print(f"[Webhook] Usuario no encontrado: {email}")

        elif tipo == "customer.subscription.deleted":
            metadata = getattr(obj, "metadata", None)
            email = metadata.get("email") if metadata else None
            if email:
                user = User.query.filter_by(email=email).first()
                if user:
                    user.plan = "free"
                    db.session.commit()
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
@login_required
def dashboard():
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
    return render_template("app.html", api_key_ok=bool(API_KEY),
                           plan=current_user.plan, scans_mes=scans_mes,
                           ultimo_auto=ultimo_auto,
                           scan_hora=current_user.scan_hora if current_user.scan_hora is not None else 3,
                           scan_dias=current_user.scan_dias.split(',') if current_user.scan_dias else [])

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
def scan():
    if current_user.plan == "free":
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
    return jsonify([s.resultado for s in scans])

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
scheduler.add_job(escaneo_automatico, 'cron', minute=0)   # cada hora en punto
scheduler.add_job(cron_onboarding,    'cron', hour=10, minute=0)  # diario a las 10:00
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
    ]:
        try:
            db.session.execute(text(col_sql))
            db.session.commit()
        except Exception:
            db.session.rollback()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
