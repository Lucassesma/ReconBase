from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from models import db, User, Scan
import reconbase_engine as engine
import os, io, json, stripe, threading
from datetime import datetime
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
@app.route("/")
def index():
    return render_template("landing.html", user=current_user)

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
        return jsonify({"error": "Plan no valido o precio no configurado"}), 400
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer_email=current_user.email if current_user.is_authenticated else None,
        line_items=[{"price": STRIPE_PRICE_PRO, "quantity": 1}],
        success_url=request.host_url + "app?pago=ok",
        cancel_url=request.host_url + "#precios",
    )
    return jsonify({"url": session.url})

@app.route("/api/webhook", methods=["POST"])
def stripe_webhook():
    payload    = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")
    secret     = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except Exception:
        return jsonify({"error": "firma invalida"}), 400

    if event["type"] == "checkout.session.completed":
        email = (event["data"]["object"].get("customer_email") or
                 event["data"]["object"].get("customer_details", {}).get("email"))
        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.plan = "pro"
                db.session.commit()

    elif event["type"] == "customer.subscription.deleted":
        email = event["data"]["object"].get("metadata", {}).get("email")
        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.plan = "free"
                db.session.commit()

    return jsonify({"ok": True})

# ── APP ──
@app.route("/app")
@login_required
def dashboard():
    return render_template("app.html", api_key_ok=bool(API_KEY))

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

def enviar_alerta_email(destinatario, objetivo, riesgo, label, desglose):
    def _send():
        try:
            emoji_nivel = "🔴" if riesgo >= 70 else "🟠" if riesgo >= 40 else "🟡"
            consejos = {
                "Red":            "Tienes puertos de red expuestos al exterior. Esto significa que servicios internos de tu empresa son accesibles desde internet. Contacta con tu proveedor de hosting para cerrarlos.",
                "SPF ausente":    "Tu dominio no tiene proteccion SPF. Cualquiera podria enviar emails haciendose pasar por tu empresa. Añade un registro SPF en tu DNS.",
                "DMARC ausente":  "Tu dominio no tiene DMARC configurado. Esto facilita los ataques de phishing usando tu nombre. Añade un registro DMARC en tu DNS.",
                "Filtraciones":   "Se han encontrado datos de tu empresa en filtraciones conocidas. Cambia las contraseñas afectadas lo antes posible y activa la autenticacion en dos pasos.",
            }
            desglose_txt = ""
            for k, v in desglose.items():
                consejo = consejos.get(k, "Revisa este punto en tu dashboard.")
                desglose_txt += f"  ⚠ {k}\n     {consejo}\n\n"

            with app.app_context():
                msg = Message(
                    subject=f"{emoji_nivel} ReconBase ha detectado vulnerabilidades en {objetivo}",
                    recipients=[destinatario],
                    body=f"""Hola,

ReconBase ha analizado tu dominio y ha encontrado algunos puntos de seguridad que requieren tu atencion.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DOMINIO ANALIZADO: {objetivo}
  NIVEL DE RIESGO:   {riesgo}% — {label} {emoji_nivel}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

QUE HEMOS ENCONTRADO:

{desglose_txt}
¿QUE DEBES HACER AHORA?

Accede a tu dashboard para ver el informe completo con todos los detalles
y los pasos exactos para solucionar cada problema:

  → http://127.0.0.1:5000/app

Si tienes dudas sobre como actuar, puedes responder a este email
y te ayudaremos a interpretar los resultados.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ReconBase — Seguridad perimetral para PYMEs
Este analisis ha sido generado automaticamente.
"""
                )
                mail.send(msg)
        except Exception as e:
            print(f"[!] Error enviando email: {e}")
    threading.Thread(target=_send, daemon=True).start()

@app.route("/api/scan", methods=["POST"])
@login_required
def scan():
    data     = request.get_json()
    objetivo = data.get("objetivo","").strip().replace("https://","").replace("http://","").rstrip("/")
    if not objetivo:
        return jsonify({"error": "Objetivo vacío"}), 400

    dominio  = objetivo.split("@")[-1] if "@" in objetivo else objetivo
    es_email = "@" in objetivo

    puertos = engine.scan_critical_ports_fast(dominio)
    dns     = engine.check_email_spoofing(dominio)
    headers = engine.check_security_headers(dominio)
    subs    = engine.scan_subdomains(dominio)
    leaks   = []
    if es_email and API_KEY:
        leaks = engine.check_leaks_real(objetivo, API_KEY) or []

    riesgo, desglose = calcular_riesgo(puertos, dns, leaks, headers)
    label, color     = label_riesgo(riesgo)

    resultado = {
        "objetivo":  objetivo,
        "dominio":   dominio,
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

    if riesgo >= 30:
        enviar_alerta_email(current_user.email, objetivo, riesgo, label, desglose)

    return jsonify(resultado)

@app.route("/api/historial", methods=["GET"])
@login_required
def historial():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).limit(20).all()
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

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
