from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id             = db.Column(db.Integer, primary_key=True)
    email          = db.Column(db.String(120), unique=True, nullable=False)
    password       = db.Column(db.String(255), nullable=False)
    empresa        = db.Column(db.String(120), nullable=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    plan           = db.Column(db.String(20), default='free', nullable=False)
    scan_hora      = db.Column(db.Integer, default=3)
    scan_dias      = db.Column(db.String(20), default='0,1,2,3,4,5,6')
    email_verified      = db.Column(db.Boolean, default=False, nullable=False)
    verify_token        = db.Column(db.String(64), nullable=True)
    trial_end           = db.Column(db.DateTime, nullable=True)
    trial_used          = db.Column(db.Boolean, default=False, nullable=False)
    reset_token         = db.Column(db.String(64), nullable=True)
    reset_token_expiry  = db.Column(db.DateTime, nullable=True)
    share_token         = db.Column(db.String(32), nullable=True)
    is_admin            = db.Column(db.Boolean, default=False, nullable=False)
    slack_webhook       = db.Column(db.String(500), nullable=True)
    custom_webhook      = db.Column(db.String(500), nullable=True)
    # 2FA TOTP
    totp_secret         = db.Column(db.String(64), nullable=True)
    totp_enabled        = db.Column(db.Boolean, default=False, nullable=False)
    # Alertas configurables
    alerta_umbral       = db.Column(db.Integer, default=0)
    # API pública
    api_key             = db.Column(db.String(64), unique=True, nullable=True)
    api_calls_month     = db.Column(db.Integer, default=0)
    # Onboarding
    onboarding_done     = db.Column(db.Boolean, default=False, nullable=False)
    # Informe PDF automático
    informe_pdf_activo  = db.Column(db.Boolean, default=False, nullable=False)
    informe_pdf_frecuencia = db.Column(db.String(20), default='semanal')   # semanal | mensual
    informe_pdf_dia     = db.Column(db.Integer, default=1)                 # weekday 0-6 (semanal) o día 1-28 (mensual)

    scans   = db.relationship('Scan',   backref='user', lazy=True)
    domains = db.relationship('Domain', backref='user', lazy=True, cascade='all, delete-orphan')

    @property
    def plan_efectivo(self):
        """Devuelve 'pro' si está en trial activo, si no el plan real."""
        if self.trial_end and datetime.utcnow() < self.trial_end:
            return 'pro'
        return self.plan

    @property
    def trial_activo(self):
        return bool(self.trial_end and datetime.utcnow() < self.trial_end)

    @property
    def trial_dias_restantes(self):
        if self.trial_activo:
            return max(0, (self.trial_end - datetime.utcnow()).days)
        return 0

    def generate_verify_token(self):
        self.verify_token = secrets.token_urlsafe(32)

    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)

    def generate_api_key(self):
        self.api_key = "rb_" + secrets.token_urlsafe(40)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Scan(db.Model):
    __tablename__ = 'scans'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    objetivo   = db.Column(db.String(255), nullable=False)
    dominio    = db.Column(db.String(255), nullable=False)
    riesgo     = db.Column(db.Integer, default=0)
    label      = db.Column(db.String(20), default='')
    resultado     = db.Column(db.JSON, nullable=True)
    pdf_unlocked  = db.Column(db.Boolean, default=False)
    share_token   = db.Column(db.String(32), nullable=True)
    timestamp     = db.Column(db.DateTime, default=datetime.utcnow)


class Domain(db.Model):
    __tablename__ = 'domains'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    dominio    = db.Column(db.String(255), nullable=False)
    activo     = db.Column(db.Boolean, default=True, nullable=False)
    added_at   = db.Column(db.DateTime, default=datetime.utcnow)
    scan_hora  = db.Column(db.Integer, nullable=True)
    scan_dias  = db.Column(db.String(20), nullable=True)

    __table_args__ = (db.UniqueConstraint('user_id', 'dominio', name='uq_user_domain'),)


class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    id         = db.Column(db.Integer, primary_key=True)
    slug       = db.Column(db.String(200), unique=True, nullable=False)
    titulo     = db.Column(db.String(300), nullable=False)
    excerpt    = db.Column(db.String(500), nullable=True)
    contenido  = db.Column(db.Text, nullable=False)
    autor      = db.Column(db.String(100), default='ReconBase')
    imagen     = db.Column(db.String(500), nullable=True)
    publicado  = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    tags       = db.Column(db.String(300), nullable=True)


# ─── Monitorización SSL ───────────────────────────────────────────────────────
class SSLCheck(db.Model):
    __tablename__ = 'ssl_checks'
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    dominio        = db.Column(db.String(255), nullable=False)
    valido         = db.Column(db.Boolean, nullable=True)        # None = no se pudo comprobar
    expira         = db.Column(db.DateTime, nullable=True)
    dias_restantes = db.Column(db.Integer, default=0)
    emitido_por    = db.Column(db.String(300), nullable=True)
    sujeto         = db.Column(db.String(300), nullable=True)
    error          = db.Column(db.String(500), nullable=True)
    checked_at     = db.Column(db.DateTime, default=datetime.utcnow)


# ─── Monitorización Uptime ───────────────────────────────────────────────────
class UptimeCheck(db.Model):
    __tablename__ = 'uptime_checks'
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    dominio     = db.Column(db.String(255), nullable=False)
    up          = db.Column(db.Boolean, default=True, nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    response_ms = db.Column(db.Integer, nullable=True)
    checked_at  = db.Column(db.DateTime, default=datetime.utcnow)


# ─── Notificaciones in-app ───────────────────────────────────────────────────
class Notification(db.Model):
    __tablename__ = 'notifications'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tipo       = db.Column(db.String(50), nullable=False)   # ssl | uptime | dns | scan | ip_rep | sistema | trial
    titulo     = db.Column(db.String(300), nullable=False)
    mensaje    = db.Column(db.Text, nullable=True)
    leida      = db.Column(db.Boolean, default=False, nullable=False)
    url        = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ─── Registros DNS (para detección de cambios) ───────────────────────────────
class DNSRecord(db.Model):
    __tablename__ = 'dns_records'
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    dominio     = db.Column(db.String(255), nullable=False)
    tipo        = db.Column(db.String(10), nullable=False)   # A | MX | TXT | NS | CNAME
    valor       = db.Column(db.Text, nullable=False)
    primera_vez = db.Column(db.DateTime, default=datetime.utcnow)
    ultima_vez  = db.Column(db.DateTime, default=datetime.utcnow)
    activo      = db.Column(db.Boolean, default=True, nullable=False)  # False = eliminado

    __table_args__ = (db.UniqueConstraint('user_id', 'dominio', 'tipo', 'valor', name='uq_dns_record'),)


# ─── Detección de tecnologías ─────────────────────────────────────────────────
class TechDetection(db.Model):
    __tablename__ = 'tech_detections'
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    dominio      = db.Column(db.String(255), nullable=False)
    tecnologias  = db.Column(db.Text, nullable=True)   # JSON: [{nombre, categoria, version}]
    headers_raw  = db.Column(db.Text, nullable=True)   # JSON: {header: value}
    detected_at  = db.Column(db.DateTime, default=datetime.utcnow)


# ─── Reputación IP ────────────────────────────────────────────────────────────
class IPReputation(db.Model):
    __tablename__ = 'ip_reputations'
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    dominio       = db.Column(db.String(255), nullable=False)
    ip            = db.Column(db.String(45), nullable=False)
    limpio        = db.Column(db.Boolean, default=True, nullable=False)
    listas_negras = db.Column(db.Text, nullable=True)   # JSON: [blacklist_name, ...]
    checked_at    = db.Column(db.DateTime, default=datetime.utcnow)


# ─── Audit Log ────────────────────────────────────────────────────────────────
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    evento     = db.Column(db.String(100), nullable=False)
    ip         = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    detalles   = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ─── Facturas ─────────────────────────────────────────────────────────────────
class Invoice(db.Model):
    __tablename__ = 'invoices'
    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    stripe_invoice_id = db.Column(db.String(100), nullable=True)
    numero            = db.Column(db.String(50), nullable=False)   # RB-2026-0001
    concepto          = db.Column(db.String(255), nullable=False)
    importe           = db.Column(db.Float, nullable=False)
    moneda            = db.Column(db.String(10), default='EUR')
    estado            = db.Column(db.String(20), default='pagada')  # pagada | pendiente | cancelada
    periodo_desde     = db.Column(db.DateTime, nullable=True)
    periodo_hasta     = db.Column(db.DateTime, nullable=True)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)
