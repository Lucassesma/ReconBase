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
    reset_token         = db.Column(db.String(64), nullable=True)
    reset_token_expiry  = db.Column(db.DateTime, nullable=True)
    share_token         = db.Column(db.String(32), nullable=True)
    is_admin            = db.Column(db.Boolean, default=False, nullable=False)
    slack_webhook       = db.Column(db.String(500), nullable=True)
    custom_webhook      = db.Column(db.String(500), nullable=True)
    scans               = db.relationship('Scan', backref='user', lazy=True)
    domains             = db.relationship('Domain', backref='user', lazy=True, cascade='all, delete-orphan')

    @property
    def plan_efectivo(self):
        """Devuelve 'pro' si está en trial activo, si no el plan real."""
        if self.trial_end and datetime.utcnow() < self.trial_end:
            return 'pro'
        return self.plan

    def generate_verify_token(self):
        self.verify_token = secrets.token_urlsafe(32)

    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)

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

    __table_args__ = (db.UniqueConstraint('user_id', 'dominio', name='uq_user_domain'),)
