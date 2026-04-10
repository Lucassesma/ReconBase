from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password   = db.Column(db.String(255), nullable=False)
    empresa    = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    plan       = db.Column(db.String(20), default='free', nullable=False)
    scan_hora  = db.Column(db.Integer, default=3)
    scan_dias  = db.Column(db.String(20), default='0,1,2,3,4,5,6')
    scans      = db.relationship('Scan', backref='user', lazy=True)

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
    resultado  = db.Column(db.JSON, nullable=True)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)
