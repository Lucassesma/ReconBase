"""Fixtures para tests de ReconBase."""
import os
import pytest

# Usar SQLite en memoria para tests
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing"
os.environ["RECONBASE_API_KEY"] = ""
os.environ["STRIPE_SECRET_KEY"] = ""
os.environ["RESEND_API_KEY"] = ""

from server import app as flask_app
from models import db as _db, User


@pytest.fixture(scope="session")
def app():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with flask_app.app_context():
        _db.create_all()
        yield flask_app
        _db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db_session(app):
    with app.app_context():
        yield _db
        _db.session.rollback()


@pytest.fixture()
def test_user(app, db_session):
    """Crea un usuario de test y lo devuelve."""
    with app.app_context():
        user = User.query.filter_by(email="test@reconbase.io").first()
        if not user:
            user = User(email="test@reconbase.io", empresa="Test Corp")
            user.set_password("TestPass123")
            user.email_verified = True
            db_session.session.add(user)
            db_session.session.commit()
        return user
