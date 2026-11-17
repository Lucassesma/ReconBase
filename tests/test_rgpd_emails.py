"""RGPD (supresión, conservación) y LSSI (consentimiento comercial y bajas)."""
from datetime import datetime, timedelta

import pytest

import reconbase_engine as engine
import server
from models import (db, User, Scan, Domain, Notification, AuditLog, LoginAttempt,
                    Lead, Invoice, AnonymousScan)


def _crear_usuario(email, password="TestPass123"):
    u = User(email=email, empresa="Empresa")
    u.set_password(password)
    u.email_verified = True
    db.session.add(u)
    db.session.commit()
    return u


@pytest.fixture()
def sin_red(monkeypatch):
    res = {"dominio": "ejemplo.com", "es_ip": False, "puertos": [], "dns": {"SPF": True, "DMARC": True},
           "headers": {}, "subs": [], "leaks": 0, "leaks_raw": [], "cms": {}, "wp": {}, "ps": {},
           "ssl": {"tiene_ssl": True}, "banners": {}, "os": None, "modo": "pasivo", "parcial": True,
           "omitidos": [], "timestamp": "x"}
    monkeypatch.setattr(engine, "analizar", lambda *a, **k: dict(res))
    enviados = []
    monkeypatch.setattr(server, "enviar_email_lead", lambda *a, **k: enviados.append((a, k)))
    monkeypatch.setattr(server, "enviar_email_lead_dia7", lambda *a, **k: enviados.append((a, k)))
    return enviados


class TestSupresion:
    def test_baja_de_cuenta_borra_todo_y_conserva_facturas(self, client, app):
        with app.app_context():
            u = _crear_usuario("borrar@ejemplo.com")
            uid = u.id
        r = client.post("/api/login", json={"email": "borrar@ejemplo.com", "password": "TestPass123"})
        assert r.get_json()["ok"]
        with app.app_context():
            db.session.add_all([
                Scan(user_id=uid, objetivo="a.com", dominio="a.com", resultado={}),
                Domain(user_id=uid, dominio="a.com"),
                Notification(user_id=uid, tipo="scan", titulo="x"),
                Invoice(user_id=uid, numero="RB-1", concepto="Pro", importe=9.0),
                Lead(email="borrar@ejemplo.com", objetivo="a.com", dominio="a.com"),
            ])
            db.session.commit()
            assert AuditLog.query.filter_by(user_id=uid).count() >= 1  # el login deja rastro
        r = client.post("/api/eliminar-cuenta", json={"password": "TestPass123", "confirmacion": "ELIMINAR"})
        assert r.status_code == 200 and r.get_json()["ok"], r.get_json()
        with app.app_context():
            assert db.session.get(User, uid) is None
            for modelo in (Scan, Domain, Notification, AuditLog):
                assert modelo.query.filter_by(user_id=uid).count() == 0
            assert LoginAttempt.query.filter_by(email="borrar@ejemplo.com").count() == 0
            assert Lead.query.filter_by(email="borrar@ejemplo.com").count() == 0
            factura = Invoice.query.filter_by(numero="RB-1").first()
            assert factura.user_id is None and factura.cliente_email == "borrar@ejemplo.com"

    def test_exportacion_incluye_todos_los_datos(self, client, app):
        with app.app_context():
            _crear_usuario("exporta@ejemplo.com")
        client.post("/api/login", json={"email": "exporta@ejemplo.com", "password": "TestPass123"})
        datos = client.get("/api/exportar-datos").get_json(force=True)
        for clave in ("usuario", "dominios", "escaneos", "notificaciones", "registro_de_actividad", "intentos_de_acceso"):
            assert clave in datos
        client.post("/api/logout")


class TestConservacion:
    def test_cron_borra_lo_caducado_y_respeta_lo_reciente(self, app):
        with app.app_context():
            viejo = datetime.utcnow() - timedelta(days=400)
            db.session.add_all([
                LoginAttempt(email="x@y.com", exito=False, created_at=viejo),
                LoginAttempt(email="reciente@y.com", exito=False),
                AnonymousScan(dominio="v.com", created_at=viejo),
                Lead(email="sin@consent.com", objetivo="a", dominio="a", created_at=datetime.utcnow() - timedelta(days=91)),
                Lead(email="con@consent.com", objetivo="a", dominio="a", acepta_comercial=True,
                     created_at=datetime.utcnow() - timedelta(days=91)),
            ])
            db.session.commit()
            server.cron_retencion_datos()
            assert LoginAttempt.query.filter_by(email="x@y.com").count() == 0
            assert LoginAttempt.query.filter_by(email="reciente@y.com").count() == 1
            assert AnonymousScan.query.filter_by(dominio="v.com").count() == 0
            assert Lead.query.filter_by(email="sin@consent.com").count() == 0
            assert Lead.query.filter_by(email="con@consent.com").count() == 1


class TestComunicacionesComerciales:
    def test_lead_sin_consentimiento_no_recibe_seguimiento(self, client, app, sin_red):
        client.post("/api/lead-unlock", json={"email": "nocom@ejemplo.com", "objetivo": "ejemplo.com"})
        client.post("/api/lead-unlock", json={"email": "sicom@ejemplo.com", "objetivo": "ejemplo.com", "acepta_comercial": True})
        with app.app_context():
            assert Lead.query.filter_by(email="nocom@ejemplo.com").first().acepta_comercial is False
            si = Lead.query.filter_by(email="sicom@ejemplo.com").first()
            assert si.acepta_comercial is True and si.consentimiento_at is not None
            for lead in Lead.query.filter(Lead.email.in_(["nocom@ejemplo.com", "sicom@ejemplo.com"])).all():
                lead.created_at = datetime.utcnow() - timedelta(days=2, hours=1)
            db.session.commit()
            sin_red.clear()
            server.cron_lead_followup()
            destinatarios = [a[0] for a, k in sin_red]
            assert destinatarios == ["sicom@ejemplo.com"]

    def test_limite_de_informes_por_destinatario(self, client, sin_red):
        for _ in range(3):
            assert client.post("/api/lead-unlock", json={"email": "limite@ejemplo.com", "objetivo": "ejemplo.com"}).status_code == 200
        assert client.post("/api/lead-unlock", json={"email": "limite@ejemplo.com", "objetivo": "ejemplo.com"}).status_code == 429

    def test_baja_firmada(self, client, app):
        with app.app_context():
            u = _crear_usuario("baja@ejemplo.com")
            u.acepta_comercial = True
            db.session.add(Lead(email="baja@ejemplo.com", objetivo="a", dominio="a", acepta_comercial=True))
            db.session.commit()
            url = server._url_baja("baja@ejemplo.com")
        assert client.get("/baja/token-falso").status_code == 400
        assert client.get(url.replace(server.BASE_URL, "")).status_code == 200
        with app.app_context():
            assert User.query.filter_by(email="baja@ejemplo.com").first().acepta_comercial is False
            lead = Lead.query.filter_by(email="baja@ejemplo.com").first()
            assert lead.unsubscribed is True and lead.acepta_comercial is False

    def test_registro_guarda_la_preferencia(self, client, app, monkeypatch):
        monkeypatch.setattr(server, "enviar_email_verificacion", lambda u: None)
        monkeypatch.setattr(server, "enviar_email_bienvenida", lambda u: None)
        client.post("/api/register", json={"email": "acepta@ejemplo.com", "password": "Secure123", "acepta_comercial": True})
        client.post("/api/logout")
        client.post("/api/register", json={"email": "rechaza@ejemplo.com", "password": "Secure123", "acepta_comercial": False})
        client.post("/api/logout")
        with app.app_context():
            assert User.query.filter_by(email="acepta@ejemplo.com").first().acepta_comercial is True
            assert User.query.filter_by(email="rechaza@ejemplo.com").first().acepta_comercial is False


class TestGratuito:
    def test_no_quedan_pagos(self, client):
        assert client.post("/api/checkout", json={"plan": "pro"}).status_code == 404
        assert client.post("/api/activar-trial").status_code == 404
        r = client.get("/pricing")
        assert r.status_code == 200 and "gratis".encode() in r.data.lower()
        assert client.get("/pago-exito").status_code == 302

    def test_todas_las_cuentas_tienen_todas_las_funciones(self, app):
        with app.app_context():
            assert User(email="z@z.com", empresa="z", plan="free").plan_efectivo == "pro"

    def test_pdf_solo_de_escaneos_propios(self, client, app):
        with app.app_context():
            otro = _crear_usuario("otro-pdf@ejemplo.com")
            db.session.add(Scan(user_id=otro.id, objetivo="a.com", dominio="a.com", resultado={"riesgo": 1}))
            db.session.commit()
            ajeno = Scan.query.filter_by(user_id=otro.id).first().id
            _crear_usuario("pdf@ejemplo.com")
        client.post("/api/login", json={"email": "pdf@ejemplo.com", "password": "TestPass123"})
        assert client.post("/api/pdf", json={"riesgo": 0, "objetivo": "falso.com"}).status_code == 404
        assert client.post("/api/pdf", json={"scan_id": ajeno}).status_code == 404
        client.post("/api/logout")


class TestAvisoTerminos:
    def test_aviso_solo_una_vez_y_con_confirmacion(self, client, app, monkeypatch):
        enviados = []
        monkeypatch.setattr(server, "send_html_email", lambda to, *a, **k: enviados.append(to))
        with app.app_context():
            admin = _crear_usuario("admin-aviso@ejemplo.com")
            admin.is_admin = True
            db.session.commit()
            total = User.query.count()
        client.post("/api/login", json={"email": "admin-aviso@ejemplo.com", "password": "TestPass123"})
        assert client.post("/api/admin/aviso-terminos", json={"prueba": True}).get_json()["enviados"] == 1
        assert client.post("/api/admin/aviso-terminos", json={"confirmacion": "no"}).status_code == 400
        enviados.clear()
        r = client.post("/api/admin/aviso-terminos", json={"confirmacion": "ENVIAR"}).get_json()
        assert r["enviados"] == total and len(enviados) == total
        assert client.post("/api/admin/aviso-terminos", json={"confirmacion": "ENVIAR"}).get_json()["enviados"] == 0
        client.post("/api/logout")

    def test_no_admin_no_puede_enviar(self, client, app):
        with app.app_context():
            _crear_usuario("normal-aviso@ejemplo.com")
        client.post("/api/login", json={"email": "normal-aviso@ejemplo.com", "password": "TestPass123"})
        assert client.post("/api/admin/aviso-terminos", json={"confirmacion": "ENVIAR"}).status_code == 403
        client.post("/api/logout")


class TestBlogCorregido:
    def test_posts_antiguos_se_actualizan(self, app):
        from models import BlogPost
        with app.app_context():
            post = BlogPost.query.filter_by(slug="nis2-espana-empresas-obligadas-como-cumplir-2026").first()
            post.contenido = "contenido antiguo con multas inventadas"
            post.seed_version = 1
            db.session.commit()
            server._sembrar_blog()
            post = BlogPost.query.filter_by(slug="nis2-espana-empresas-obligadas-como-cumplir-2026").first()
            assert "Directiva (UE) 2022/2555" in post.contenido
            assert post.seed_version == server.BLOG_SEEDS_VERSION

    def test_sin_cifras_inventadas(self, app):
        from models import BlogPost
        with app.app_context():
            todo = " ".join(p.contenido for p in BlogPost.query.all())
            for frase in ("340%", "105.000", "43&nbsp;% de los ciberataques", "asesoría de Madrid", "INCIBE-CERT y CCN-CERT) ya pueden imponer"):
                assert frase not in todo, frase
