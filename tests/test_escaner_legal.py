"""El escáner solo hace comprobaciones activas sobre dominios verificados."""
from datetime import datetime, timedelta

import pytest

import reconbase_engine as engine
import server
from models import db, User, Domain, ScanOptOut, Notification


class _Resp:
    def __init__(self, text="", status_code=200, headers=None, url="", json_data=None):
        self.text, self.status_code, self.url = text, status_code, url
        self.headers = headers or {}
        self._json = json_data

    def json(self):
        return self._json


@pytest.fixture()
def red_simulada(monkeypatch):
    """Sustituye todo acceso a red del motor y apunta qué comprobaciones se hacen."""
    llamadas = []

    def apunta(nombre, valor):
        def f(*a, **k):
            llamadas.append(nombre)
            return valor
        return f

    home = '<html><meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/plugins/elementor/x.css"></html>'
    monkeypatch.setattr(engine, "scan_critical_ports_fast", apunta("puertos", [{"puerto": 3306, "servicio": "MySQL"}]))
    monkeypatch.setattr(engine, "banner_grab", apunta("banners", {3306: "5.7.0-MySQL"}))
    monkeypatch.setattr(engine, "ssl_scan", apunta("ssl", {"tiene_ssl": True, "dias_restantes": 90}))
    monkeypatch.setattr(engine, "check_security_headers", apunta("cabeceras", {"HSTS": True}))
    monkeypatch.setattr(engine, "check_email_spoofing", apunta("dns", {"SPF": True, "DMARC": False}))
    monkeypatch.setattr(engine, "scan_subdomains", apunta("subdominios", []))
    monkeypatch.setattr(engine, "detect_cms", apunta("cms", {"cms": "WordPress", "version": "6.4.2", "riesgo": True, "detalle": ""}))
    monkeypatch.setattr(engine, "sondear_fichero", apunta("fichero_sensible", None))
    monkeypatch.setattr(engine, "_leer_pagina", apunta("ruta_no_enlazada", (404, "")))

    def safe_get(url, timeout=5, headers=None):
        if url.endswith("/wp-json/wp/v2/users"):
            llamadas.append("usuarios_wp")
            return _Resp(json_data=[{"name": "admin"}])
        return _Resp(text=home, url=url)

    monkeypatch.setattr(engine, "_safe_get", safe_get)
    return llamadas


ACTIVAS = {"puertos", "banners", "fichero_sensible", "ruta_no_enlazada", "usuarios_wp"}


class TestMotorModos:
    def test_pasivo_no_hace_comprobaciones_activas(self, red_simulada):
        res = engine.analizar("ejemplo.com", modo=engine.MODO_PASIVO)
        assert not ACTIVAS & set(red_simulada), red_simulada
        assert res["modo"] == "pasivo" and res["parcial"] is True
        assert res["puertos"] == [] and res["banners"] == {}
        assert res["wp"]["is_wordpress"] and res["wp"]["plugins"] == ["elementor"]
        assert "puertos y servicios expuestos" in res["omitidos"]

    def test_completo_hace_las_comprobaciones_activas(self, red_simulada):
        res = engine.analizar("ejemplo.com", modo=engine.MODO_COMPLETO)
        assert {"puertos", "banners", "fichero_sensible", "ruta_no_enlazada", "usuarios_wp"} <= set(red_simulada)
        assert res["modo"] == "completo" and res["omitidos"] == []
        assert res["wp"]["users_found"] == ["admin"]

    def test_modo_por_defecto_es_pasivo(self, red_simulada):
        engine.analizar("ejemplo.com")
        engine.wordpress_audit("ejemplo.com")
        engine.prestashop_audit("ejemplo.com")
        assert not ACTIVAS & set(red_simulada)

    def test_puntuacion_usa_las_claves_reales(self):
        res = engine.puntuar({"puertos": [], "dns": {"SPF": True, "DMARC": True}, "headers": {},
                              "ssl": {"caducado": True}, "leaks_raw": []})
        assert res["riesgo"] == 20 and res["desglose"] == {"SSL caducado": 20}


class TestFicherosSensiblesSinContenido:
    def test_fichero_expuesto_solo_mira_cabeceras(self):
        assert engine.fichero_expuesto({"status": 200, "content_type": "text/plain", "length": 400})
        assert engine.fichero_expuesto({"status": 200, "content_type": "application/octet-stream", "length": None})
        # La web responde a todo con su home (soft 404): no cuenta.
        assert not engine.fichero_expuesto({"status": 200, "content_type": "text/html; charset=utf-8", "length": 9000})
        assert not engine.fichero_expuesto({"status": 404, "content_type": "text/plain", "length": 400})
        assert not engine.fichero_expuesto(None)

    def test_sondeo_usa_head_y_no_lee_el_cuerpo(self, monkeypatch):
        metodos = []

        class R:
            status_code, headers = 200, {"Content-Type": "text/plain", "Content-Length": "120"}
            def close(self): pass
            @property
            def text(self): raise AssertionError("no se debe leer el contenido")

        def fake(url, timeout=4, method="GET", stream=False, **k):
            metodos.append((method, stream))
            return R()

        monkeypatch.setattr(engine, "peticion_segura", fake)
        info = engine.sondear_fichero("https://ejemplo.com/.env")
        assert info == {"status": 200, "content_type": "text/plain", "length": 120}
        assert metodos == [("HEAD", False)]

    def test_user_agent_identifica_al_escaner(self, monkeypatch):
        vistas = {}

        def fake_request(method, url, timeout=None, headers=None, allow_redirects=None, stream=None):
            vistas.update(headers)
            return _Resp(status_code=200)

        monkeypatch.setattr(engine, "destino_permitido", lambda h: True)
        monkeypatch.setattr(engine.requests, "request", fake_request)
        _Resp.is_redirect = False
        engine.get_seguro("https://ejemplo.com", headers={"User-Agent": "Chrome falso"})
        assert vistas["User-Agent"] == engine.USER_AGENT
        assert "/escaner-info" in engine.USER_AGENT


def _usuario(email, verificado=None, metodo="dns"):
    u = User.query.filter_by(email=email).first()
    if not u:
        u = User(email=email, empresa="Empresa")
        u.set_password("TestPass123")
        u.email_verified = True
        db.session.add(u)
        db.session.commit()
    if verificado:
        d = Domain.query.filter_by(user_id=u.id, dominio=verificado).first() or Domain(user_id=u.id, dominio=verificado)
        d.verificado, d.verif_metodo, d.verif_token = True, metodo, "tok"
        d.verif_comprobado_at = datetime.utcnow()
        db.session.add(d)
        db.session.commit()
    return u


def _login(client, email):
    r = client.post("/api/login", json={"email": email, "password": "TestPass123"})
    assert r.get_json()["ok"] is True


class TestModoSegunVerificacion:
    def test_normalizar_dominio(self):
        n = server._normalizar_dominio
        assert n("https://www.Ejemplo.com/ruta?x=1") == "ejemplo.com"
        assert n("ana@ejemplo.com") == "ejemplo.com"
        assert n("awww.ejemplo.com") == "awww.ejemplo.com"
        assert n("ejemplo.com:8080") == "ejemplo.com"
        assert n("8.8.8.8") == "8.8.8.8"
        assert n("<script>") == "" and n("") == ""

    def test_dns_cubre_subdominios_y_meta_no(self, app):
        with app.app_context():
            u = _usuario("dns@ejemplo.com", verificado="verif-dns.com", metodo="dns")
            assert server._modo_para(u, "verif-dns.com") == "completo"
            assert server._modo_para(u, "tienda.verif-dns.com") == "completo"
            assert server._modo_para(u, "otro.com") == "pasivo"
            u2 = _usuario("meta@ejemplo.com", verificado="verif-meta.com", metodo="meta")
            assert server._modo_para(u2, "verif-meta.com") == "completo"
            assert server._modo_para(u2, "tienda.verif-meta.com") == "pasivo"
            assert server._modo_para(None, "verif-dns.com") == "pasivo"

    def test_visitante_anonimo_recibe_analisis_pasivo(self, client, red_simulada):
        r = client.post("/api/scan-demo", json={"objetivo": "ejemplo.com"})
        d = r.get_json()
        assert r.status_code == 200 and d["modo"] == "pasivo"
        assert not ACTIVAS & set(red_simulada)

    def test_endpoints_publicos_son_pasivos(self, client, red_simulada):
        client.post("/api/auditar-cms", json={"objetivo": "ejemplo.com"})
        client.post("/api/skimmer-check", json={"dominio": "ejemplo.com"})
        client.post("/api/lead-unlock", json={"email": "a@b.com", "objetivo": "ejemplo.com"})
        assert not ACTIVAS & set(red_simulada)

    def test_usuario_con_dominio_verificado_recibe_analisis_completo(self, client, app, red_simulada):
        with app.app_context():
            _usuario("duena@verificado.com", verificado="verificado.com")
        _login(client, "duena@verificado.com")
        d = client.post("/api/scan", json={"objetivo": "verificado.com"}).get_json()
        assert d["modo"] == "completo" and d["puertos"]
        d2 = client.post("/api/scan", json={"objetivo": "ajeno.com"}).get_json()
        assert d2["modo"] == "pasivo" and d2["puertos"] == []
        client.post("/api/logout")


class TestHIBPRestringido:
    def test_solo_email_propio_o_de_dominio_verificado(self, client, app, red_simulada, monkeypatch):
        consultados = []
        monkeypatch.setattr(server, "API_KEY", "clave")
        monkeypatch.setattr(engine, "check_leaks_real", lambda email, key, timeout=8: consultados.append(email) or [])
        with app.app_context():
            _usuario("hibp@propio.com", verificado="mi-empresa.com")
        _login(client, "hibp@propio.com")
        d = client.post("/api/scan", json={"objetivo": "vecino@gmail.com"}).get_json()
        assert d["hibp_estado"] == "no_permitido"
        client.post("/api/scan", json={"objetivo": "hibp@propio.com"})
        client.post("/api/scan", json={"objetivo": "rrhh@mi-empresa.com"})
        assert consultados == ["hibp@propio.com", "rrhh@mi-empresa.com"]
        client.post("/api/logout")
        d = client.post("/api/scan-demo", json={"objetivo": "vecino@gmail.com"}).get_json()
        assert d["hibp_estado"] == "no_permitido"
        assert consultados == ["hibp@propio.com", "rrhh@mi-empresa.com"]


class TestExclusionDelTitular:
    def test_dominio_excluido_no_se_analiza(self, client, app, red_simulada, monkeypatch):
        enviados = []
        monkeypatch.setattr(server, "send_html_email", lambda *a, **k: enviados.append(a))
        r = client.post("/api/excluir-dominio", json={"dominio": "excluido.com", "email": "yo@gmail.com"})
        assert r.status_code == 400  # el email debe ser del dominio
        r = client.post("/api/excluir-dominio", json={"dominio": "excluido.com", "email": "admin@excluido.com"})
        assert r.status_code == 200 and len(enviados) == 1
        # Sin confirmar todavía se puede analizar
        assert client.post("/api/scan-demo", json={"objetivo": "excluido.com"}).status_code == 200
        with app.app_context():
            token = ScanOptOut.query.filter_by(dominio="excluido.com").first().token
        assert client.get(f"/excluir-dominio/confirmar/{token}").status_code == 200
        for url, campo in [("/api/scan-demo", "objetivo"), ("/api/auditar-cms", "objetivo"),
                           ("/api/check-headers", "dominio"), ("/api/skimmer-check", "dominio")]:
            r = client.post(url, json={campo: "tienda.excluido.com"})
            assert r.status_code == 403 and r.get_json()["excluido"] is True

    def test_el_titular_verificado_puede_analizarlo(self, client, app, red_simulada):
        with app.app_context():
            db.session.add(ScanOptOut(dominio="propio-excluido.com", email="a@propio-excluido.com",
                                      token="t-propio", confirmado=True))
            db.session.commit()
            _usuario("titular@propio-excluido.com", verificado="propio-excluido.com")
        assert client.post("/api/scan-demo", json={"objetivo": "propio-excluido.com"}).status_code == 403
        _login(client, "titular@propio-excluido.com")
        assert client.post("/api/scan", json={"objetivo": "propio-excluido.com"}).status_code == 200
        client.post("/api/logout")

    def test_pagina_publica_del_escaner(self, client):
        r = client.get("/escaner-info")
        assert r.status_code == 200 and engine.USER_AGENT.encode() in r.data


class TestVerificacionDeDominios:
    def test_flujo_de_verificacion(self, client, app, monkeypatch):
        with app.app_context():
            _usuario("verifica@ejemplo.com")
        _login(client, "verifica@ejemplo.com")
        d = client.post("/api/dominios", json={"dominio": "por-verificar.com", "autorizacion": True}).get_json()
        assert d["ok"] and d["verificado"] is False
        assert d["instrucciones"]["dns"]["valor"].startswith("reconbase-verificacion=")
        monkeypatch.setattr(server, "_comprobar_verificacion", lambda dom, tok, met: False)
        r = client.post(f"/api/dominios/{d['id']}/verificar", json={"metodo": "dns"})
        assert r.status_code == 400
        monkeypatch.setattr(server, "_comprobar_verificacion", lambda dom, tok, met: met == "meta")
        r = client.post(f"/api/dominios/{d['id']}/verificar", json={"metodo": "meta"})
        assert r.get_json()["verificado"] is True
        client.post("/api/logout")

    def test_meta_en_otro_dominio_no_vale(self, monkeypatch):
        meta = '<meta name="reconbase-verificacion" content="abc123">'
        monkeypatch.setattr(engine, "get_seguro", lambda url, timeout=5, **k: _Resp(text=meta, url="https://otro-sitio.com/"))
        assert server._comprobar_verificacion("ejemplo.com", "abc123", "meta") is False
        monkeypatch.setattr(engine, "get_seguro", lambda url, timeout=5, **k: _Resp(text=meta, url="https://www.ejemplo.com/"))
        assert server._comprobar_verificacion("ejemplo.com", "abc123", "meta") is True
        assert server._comprobar_verificacion("ejemplo.com", "otro", "meta") is False

    def test_reverificacion_mensual_retira_la_verificacion(self, app, monkeypatch):
        monkeypatch.setattr(server, "_comprobar_verificacion", lambda dom, tok, met: False)
        monkeypatch.setattr(server, "send_html_email", lambda *a, **k: None)
        with app.app_context():
            u = _usuario("reverif@ejemplo.com", verificado="caducado.com")
            d = Domain.query.filter_by(user_id=u.id, dominio="caducado.com").first()
            d.verif_comprobado_at = datetime.utcnow() - timedelta(days=31)
            db.session.commit()
            server.cron_reverificar_dominios()
            d = Domain.query.filter_by(user_id=u.id, dominio="caducado.com").first()
            assert d.verificado is False
            assert Notification.query.filter_by(user_id=u.id, tipo="sistema").count() == 1


class TestFuentesDeTerceros:
    def test_lista_negra_sin_clave_no_simula_resultado(self, client, monkeypatch):
        monkeypatch.setattr(server, "WEB_RISK_API_KEY", "")
        r = client.post("/api/check-blacklist", json={"dominio": "ejemplo.com"})
        assert r.status_code == 503 and r.get_json()["disponible"] is False

    def test_web_risk(self, monkeypatch):
        monkeypatch.setattr(engine, "_consultar_web_risk", lambda uri, key, timeout=8: ["MALWARE"] if uri.startswith("https") else [])
        res = engine.check_blacklist("https://www.malo.com/x", web_risk_key="k")
        assert res["listed"] and res["domain"] == "malo.com" and res["sources"][0]["threat"] == "Malware"

    def test_dnsbl_ignora_codigos_de_error(self, monkeypatch):
        import dns.resolver
        monkeypatch.setattr(dns.resolver, "resolve", lambda name, tipo, lifetime=3: ["127.255.255.254"])
        assert server._check_ip_reputacion("1.2.3.4")["limpio"] is True
        monkeypatch.setattr(dns.resolver, "resolve", lambda name, tipo, lifetime=3: ["127.0.0.2"])
        assert server._check_ip_reputacion("1.2.3.4")["limpio"] is False


class TestCertificadoNoValido:
    def test_certificado_no_valido_penaliza(self):
        res = engine.puntuar({"dns": {"SPF": True, "DMARC": True}, "ssl": {"tiene_ssl": True, "valido": False}})
        assert res["desglose"] == {"Certificado SSL no válido": 15}

    def test_certificado_valido_no_penaliza(self):
        res = engine.puntuar({"dns": {"SPF": True, "DMARC": True}, "ssl": {"tiene_ssl": True, "valido": True, "dias_restantes": 90}})
        assert res["riesgo"] == 0
