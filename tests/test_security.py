"""Tests de regresión de seguridad (sin red: solo IPs literales y nombres internos)."""
import pytest

import reconbase_engine as engine
import server

DESTINOS_INTERNOS = [
    "127.0.0.1", "localhost", "10.0.0.1", "172.16.5.4", "192.168.1.1",
    "169.254.169.254", "100.64.0.1", "0.0.0.0", "[::1]", "::ffff:127.0.0.1",
    "postgres.railway.internal", "printer.local",
]


class TestAntiSSRF:
    @pytest.mark.parametrize("host", DESTINOS_INTERNOS)
    def test_destinos_internos_bloqueados(self, host):
        assert engine.es_destino_interno(host)
        assert not engine.destino_permitido(host)
        assert engine.ip_publica_de(host) is None

    def test_ip_publica_permitida(self):
        assert engine.destino_permitido("8.8.8.8")
        assert engine.ip_publica_de("8.8.8.8") == "8.8.8.8"

    def test_motor_no_conecta_a_destinos_internos(self):
        assert engine.scan_critical_ports_fast("127.0.0.1") == []
        assert engine.banner_grab("127.0.0.1", [{"puerto": 6379, "servicio": "Redis"}]) == {}
        assert engine.ssl_scan("localhost")["tiene_ssl"] is False

    def test_get_seguro_rechaza_metadatos_cloud(self):
        with pytest.raises(ValueError):
            engine.get_seguro("http://169.254.169.254/latest/meta-data/")

    def test_get_seguro_rechaza_esquemas_no_http(self):
        with pytest.raises(ValueError):
            engine.get_seguro("file:///etc/passwd")

    @pytest.mark.parametrize("endpoint,campo", [
        ("/api/scan-demo", "objetivo"),
        ("/api/auditar-cms", "objetivo"),
        ("/api/check-headers", "dominio"),
        ("/api/skimmer-check", "dominio"),
    ])
    def test_endpoints_publicos_rechazan_red_interna(self, client, endpoint, campo):
        r = client.post(endpoint, json={campo: "169.254.169.254"})
        assert r.status_code == 400
        assert "red interna" in r.get_json()["error"]

    def test_endpoint_rechaza_puerto_en_host_interno(self, client):
        r = client.post("/api/scan-demo", json={"objetivo": "127.0.0.1:6379"})
        assert r.status_code == 400


class _RespFalsa:
    def __init__(self, text="", status_code=200, json_data=None, headers=None, url=""):
        self.text, self.status_code, self._json = text, status_code, json_data
        self.headers, self.url = headers or {}, url

    def json(self):
        return self._json


XSS = "<img src=x onerror=alert(1)>"


class TestContenidoRemotoNoEjecutable:
    """Lo que devuelve una web escaneada no debe poder inyectar HTML en ReconBase."""

    def test_usuarios_wordpress_saneados(self, monkeypatch):
        home = '<meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/x.css">'

        def falso(url, timeout=5, headers=None):
            if url.endswith("/wp-json/wp/v2/users"):
                return _RespFalsa(json_data=[{"name": XSS}, {"name": "José García"}])
            if url.endswith("://web-maliciosa.test"):
                return _RespFalsa(text=home)
            return None

        monkeypatch.setattr(engine, "_safe_get", falso)
        res = engine.wordpress_audit("web-maliciosa.test")
        assert res["users_found"], "debería haber detectado usuarios"
        for nombre in res["users_found"]:
            assert "<" not in nombre and ">" not in nombre
        assert "José García" in res["users_found"]

    def test_evidencia_skimmer_saneada(self, monkeypatch):
        home = ('<div class="/modules/ps_cart/"></div>'
                f'<script src="https://{XSS}googie-analytics.com/a.js"></script>')

        def falso(url, timeout=5, headers=None):
            return _RespFalsa(text=home, url=url) if url.endswith("://tienda-maliciosa.test") else None

        monkeypatch.setattr(engine, "_safe_get", falso)
        res = engine.prestashop_audit("tienda-maliciosa.test")
        assert res["skimmer_suspect"]
        for ev in res["skimmer_evidence"]:
            assert "<" not in ev and ">" not in ev

    def test_version_cms_de_wp_json_saneada(self, monkeypatch):
        def falso(url, timeout=5, headers=None, max_redirects=5):
            if url.endswith("/wp-json/"):
                return _RespFalsa(json_data={"version": XSS})
            return _RespFalsa(text="<html><link href='/wp-content/a.css'></html>")

        monkeypatch.setattr(engine, "get_seguro", falso)
        res = engine.detect_cms("web-maliciosa.test")
        assert res["cms"] == "WordPress"
        assert res["version"] is None or "<" not in str(res["version"])

    def test_plantillas_escapan_datos_remotos(self):
        sumideros = {
            "templates/landing_wordpress.html": ".map(rbEsc).join(', ')",
            "templates/landing_prestashop.html": ".map(rbEsc).join(' · ')",
            "templates/tool_skimmer_check.html": "'<li>'+rbEsc(e)+'</li>'",
            "templates/landing.html": "'<li>'+rbEsc(e)+'</li>'",
            "static/js/scanner.js": "'<li>'+rbEsc(e)+'</li>'",
        }
        for ruta, fragmento in sumideros.items():
            assert fragmento in open(ruta, encoding="utf-8").read(), ruta


PROXY = {"REMOTE_ADDR": "10.0.0.9"}


class TestRateLimitIPReal:
    """El rate limit debe contar por visitante, sin que se pueda falsificar la IP."""

    def test_sin_secreto_ignora_cf_connecting_ip(self, app, monkeypatch):
        monkeypatch.setattr(server, "ORIGIN_SECRET", "")
        with app.test_request_context("/", headers={"CF-Connecting-IP": "1.2.3.4"}, environ_base=PROXY):
            assert server._ip_cliente() == "10.0.0.9"

    def test_secreto_correcto_usa_ip_de_cloudflare(self, app, monkeypatch):
        monkeypatch.setattr(server, "ORIGIN_SECRET", "s3cr3t")
        cab = {"CF-Connecting-IP": "1.2.3.4", "X-Origin-Secret": "s3cr3t"}
        with app.test_request_context("/", headers=cab, environ_base=PROXY):
            assert server._ip_cliente() == "1.2.3.4"

    def test_secreto_incorrecto_no_permite_falsificar_ip(self, app, monkeypatch):
        monkeypatch.setattr(server, "ORIGIN_SECRET", "s3cr3t")
        cab = {"CF-Connecting-IP": "1.2.3.4", "X-Origin-Secret": "inventado"}
        with app.test_request_context("/", headers=cab, environ_base=PROXY):
            assert server._ip_cliente() == "10.0.0.9"

    def test_origin_lock_bloquea_acceso_directo(self, client, monkeypatch):
        monkeypatch.setattr(server, "ORIGIN_SECRET", "s3cr3t")
        monkeypatch.setattr(server, "ORIGIN_LOCK", True)
        assert client.get("/").status_code == 403
        assert client.get("/", headers={"X-Origin-Secret": "s3cr3t"}).status_code == 200
        assert client.post("/api/webhook", data=b"{}").status_code != 403

    def test_origin_lock_desactivado_por_defecto(self, client, monkeypatch):
        monkeypatch.setattr(server, "ORIGIN_SECRET", "s3cr3t")
        monkeypatch.setattr(server, "ORIGIN_LOCK", False)
        assert client.get("/").status_code == 200
