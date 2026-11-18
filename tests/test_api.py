"""Tests para los endpoints críticos de ReconBase."""
import json
import pytest


class TestPublicPages:
    """Tests para páginas públicas (sin autenticación)."""

    def test_landing_page(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"RECON" in r.data

    def test_login_page(self, client):
        r = client.get("/login")
        assert r.status_code == 200

    def test_register_page(self, client):
        r = client.get("/register")
        assert r.status_code == 200

    def test_pricing_page(self, client):
        r = client.get("/pricing")
        assert r.status_code == 200

    def test_blog_page(self, client):
        r = client.get("/blog")
        assert r.status_code == 200

    def test_terms_page(self, client):
        r = client.get("/terms")
        assert r.status_code == 200

    def test_privacy_page(self, client):
        r = client.get("/privacy")
        assert r.status_code == 200

    def test_sitemap(self, client):
        r = client.get("/sitemap.xml")
        assert r.status_code == 200
        assert b"urlset" in r.data

    def test_robots(self, client):
        r = client.get("/robots.txt")
        assert r.status_code == 200
        assert b"User-agent" in r.data

    def test_404(self, client):
        r = client.get("/this-page-does-not-exist")
        assert r.status_code == 404


class TestAuth:
    """Tests para autenticación."""

    def test_register(self, client, db_session):
        r = client.post("/api/register", json={
            "email": "nuevo@test.com",
            "password": "Secure123",
            "empresa": "Nueva Corp"
        })
        data = r.get_json()
        assert data["ok"] is True

    def test_register_duplicate(self, client, test_user):
        r = client.post("/api/register", json={
            "email": "test@reconbase.io",
            "password": "Secure123",
            "empresa": "Dup Corp"
        })
        data = r.get_json()
        assert data["ok"] is False
        assert r.status_code == 400

    def test_register_short_password(self, client):
        r = client.post("/api/register", json={
            "email": "short@test.com",
            "password": "123",
            "empresa": "Short"
        })
        data = r.get_json()
        assert data["ok"] is False
        assert r.status_code == 400

    def test_login_success(self, client, test_user):
        r = client.post("/api/login", json={
            "email": "test@reconbase.io",
            "password": "TestPass123"
        })
        data = r.get_json()
        assert data["ok"] is True

    def test_login_wrong_password(self, client, test_user):
        r = client.post("/api/login", json={
            "email": "test@reconbase.io",
            "password": "WrongPass"
        })
        data = r.get_json()
        assert data["ok"] is False
        assert r.status_code == 401

    def test_login_nonexistent(self, client):
        r = client.post("/api/login", json={
            "email": "nobody@test.com",
            "password": "whatever"
        })
        assert r.status_code == 401

    def test_logout(self, client, test_user):
        # Login first
        client.post("/api/login", json={
            "email": "test@reconbase.io",
            "password": "TestPass123"
        })
        r = client.post("/api/logout")
        data = r.get_json()
        assert data["ok"] is True


class TestProtectedEndpoints:
    """Tests para endpoints que requieren autenticación."""

    def _login(self, client):
        r = client.post("/api/login", json={
            "email": "test@reconbase.io",
            "password": "TestPass123"
        })
        assert r.status_code == 200, f"El login falló silenciosamente. Respuesta: {r.get_data(as_text=True)}"

    def test_perfil_requires_login(self, client):
        r = client.get("/perfil")
        assert r.status_code in (302, 401)

    def test_historial_requires_login(self, client):
        r = client.get("/api/historial")
        assert r.status_code in (302, 401)

    def test_cambiar_password(self, client, test_user):
        self._login(client)
        r = client.post("/api/cambiar-password", json={
            "actual": "TestPass123",
            "nueva": "NewSecure456"
        })
        data = r.get_json()
        assert data["ok"] is True
        # Restaurar
        client.post("/api/cambiar-password", json={
            "actual": "NewSecure456",
            "nueva": "TestPass123"
        })

    def test_cambiar_password_wrong(self, client, test_user):
        self._login(client)
        r = client.post("/api/cambiar-password", json={
            "actual": "WrongOldPass",
            "nueva": "NewSecure456"
        })
        data = r.get_json()
        assert data["ok"] is False
        assert r.status_code == 400

    def test_alertas_get(self, client, test_user):
        self._login(client)
        r = client.get("/api/alertas")
        data = r.get_json()
        assert "alerta_umbral" in data

    def test_alertas_set(self, client, test_user):
        self._login(client)
        r = client.post("/api/alertas", json={"alerta_umbral": 70})
        data = r.get_json()
        assert data["ok"] is True

    def test_api_key_generate(self, client, test_user):
        self._login(client)
        r = client.post("/api/apikey", json={})
        data = r.get_json()
        assert data["ok"] is True
        assert data["api_key"].startswith("rb_")

    def test_dominios_crud(self, client, test_user):
        self._login(client)
        # Sin declarar titularidad o autorización no se puede añadir
        r = client.post("/api/dominios", json={"dominio": "test-example.com"})
        assert r.status_code == 400
        # Añadir
        r = client.post("/api/dominios", json={"dominio": "test-example.com", "autorizacion": True})
        data = r.get_json()
        assert data["ok"] is True
        dom_id = data["id"]
        # Listar
        r = client.get("/api/dominios")
        data = r.get_json()
        assert len(data["dominios"]) >= 1
        # Toggle
        r = client.post(f"/api/dominios/{dom_id}/toggle")
        data = r.get_json()
        assert data["ok"] is True
        # Eliminar
        r = client.delete(f"/api/dominios/{dom_id}")
        data = r.get_json()
        assert data["ok"] is True

    def test_integraciones(self, client, test_user):
        self._login(client)
        r = client.get("/api/integraciones")
        data = r.get_json()
        assert "slack_webhook" in data

    def test_exportar_datos(self, client, test_user):
        self._login(client)
        r = client.get("/api/exportar-datos")
        assert r.status_code == 200
        assert r.content_type == "application/json"

    def test_hsts(self, client):
        r = client.get("/")
        assert "Strict-Transport-Security" in r.headers

    def test_x_frame_options(self, client):
        r = client.get("/")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options(self, client):
        r = client.get("/")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_csp(self, client):
        r = client.get("/")
        assert "Content-Security-Policy" in r.headers

    def test_referrer_policy(self, client):
        r = client.get("/")
        assert "Referrer-Policy" in r.headers


class TestCookieConsent:
    """Google solo se carga tras aceptar: ninguna página lo inserta directamente."""

    @pytest.mark.parametrize("ruta", ["/", "/terms", "/privacy", "/cookies", "/pricing", "/blog",
                                      "/login", "/register", "/herramientas", "/auditoria-wordpress",
                                      "/auditoria-prestashop", "/skimmer-check", "/comprobar-cabeceras-http",
                                      "/comprobar-dmarc-spf", "/comprobar-lista-negra", "/auditoria-rapida",
                                      "/escaner-info"])
    def test_paginas_sin_google_antes_del_consentimiento(self, client, ruta):
        html = client.get(ruta).get_data(as_text=True)
        assert "/static/js/consent.js" in html, ruta
        assert "googletagmanager.com/gtm.js" not in html, ruta
        assert "ns.html?id=GTM" not in html, ruta
        assert "'ad_storage':'granted'" not in html, ruta
        assert "data-rb-cookies" in html, ruta


class TestAPIv1:
    """Tests para la API pública."""

    def test_api_v1_no_key(self, client):
        r = client.post("/api/v1/scan", json={"dominio": "example.com"})
        assert r.status_code == 401

    def test_api_v1_bad_key(self, client):
        r = client.post("/api/v1/scan",
                        json={"dominio": "example.com"},
                        headers={"X-API-Key": "rb_fake_key_123"})
        assert r.status_code == 401


class TestEmailDeContacto:
    PAGINAS = ["/", "/terms", "/privacy", "/cookies", "/pricing", "/escaner-info", "/status", "/login"]

    def test_sin_email_configurado_no_se_muestra_ninguno(self, client, monkeypatch):
        import server
        monkeypatch.setattr(server, "CONTACTO_EMAIL", "")
        for ruta in self.PAGINAS:
            html = client.get(ruta).get_data(as_text=True)
            assert 'href="mailto:' not in html and "hola@reconbase" not in html, ruta
        assert client.get("/.well-known/security.txt").status_code == 404
        assert "dirección postal del responsable" in client.get("/privacy").get_data(as_text=True)

    def test_con_email_configurado_aparece(self, client, monkeypatch):
        import server
        monkeypatch.setattr(server, "CONTACTO_EMAIL", "contacto@ejemplo.com")
        for ruta in ["/terms", "/privacy", "/escaner-info"]:
            assert "mailto:contacto@ejemplo.com" in client.get(ruta).get_data(as_text=True), ruta
        assert "contacto@ejemplo.com" in client.get("/.well-known/security.txt").get_data(as_text=True)
