"""Tests de regresión de seguridad (sin red: solo IPs literales y nombres internos)."""
import pytest

import reconbase_engine as engine

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
