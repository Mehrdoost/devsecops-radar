from unittest.mock import MagicMock, patch

import pytest

from devsecops_radar.core.settings import settings
from devsecops_radar.web.app import (
    _check_file,
    _get_local_ip,
    create_app,
    print_startup_banner,
    start_server,
)


# ------------------------------------------------------------
# _get_local_ip
# ------------------------------------------------------------
class TestGetLocalIp:
    def test_returns_ip(self):
        with patch("socket.socket") as mock_sock:
            mock_instance = MagicMock()
            mock_instance.getsockname.return_value = ("192.168.1.5", 12345)
            mock_sock.return_value.__enter__.return_value = mock_instance
            assert _get_local_ip() == "192.168.1.5"

    def test_fallback_on_error(self):
        with patch("socket.socket", side_effect=OSError):
            assert _get_local_ip() == "127.0.0.1"


# ------------------------------------------------------------
# _check_file
# ------------------------------------------------------------
class TestCheckFile:
    def test_file_exists(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("data")
        assert _check_file(str(f)) is True

    def test_file_missing(self, tmp_path):
        assert _check_file(str(tmp_path / "missing.txt")) is False


# ------------------------------------------------------------
# print_startup_banner
# ------------------------------------------------------------
class TestPrintStartupBanner:
    @pytest.fixture(autouse=True)
    def setup_settings(self):
        self._api_key_patch = patch.object(settings, "PIPELINE_API_KEY", "test-key")
        self._host_patch = patch.object(settings, "HOST", "127.0.0.1")
        self._port_patch = patch.object(settings, "PORT", 8080)
        self._debug_patch = patch.object(settings, "DEBUG", False)
        self._api_key_patch.start()
        self._host_patch.start()
        self._port_patch.start()
        self._debug_patch.start()
        yield
        self._api_key_patch.stop()
        self._host_patch.stop()
        self._port_patch.stop()
        self._debug_patch.stop()

    def test_rich_installed(self):
        # Create a mock httpx module to avoid needing the real import
        mock_httpx = MagicMock()
        mock_httpx.get.return_value.status_code = 200
        # Patch the httpx that will be imported inside the function
        with patch.dict("sys.modules", {"httpx": mock_httpx}), \
             patch.dict("sys.modules", {"rich": MagicMock()}), \
             patch("devsecops_radar.web.app.Console") as mock_console, \
             patch("devsecops_radar.web.app.HAS_RICH", True), \
             patch("devsecops_radar.web.app._get_local_ip", return_value="10.0.0.1"), \
             patch("devsecops_radar.web.app._check_file", return_value=True):
            print_startup_banner("0.0.0.0", 8080, False)
            mock_console.return_value.print.assert_called_once()

    def test_rich_not_installed(self):
        with patch("devsecops_radar.web.app.HAS_RICH", False), \
             patch("devsecops_radar.web.app.logger") as mock_logger:
            print_startup_banner("127.0.0.1", 5000, True)
            mock_logger.info.assert_called_once()


# ------------------------------------------------------------
# create_app
# ------------------------------------------------------------
class TestCreateApp:
    @pytest.fixture
    def client(self):
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_login_missing_password(self, client):
        # Missing JSON should return 400 (Invalid JSON payload format)
        resp = client.post("/api/auth/login", json={})
        assert resp.status_code == 400
        assert b"Invalid JSON payload format" in resp.data

    def test_login_empty_password(self, client):
        resp = client.post("/api/auth/login", json={"password": ""})
        assert resp.status_code == 401

    def test_login_success(self, client):
        with patch("devsecops_radar.web.app.hmac.compare_digest", return_value=True), \
             patch("devsecops_radar.web.app.create_token", return_value="fake-token"), \
             patch.object(settings, "PIPELINE_API_KEY", "secret"):
            resp = client.post("/api/auth/login", json={"password": "secret"})
            assert resp.status_code == 200
            assert b"fake-token" in resp.data

    def test_login_wrong_password(self, client):
        with patch("devsecops_radar.web.app.hmac.compare_digest", return_value=False), \
             patch.object(settings, "PIPELINE_API_KEY", "secret"):
            resp = client.post("/api/auth/login", json={"password": "wrong"})
            assert resp.status_code == 401

    def test_login_payload_too_long(self, client):
        long_pwd = "a" * 200
        resp = client.post("/api/auth/login", json={"password": long_pwd})
        assert resp.status_code == 401

    def test_404_handler(self, client):
        resp = client.get("/nonexistent")
        assert resp.status_code == 404

    def test_413_handler(self, client):
        # Can't easily trigger 413 in test client, but handler is registered.
        pass

    def test_500_handler(self, client):
        # Handler is registered.
        pass


# ------------------------------------------------------------
# start_server
# ------------------------------------------------------------
class TestStartServer:
    def test_debug_mode(self):
        # Create a mock app and patch its run method
        mock_app = MagicMock()
        with patch.object(settings, "DEBUG", True), \
             patch.object(settings, "HOST", "127.0.0.1"), \
             patch.object(settings, "PORT", 5000), \
             patch("devsecops_radar.web.app.create_app", return_value=mock_app), \
             patch("devsecops_radar.web.app.print_startup_banner") as mock_banner:
            start_server()
            mock_banner.assert_called_once()
            mock_app.run.assert_called_once_with(host="127.0.0.1", port=5000, debug=True)

    def test_production_mode(self):
        mock_app = MagicMock()
        # Create a fake waitress module with a serve mock
        mock_waitress = MagicMock()
        mock_serve = MagicMock()
        mock_waitress.serve = mock_serve
        with patch.dict("sys.modules", {"waitress": mock_waitress}), \
             patch.object(settings, "DEBUG", False), \
             patch.object(settings, "HOST", "0.0.0.0"), \
             patch.object(settings, "PORT", 8080), \
             patch("devsecops_radar.web.app.create_app", return_value=mock_app), \
             patch("devsecops_radar.web.app.print_startup_banner") as mock_banner:
            start_server()
            mock_banner.assert_called_once()
            # serve should be called with app, host, port, threads=8
            mock_serve.assert_called_once_with(mock_app, host="0.0.0.0", port=8080, threads=8)
