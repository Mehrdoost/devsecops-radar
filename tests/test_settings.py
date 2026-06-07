import pytest

from devsecops_radar.core.settings import Settings, settings


class TestParseBool:
    def test_truthy_values(self):
        assert Settings._parse_bool("true") is True
        assert Settings._parse_bool("1") is True
        assert Settings._parse_bool("t") is True
        assert Settings._parse_bool("yes") is True
        assert Settings._parse_bool("y") is True
        assert Settings._parse_bool("on") is True
        # case insensitive
        assert Settings._parse_bool("True") is True
        assert Settings._parse_bool("YES") is True

    def test_falsy_values(self):
        assert Settings._parse_bool("false") is False
        assert Settings._parse_bool("0") is False
        assert Settings._parse_bool("no") is False
        assert Settings._parse_bool("off") is False
        assert Settings._parse_bool("anything") is False


class TestParsePort:
    def test_valid_ports(self):
        assert Settings._parse_port("8080") == 8080
        assert Settings._parse_port("1") == 1
        assert Settings._parse_port("65535") == 65535

    def test_port_too_low(self):
        with pytest.raises(ValueError):
            Settings._parse_port("0")

    def test_port_too_high(self):
        with pytest.raises(ValueError):
            Settings._parse_port("65536")

    def test_non_numeric(self):
        with pytest.raises(ValueError):
            Settings._parse_port("abc")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            Settings._parse_port("")


class TestValidateJwtSecret:
    def test_missing_secret(self, monkeypatch):
        monkeypatch.delenv("JWT_SECRET", raising=False)
        with pytest.raises(ValueError, match="JWT_SECRET environment variable is required"):
            Settings._validate_jwt_secret()

    def test_secret_too_short(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "short")
        with pytest.raises(ValueError, match="at least 32 characters"):
            Settings._validate_jwt_secret()

    def test_valid_secret(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "A" * 32)
        assert Settings._validate_jwt_secret() == "A" * 32


class TestValidateApiKey:
    def test_missing_key(self, monkeypatch):
        monkeypatch.delenv("PIPELINE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="PIPELINE_API_KEY environment variable is required"):
            Settings._validate_api_key()

    def test_key_disabled(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_API_KEY", "disabled")
        with pytest.raises(ValueError, match="PIPELINE_API_KEY value 'disabled' is strictly prohibited."):
            Settings._validate_api_key()

    def test_key_disabled_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_API_KEY", "DISABLED")
        with pytest.raises(ValueError):
            Settings._validate_api_key()

    def test_valid_key(self, monkeypatch):
        monkeypatch.setenv("PIPELINE_API_KEY", "my-secret-key")
        assert Settings._validate_api_key() == "my-secret-key"


class TestSettingsInitialization:
    def test_successful_creation(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "X" * 32)
        monkeypatch.setenv("PIPELINE_API_KEY", "abc123")
        monkeypatch.setenv("PORT", "3000")
        monkeypatch.setenv("DEBUG", "true")
        monkeypatch.setenv("HOST", "0.0.0.0")

        s = Settings()
        assert s.HOST == "0.0.0.0"
        assert s.PORT == 3000
        assert s.DEBUG is True
        assert s.JWT_SECRET == "X" * 32
        assert s.PIPELINE_API_KEY == "abc123"

    def test_default_host(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "Y" * 32)
        monkeypatch.setenv("PIPELINE_API_KEY", "key")
        s = Settings()
        assert s.HOST == "127.0.0.1"

    def test_default_port_debug(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "Z" * 32)
        monkeypatch.setenv("PIPELINE_API_KEY", "key")
        s = Settings()
        assert s.PORT == 8080
        assert s.DEBUG is False

    def test_invalid_jwt_causes_error(self, monkeypatch):
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.setenv("PIPELINE_API_KEY", "key")
        with pytest.raises(ValueError, match="JWT_SECRET"):
            Settings()

    def test_invalid_api_key_causes_error(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "A" * 32)
        monkeypatch.delenv("PIPELINE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="PIPELINE_API_KEY"):
            Settings()

    def test_invalid_port_causes_error(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "B" * 32)
        monkeypatch.setenv("PIPELINE_API_KEY", "key")
        monkeypatch.setenv("PORT", "invalid")
        with pytest.raises(ValueError, match="Invalid PORT"):
            Settings()


class TestSettingsSingleton:
    def test_singleton_exists(self):
        # The singleton is already imported; just check it's an instance of Settings
        assert isinstance(settings, Settings)
