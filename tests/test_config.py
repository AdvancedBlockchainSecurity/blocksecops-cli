"""Tests for configuration management."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apogee_cli.config import (
    APP_NAME,
    CONFIG_DIR,
    Config,
    Settings,
    clear_api_key,
    delete_api_key,
    get_api_key,
    get_api_url,
    get_config_dir,
    is_ci_mode,
    load_config,
    save_config,
    set_api_key,
    set_api_url,
)


class TestConstants:
    def test_app_name(self):
        assert APP_NAME == "0xapogee"

    def test_config_dir_name(self):
        assert CONFIG_DIR.name == ".0xapogee"

    def test_config_dir_is_in_home(self):
        assert CONFIG_DIR.parent == Path.home()


class TestConfigModel:
    def test_defaults(self):
        cfg = Config()
        assert cfg.api_url == "https://api.0xapogee.com"
        assert cfg.default_output == "table"
        assert cfg.default_severity_threshold == "high"
        assert cfg.ci_mode is False
        assert cfg.color is True

    def test_custom_values(self):
        cfg = Config(api_url="https://custom.example.com", ci_mode=True)
        assert cfg.api_url == "https://custom.example.com"
        assert cfg.ci_mode is True


class TestSettingsModel:
    def test_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            s = Settings(_env_file=None)
            assert s.apogee_api_key is None
            assert s.apogee_api_url is None

    def test_reads_apogee_env_vars(self):
        env = {"APOGEE_API_KEY": "key123", "APOGEE_API_URL": "https://custom.test"}
        with patch.dict(os.environ, env, clear=True):
            s = Settings(_env_file=None)
            assert s.apogee_api_key == "key123"
            assert s.apogee_api_url == "https://custom.test"

    def test_old_env_vars_are_ignored(self):
        """BLOCKSECOPS_API_KEY must NOT be read."""
        env = {"BLOCKSECOPS_API_KEY": "old-key"}
        with patch.dict(os.environ, env, clear=True):
            s = Settings(_env_file=None)
            assert s.apogee_api_key is None


class TestLoadSaveConfig:
    def test_load_default_when_no_file(self, tmp_path):
        with patch("apogee_cli.config.CONFIG_FILE", tmp_path / "nope.json"):
            cfg = load_config()
        assert cfg.api_url == "https://api.0xapogee.com"

    def test_round_trip(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_dir = tmp_path

        with (
            patch("apogee_cli.config.CONFIG_FILE", config_file),
            patch("apogee_cli.config.CONFIG_DIR", config_dir),
        ):
            original = Config(api_url="https://test.example.com", ci_mode=True)
            save_config(original)

            loaded = load_config()
            assert loaded.api_url == "https://test.example.com"
            assert loaded.ci_mode is True


class TestApiKey:
    def test_env_var_takes_precedence(self):
        env = {"APOGEE_API_KEY": "env-key"}
        with patch.dict(os.environ, env, clear=True):
            with patch("apogee_cli.config.keyring") as mock_kr:
                mock_kr.get_password.return_value = "keyring-key"
                key = get_api_key()
        assert key == "env-key"

    def test_falls_back_to_keyring(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("apogee_cli.config.keyring") as mock_kr:
                mock_kr.get_password.return_value = "kr-key"
                key = get_api_key()
        assert key == "kr-key"

    def test_returns_none_when_nothing(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("apogee_cli.config.keyring") as mock_kr:
                mock_kr.get_password.return_value = None
                key = get_api_key()
        assert key is None

    def test_set_api_key_uses_keyring(self):
        with patch("apogee_cli.config.keyring") as mock_kr:
            set_api_key("new-key")
            mock_kr.set_password.assert_called_once_with("0xapogee", "api_key", "new-key")

    def test_set_api_key_file_fallback(self, tmp_path):
        config_dir = tmp_path
        with (
            patch("apogee_cli.config.keyring") as mock_kr,
            patch("apogee_cli.config.get_config_dir", return_value=config_dir),
        ):
            mock_kr.set_password.side_effect = Exception("no keyring")
            set_api_key("fallback-key")
            key_file = config_dir / ".api_key"
            assert key_file.read_text() == "fallback-key"

    def test_delete_api_key(self, tmp_path):
        key_file = tmp_path / ".api_key"
        key_file.write_text("old")
        with (
            patch("apogee_cli.config.keyring") as mock_kr,
            patch("apogee_cli.config.get_config_dir", return_value=tmp_path),
        ):
            delete_api_key()
            mock_kr.delete_password.assert_called_once_with("0xapogee", "api_key")
            assert not key_file.exists()


class TestApiUrl:
    def test_env_var_overrides(self):
        env = {"APOGEE_API_URL": "https://custom.url"}
        with patch.dict(os.environ, env, clear=True):
            url = get_api_url()
        assert url == "https://custom.url"

    def test_falls_back_to_config(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("apogee_cli.config.load_config") as mock_load:
                mock_load.return_value = Config(api_url="https://from-config.com")
                url = get_api_url()
        assert url == "https://from-config.com"

    def test_set_api_url(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_dir = tmp_path

        with (
            patch("apogee_cli.config.CONFIG_FILE", config_file),
            patch("apogee_cli.config.CONFIG_DIR", config_dir),
        ):
            set_api_url("https://new.example.com")
            loaded = load_config()
            assert loaded.api_url == "https://new.example.com"


class TestCiMode:
    def test_ci_env_var(self):
        with patch.dict(os.environ, {"CI": "true"}, clear=True):
            assert is_ci_mode() is True

    def test_config_ci_mode(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("apogee_cli.config.load_config") as mock_load:
                mock_load.return_value = Config(ci_mode=True)
                assert is_ci_mode() is True

    def test_default_false(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("apogee_cli.config.load_config") as mock_load:
                mock_load.return_value = Config()
                assert is_ci_mode() is False
