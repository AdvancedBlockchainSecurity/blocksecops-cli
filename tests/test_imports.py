"""Tests that all public modules and symbols import correctly under new names."""

import importlib

import pytest


class TestModuleImports:
    """Every module must be importable under apogee_cli.*"""

    @pytest.mark.parametrize(
        "module",
        [
            "apogee_cli",
            "apogee_cli.main",
            "apogee_cli.config",
            "apogee_cli.api",
            "apogee_cli.api.client",
            "apogee_cli.api.models",
            "apogee_cli.commands",
            "apogee_cli.commands.auth",
            "apogee_cli.commands.scan",
            "apogee_cli.formatters",
            "apogee_cli.formatters.base",
            "apogee_cli.formatters.json_formatter",
            "apogee_cli.formatters.sarif_formatter",
            "apogee_cli.formatters.junit_formatter",
            "apogee_cli.formatters.table_formatter",
        ],
    )
    def test_import(self, module):
        mod = importlib.import_module(module)
        assert mod is not None


class TestOldModulesDontExist:
    """blocksecops_cli.* must NOT be importable."""

    @pytest.mark.parametrize(
        "module",
        [
            "blocksecops_cli",
            "blocksecops_cli.main",
            "blocksecops_cli.config",
            "blocksecops_cli.api",
            "blocksecops_cli.api.client",
        ],
    )
    def test_old_import_fails(self, module):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(module)


class TestKeySymbols:
    """Key classes and functions must exist under the new names."""

    def test_apogee_client(self):
        from apogee_cli.api.client import ApogeeClient
        assert ApogeeClient is not None

    def test_no_blocksecops_client(self):
        """BlockSecOpsClient must not exist."""
        from apogee_cli.api import client as mod
        assert not hasattr(mod, "BlockSecOpsClient")

    def test_api_init_exports(self):
        from apogee_cli.api import ApogeeClient, Scan, ScanResult, Vulnerability
        assert all(
            cls is not None for cls in [ApogeeClient, Scan, ScanResult, Vulnerability]
        )

    def test_formatters_exports(self):
        from apogee_cli.formatters import (
            JSONFormatter,
            JUnitFormatter,
            OutputFormat,
            SARIFFormatter,
            TableFormatter,
            get_formatter,
        )
        assert all(
            obj is not None
            for obj in [JSONFormatter, JUnitFormatter, OutputFormat, SARIFFormatter, TableFormatter, get_formatter]
        )

    def test_config_exports(self):
        from apogee_cli.config import (
            APP_NAME,
            CONFIG_DIR,
            get_api_key,
            get_api_url,
            set_api_key,
            delete_api_key,
            load_config,
            save_config,
        )
        assert APP_NAME == "0xapogee"

    def test_version(self):
        from apogee_cli import __version__
        assert __version__ == "0.1.0"

    def test_cli_entry_point(self):
        from apogee_cli.main import cli, app
        assert callable(cli)
        assert app is not None
