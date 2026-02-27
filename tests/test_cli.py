"""CLI integration tests – invoke commands via typer CliRunner."""

import json
from unittest.mock import AsyncMock, patch
from uuid import UUID

import pytest
from typer.testing import CliRunner

from apogee_cli.main import app

from .conftest import CONTRACT_UUID, NOW, SCAN_UUID, USER_UUID

runner = CliRunner()


# ---------------------------------------------------------------------------
# Top-level commands
# ---------------------------------------------------------------------------
class TestTopLevel:
    def test_no_args_shows_help(self):
        result = runner.invoke(app)
        # Typer returns 0 or 2 for no-args-is-help depending on version
        assert result.exit_code in (0, 2)
        assert "Apogee CLI" in result.output or "version" in result.output

    def test_help_flag(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Apogee" in result.output
        assert "version" in result.output

    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0xapogee-cli version 0.1.0" in result.output

    def test_no_blocksecops_in_help(self):
        result = runner.invoke(app, ["--help"])
        assert "blocksecops" not in result.output.lower()

    def test_no_blocksecops_in_version(self):
        result = runner.invoke(app, ["version"])
        assert "blocksecops" not in result.output.lower()


# ---------------------------------------------------------------------------
# Auth commands
# ---------------------------------------------------------------------------
class TestAuthLogin:
    def test_login_success(self):
        async def mock_validate(self, key):
            return True

        with (
            patch("apogee_cli.commands.auth.ApogeeClient") as MockClient,
            patch("apogee_cli.commands.auth.set_api_key") as mock_set,
        ):
            instance = MockClient.return_value
            instance.validate_api_key = AsyncMock(return_value=True)
            result = runner.invoke(app, ["auth", "login", "--api-key", "test-key-123"])
        assert result.exit_code == 0
        assert "Successfully authenticated" in result.output

    def test_login_invalid_key(self):
        with patch("apogee_cli.commands.auth.ApogeeClient") as MockClient:
            instance = MockClient.return_value
            instance.validate_api_key = AsyncMock(return_value=False)
            result = runner.invoke(app, ["auth", "login", "--api-key", "bad-key"])
        assert result.exit_code == 1
        assert "Invalid API key" in result.output


class TestAuthLogout:
    def test_logout(self):
        with patch("apogee_cli.commands.auth.clear_api_key") as mock_clear:
            result = runner.invoke(app, ["auth", "logout"])
        assert result.exit_code == 0
        assert "Logged out" in result.output
        mock_clear.assert_called_once()


class TestAuthWhoami:
    def test_not_logged_in(self):
        with patch("apogee_cli.commands.auth.get_api_key", return_value=None):
            result = runner.invoke(app, ["auth", "whoami"])
        assert result.exit_code == 1
        assert "0xapogee auth login" in result.output

    def test_whoami_success(self):
        from apogee_cli.api.models import UserInfo

        user = UserInfo(
            id=USER_UUID, email="user@example.com", tier="growth"
        )
        with (
            patch("apogee_cli.commands.auth.get_api_key", return_value="key"),
            patch("apogee_cli.commands.auth.ApogeeClient") as MockClient,
            patch("apogee_cli.commands.auth.get_api_url", return_value="https://api.0xapogee.com"),
        ):
            instance = MockClient.return_value
            instance.whoami = AsyncMock(return_value=user)
            result = runner.invoke(app, ["auth", "whoami"])
        assert result.exit_code == 0
        assert "user@example.com" in result.output
        assert "growth" in result.output


class TestAuthStatus:
    def test_not_authenticated(self):
        with (
            patch("apogee_cli.commands.auth.get_api_key", return_value=None),
            patch("apogee_cli.commands.auth.get_api_url", return_value="https://api.0xapogee.com"),
        ):
            result = runner.invoke(app, ["auth", "status"])
        assert "Not authenticated" in result.output
        assert "0xapogee auth login" in result.output

    def test_authenticated(self, user_info):
        with (
            patch("apogee_cli.commands.auth.get_api_key", return_value="key"),
            patch("apogee_cli.commands.auth.get_api_url", return_value="https://api.0xapogee.com"),
            patch("apogee_cli.commands.auth.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.whoami = AsyncMock(return_value=user_info)
            result = runner.invoke(app, ["auth", "status"])
        assert "Authenticated as user@example.com" in result.output


# ---------------------------------------------------------------------------
# Scan commands
# ---------------------------------------------------------------------------
class TestScanRun:
    def test_requires_auth(self, tmp_sol_file):
        with patch("apogee_cli.commands.scan.get_api_key", return_value=None):
            result = runner.invoke(app, ["scan", "run", str(tmp_sol_file)])
        assert result.exit_code == 1
        assert "0xapogee auth login" in result.output

    def test_scan_no_wait(self, tmp_sol_file, scan_pending):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.scan_file = AsyncMock(return_value=(scan_pending, None))
            result = runner.invoke(
                app, ["scan", "run", str(tmp_sol_file), "--no-wait"]
            )
        assert result.exit_code == 0
        assert "Scan started" in result.output
        assert "0xapogee scan status" in result.output

    def test_scan_with_results(self, tmp_sol_file, scan_completed, scan_result_with_vulns):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.scan_file = AsyncMock(
                return_value=(scan_completed, scan_result_with_vulns)
            )
            result = runner.invoke(
                app, ["scan", "run", str(tmp_sol_file), "--output", "json"]
            )
        assert result.exit_code == 0
        # Output should contain JSON with vulnerability data
        assert "total_vulnerabilities" in result.output

    def test_scan_fail_on_threshold(self, tmp_sol_file, scan_completed, scan_result_with_vulns):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.scan_file = AsyncMock(
                return_value=(scan_completed, scan_result_with_vulns)
            )
            result = runner.invoke(
                app, ["scan", "run", str(tmp_sol_file), "--output", "json", "--fail-on", "critical"]
            )
        assert result.exit_code == 1

    def test_scan_fail_on_no_match(self, tmp_sol_file, scan_completed, scan_result_empty):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.scan_file = AsyncMock(
                return_value=(scan_completed, scan_result_empty)
            )
            result = runner.invoke(
                app, ["scan", "run", str(tmp_sol_file), "--output", "json", "--fail-on", "critical"]
            )
        assert result.exit_code == 0

    def test_scan_failed_status(self, tmp_sol_file, scan_failed):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.scan_file = AsyncMock(return_value=(scan_failed, None))
            result = runner.invoke(app, ["scan", "run", str(tmp_sol_file)])
        assert result.exit_code == 1
        assert "Scan failed" in result.output


class TestScanStatus:
    def test_requires_auth(self):
        with patch("apogee_cli.commands.scan.get_api_key", return_value=None):
            result = runner.invoke(app, ["scan", "status", str(SCAN_UUID)])
        assert result.exit_code == 1
        assert "0xapogee auth login" in result.output

    def test_invalid_uuid(self):
        with patch("apogee_cli.commands.scan.get_api_key", return_value="key"):
            result = runner.invoke(app, ["scan", "status", "not-a-uuid"])
        assert result.exit_code == 1
        assert "Invalid scan ID" in result.output

    def test_shows_status(self, scan_completed):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.get_scan = AsyncMock(return_value=scan_completed)
            result = runner.invoke(app, ["scan", "status", str(SCAN_UUID)])
        assert result.exit_code == 0
        assert "COMPLETED" in result.output


class TestScanResults:
    def test_requires_auth(self):
        with patch("apogee_cli.commands.scan.get_api_key", return_value=None):
            result = runner.invoke(app, ["scan", "results", str(SCAN_UUID)])
        assert result.exit_code == 1

    def test_shows_results_json(self, scan_completed, scan_result_with_vulns):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.get_scan = AsyncMock(return_value=scan_completed)
            instance.get_scan_results = AsyncMock(return_value=scan_result_with_vulns)
            result = runner.invoke(
                app, ["scan", "results", str(SCAN_UUID), "--output", "json"]
            )
        assert result.exit_code == 0
        assert "total_vulnerabilities" in result.output


class TestScanList:
    def test_requires_auth(self):
        with patch("apogee_cli.commands.scan.get_api_key", return_value=None):
            result = runner.invoke(app, ["scan", "list"])
        assert result.exit_code == 1

    def test_empty_list(self):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.list_contracts = AsyncMock(return_value=[])
            result = runner.invoke(app, ["scan", "list"])
        assert result.exit_code == 0
        assert "No contracts found" in result.output

    def test_with_contracts(self, contract):
        with (
            patch("apogee_cli.commands.scan.get_api_key", return_value="key"),
            patch("apogee_cli.commands.scan.ApogeeClient") as MockClient,
        ):
            instance = MockClient.return_value
            instance.list_contracts = AsyncMock(return_value=[contract])
            result = runner.invoke(app, ["scan", "list"])
        assert result.exit_code == 0
        assert "Token.sol" in result.output


# ---------------------------------------------------------------------------
# Auth subcommand help
# ---------------------------------------------------------------------------
class TestSubcommandHelp:
    def test_auth_help(self):
        result = runner.invoke(app, ["auth", "--help"])
        assert result.exit_code == 0
        assert "login" in result.output
        assert "logout" in result.output
        assert "whoami" in result.output
        assert "status" in result.output

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "run" in result.output
        assert "status" in result.output
        assert "results" in result.output
        assert "list" in result.output

    def test_no_blocksecops_in_auth_help(self):
        result = runner.invoke(app, ["auth", "--help"])
        assert "blocksecops" not in result.output.lower()

    def test_no_blocksecops_in_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert "blocksecops" not in result.output.lower()
