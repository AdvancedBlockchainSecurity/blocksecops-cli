"""Tests for the ApogeeClient HTTP client."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest

from apogee_cli.api.client import APIError, ApogeeClient, AuthenticationError
from apogee_cli.api.models import ScanStatus

from .conftest import CONTRACT_UUID, NOW, SCAN_UUID, USER_UUID


class TestClientInit:
    def test_explicit_params(self):
        client = ApogeeClient(api_url="https://test.api", api_key="my-key", timeout=60.0)
        assert client.api_url == "https://test.api"
        assert client.api_key == "my-key"
        assert client.timeout == 60.0

    def test_strips_trailing_slash(self):
        client = ApogeeClient(api_url="https://test.api/", api_key="k")
        assert client.api_url == "https://test.api"

    def test_defaults_from_config(self):
        with (
            patch("apogee_cli.api.client.get_api_url", return_value="https://api.0xapogee.com"),
            patch("apogee_cli.api.client.get_api_key", return_value="cfg-key"),
        ):
            client = ApogeeClient()
            assert client.api_url == "https://api.0xapogee.com"
            assert client.api_key == "cfg-key"


class TestHeaders:
    def test_user_agent(self):
        client = ApogeeClient(api_url="https://x", api_key="k")
        h = client._get_headers()
        assert h["User-Agent"] == "0xapogee-cli/0.1.0"

    def test_api_key_header(self):
        client = ApogeeClient(api_url="https://x", api_key="secret-key")
        h = client._get_headers()
        assert h["X-API-Key"] == "secret-key"

    def test_no_api_key_header_when_none(self):
        client = ApogeeClient(api_url="https://x", api_key=None)
        h = client._get_headers()
        assert "X-API-Key" not in h


class TestRequest:
    @pytest.fixture
    def client(self):
        return ApogeeClient(api_url="https://api.test", api_key="k")

    @pytest.mark.asyncio
    async def test_401_raises_auth_error(self, client):
        resp = httpx.Response(401, text="Unauthorized")
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=resp):
            with pytest.raises(AuthenticationError, match="0xapogee auth login"):
                await client._request("GET", "/test")

    @pytest.mark.asyncio
    async def test_403_raises_auth_error(self, client):
        resp = httpx.Response(403, text="Forbidden")
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=resp):
            with pytest.raises(AuthenticationError, match="Access denied"):
                await client._request("GET", "/test")

    @pytest.mark.asyncio
    async def test_500_raises_api_error(self, client):
        resp = httpx.Response(500, text="Server error")
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=resp):
            with pytest.raises(APIError) as exc_info:
                await client._request("GET", "/test")
            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_204_returns_none(self, client):
        resp = httpx.Response(204)
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=resp):
            result = await client._request("DELETE", "/test")
        assert result is None

    @pytest.mark.asyncio
    async def test_200_returns_json(self, client):
        resp = httpx.Response(200, json={"ok": True})
        with patch("httpx.AsyncClient.request", new_callable=AsyncMock, return_value=resp):
            result = await client._request("GET", "/test")
        assert result == {"ok": True}


class TestWhoami:
    @pytest.mark.asyncio
    async def test_whoami(self):
        client = ApogeeClient(api_url="https://api.test", api_key="k")
        user_data = {"id": str(USER_UUID), "email": "me@test.com", "tier": "pro"}
        with patch.object(client, "_request", new_callable=AsyncMock, return_value=user_data):
            user = await client.whoami()
        assert user.email == "me@test.com"


class TestValidateApiKey:
    @pytest.mark.asyncio
    async def test_valid_key(self):
        client = ApogeeClient(api_url="https://api.test", api_key="old-key")
        user_data = {"id": str(USER_UUID), "email": "me@test.com", "tier": "pro"}
        with patch.object(client, "_request", new_callable=AsyncMock, return_value=user_data):
            result = await client.validate_api_key("new-key")
        assert result is True
        # Key should be restored
        assert client.api_key == "old-key"

    @pytest.mark.asyncio
    async def test_invalid_key(self):
        client = ApogeeClient(api_url="https://api.test", api_key="old-key")
        with patch.object(
            client, "_request", new_callable=AsyncMock, side_effect=AuthenticationError("bad")
        ):
            result = await client.validate_api_key("bad-key")
        assert result is False
        assert client.api_key == "old-key"


class TestUploadFile:
    @pytest.mark.asyncio
    async def test_upload_success(self, tmp_sol_file):
        client = ApogeeClient(api_url="https://api.test", api_key="k")
        resp_data = {
            "contract_id": str(CONTRACT_UUID),
            "filename": "Token.sol",
            "status": "uploaded",
            "message": "ok",
        }
        with patch.object(client, "_request", new_callable=AsyncMock, return_value=resp_data):
            upload = await client.upload_file(tmp_sol_file)
        assert upload.contract_id == CONTRACT_UUID

    @pytest.mark.asyncio
    async def test_upload_file_not_found(self):
        client = ApogeeClient(api_url="https://api.test", api_key="k")
        with pytest.raises(FileNotFoundError):
            await client.upload_file(Path("/nonexistent/file.sol"))


class TestScanFile:
    @pytest.mark.asyncio
    async def test_scan_file_no_wait(self, tmp_sol_file):
        client = ApogeeClient(api_url="https://api.test", api_key="k")

        upload_data = {
            "contract_id": str(CONTRACT_UUID),
            "filename": "Token.sol",
            "status": "uploaded",
            "message": "ok",
        }
        scan_data = {
            "id": str(SCAN_UUID),
            "contract_id": str(CONTRACT_UUID),
            "status": "pending",
            "created_at": NOW.isoformat(),
        }

        call_count = 0

        async def mock_request(method, path, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/upload" in path:
                return upload_data
            if "/scans" in path:
                return scan_data

        with patch.object(client, "_request", side_effect=mock_request):
            scan, result = await client.scan_file(tmp_sol_file, wait=False)
        assert scan.status == ScanStatus.PENDING
        assert result is None
