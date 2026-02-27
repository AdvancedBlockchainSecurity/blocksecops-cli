"""Shared fixtures for all tests."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest

from apogee_cli.api.models import (
    Contract,
    Scan,
    ScanResult,
    ScanStatus,
    UploadResponse,
    UserInfo,
    Vulnerability,
    VulnerabilitySeverity,
)


# ---------------------------------------------------------------------------
# Fixed UUIDs for deterministic tests
# ---------------------------------------------------------------------------
SCAN_UUID = UUID("11111111-1111-1111-1111-111111111111")
CONTRACT_UUID = UUID("22222222-2222-2222-2222-222222222222")
VULN_UUID_1 = UUID("33333333-3333-3333-3333-333333333333")
VULN_UUID_2 = UUID("44444444-4444-4444-4444-444444444444")
VULN_UUID_3 = UUID("55555555-5555-5555-5555-555555555555")
USER_UUID = UUID("66666666-6666-6666-6666-666666666666")
NOW = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def user_info():
    return UserInfo(id=USER_UUID, email="user@example.com", tier="pro")


@pytest.fixture
def upload_response():
    return UploadResponse(
        contract_id=CONTRACT_UUID,
        filename="Token.sol",
        status="uploaded",
        message="File uploaded successfully",
    )


@pytest.fixture
def scan_completed():
    return Scan(
        id=SCAN_UUID,
        contract_id=CONTRACT_UUID,
        contract_name="Token.sol",
        status=ScanStatus.COMPLETED,
        progress=100,
        scanners_requested=["slither"],
        scanners_completed=["slither"],
        started_at=NOW,
        completed_at=NOW,
        created_at=NOW,
    )


@pytest.fixture
def scan_pending():
    return Scan(
        id=SCAN_UUID,
        contract_id=CONTRACT_UUID,
        status=ScanStatus.PENDING,
        created_at=NOW,
    )


@pytest.fixture
def scan_failed():
    return Scan(
        id=SCAN_UUID,
        contract_id=CONTRACT_UUID,
        status=ScanStatus.FAILED,
        error_message="Internal error",
        created_at=NOW,
    )


@pytest.fixture
def vuln_critical():
    return Vulnerability(
        id=VULN_UUID_1,
        title="Reentrancy vulnerability",
        description="Contract is vulnerable to reentrancy attack",
        severity=VulnerabilitySeverity.CRITICAL,
        confidence="high",
        category="reentrancy",
        file_path="contracts/Token.sol",
        line_number=42,
        code_snippet="function withdraw() external { msg.sender.call{value: bal}('');",
        recommendation="Use checks-effects-interactions pattern",
        references=["https://swcregistry.io/docs/SWC-107"],
        scanner_id="slither",
        created_at=NOW,
    )


@pytest.fixture
def vuln_medium():
    return Vulnerability(
        id=VULN_UUID_2,
        title="Floating pragma",
        description="Contract uses a floating pragma",
        severity=VulnerabilitySeverity.MEDIUM,
        confidence="high",
        category="best-practices",
        file_path="contracts/Token.sol",
        line_number=1,
        scanner_id="slither",
        created_at=NOW,
    )


@pytest.fixture
def vuln_low():
    return Vulnerability(
        id=VULN_UUID_3,
        title="Missing event emission",
        description="State-changing function does not emit event",
        severity=VulnerabilitySeverity.LOW,
        file_path="contracts/Token.sol",
        line_number=55,
        scanner_id="slither",
        created_at=NOW,
    )


@pytest.fixture
def scan_result_with_vulns(vuln_critical, vuln_medium, vuln_low):
    return ScanResult(
        total_vulnerabilities=3,
        critical_count=1,
        high_count=0,
        medium_count=1,
        low_count=1,
        info_count=0,
        vulnerabilities=[vuln_critical, vuln_medium, vuln_low],
        scanners_used=["slither"],
        duration_seconds=12.5,
    )


@pytest.fixture
def scan_result_empty():
    return ScanResult(
        total_vulnerabilities=0,
        scanners_used=["slither"],
        duration_seconds=5.0,
    )


@pytest.fixture
def contract():
    return Contract(
        id=CONTRACT_UUID,
        name="Token.sol",
        network="ethereum",
        language="solidity",
        status="uploaded",
        created_at=NOW,
    )


@pytest.fixture
def tmp_sol_file(tmp_path):
    """Create a temporary .sol file for scan tests."""
    sol = tmp_path / "Token.sol"
    sol.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n")
    return sol


@pytest.fixture
def mock_api_key():
    """Patch get_api_key to return a fake key."""
    with patch("apogee_cli.config.get_api_key", return_value="test-api-key-123"):
        yield "test-api-key-123"


@pytest.fixture
def mock_no_api_key():
    """Patch get_api_key to return None (unauthenticated)."""
    with patch("apogee_cli.config.get_api_key", return_value=None):
        yield
