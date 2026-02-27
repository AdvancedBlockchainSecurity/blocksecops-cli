"""Tests for API data models."""

from datetime import datetime, timezone
from uuid import uuid4

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


class TestVulnerabilitySeverity:
    def test_values(self):
        assert VulnerabilitySeverity.CRITICAL == "critical"
        assert VulnerabilitySeverity.HIGH == "high"
        assert VulnerabilitySeverity.MEDIUM == "medium"
        assert VulnerabilitySeverity.LOW == "low"
        assert VulnerabilitySeverity.INFO == "informational"

    def test_all_members(self):
        assert len(VulnerabilitySeverity) == 5


class TestScanStatus:
    def test_values(self):
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.QUEUED == "queued"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.COMPLETED == "completed"
        assert ScanStatus.FAILED == "failed"
        assert ScanStatus.CANCELLED == "cancelled"


class TestVulnerability:
    def test_minimal(self):
        v = Vulnerability(
            id=uuid4(),
            title="Test",
            description="desc",
            severity=VulnerabilitySeverity.LOW,
            created_at=datetime.now(tz=timezone.utc),
        )
        assert v.file_path is None
        assert v.references == []

    def test_full(self, vuln_critical):
        assert vuln_critical.severity == VulnerabilitySeverity.CRITICAL
        assert vuln_critical.line_number == 42
        assert len(vuln_critical.references) == 1


class TestScan:
    def test_completed(self, scan_completed):
        assert scan_completed.status == ScanStatus.COMPLETED
        assert scan_completed.progress == 100

    def test_pending_defaults(self, scan_pending):
        assert scan_pending.progress == 0
        assert scan_pending.started_at is None

    def test_failed_has_error(self, scan_failed):
        assert scan_failed.error_message == "Internal error"


class TestScanResult:
    def test_empty(self, scan_result_empty):
        assert scan_result_empty.total_vulnerabilities == 0
        assert scan_result_empty.vulnerabilities == []

    def test_with_vulns(self, scan_result_with_vulns):
        assert scan_result_with_vulns.total_vulnerabilities == 3
        assert scan_result_with_vulns.critical_count == 1
        assert scan_result_with_vulns.duration_seconds == 12.5


class TestContract:
    def test_defaults(self, contract):
        assert contract.network == "ethereum"
        assert contract.language == "solidity"
        assert contract.file_count == 1


class TestUploadResponse:
    def test_fields(self, upload_response):
        assert upload_response.filename == "Token.sol"
        assert upload_response.status == "uploaded"


class TestUserInfo:
    def test_fields(self, user_info):
        assert user_info.email == "user@example.com"
        assert user_info.tier == "pro"
        assert user_info.quota is None
