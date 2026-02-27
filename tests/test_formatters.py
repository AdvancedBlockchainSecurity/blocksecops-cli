"""Tests for output formatters."""

import json
import xml.etree.ElementTree as ET

import pytest

from apogee_cli.formatters import (
    JSONFormatter,
    JUnitFormatter,
    OutputFormat,
    SARIFFormatter,
    TableFormatter,
    get_formatter,
)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
class TestGetFormatter:
    def test_table(self):
        assert isinstance(get_formatter(OutputFormat.TABLE), TableFormatter)

    def test_json(self):
        assert isinstance(get_formatter(OutputFormat.JSON), JSONFormatter)

    def test_sarif(self):
        assert isinstance(get_formatter(OutputFormat.SARIF), SARIFFormatter)

    def test_junit(self):
        assert isinstance(get_formatter(OutputFormat.JUNIT), JUnitFormatter)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------
class TestJSONFormatter:
    def test_format_scan(self, scan_completed, scan_result_with_vulns):
        fmt = JSONFormatter()
        raw = fmt.format_scan(scan_completed, scan_result_with_vulns)
        data = json.loads(raw)

        assert data["scan"]["status"] == "completed"
        assert data["summary"]["total_vulnerabilities"] == 3
        assert data["summary"]["critical"] == 1
        assert len(data["vulnerabilities"]) == 3

    def test_format_scan_empty(self, scan_completed, scan_result_empty):
        fmt = JSONFormatter()
        data = json.loads(fmt.format_scan(scan_completed, scan_result_empty))
        assert data["summary"]["total_vulnerabilities"] == 0
        assert data["vulnerabilities"] == []

    def test_format_summary(self, scan_result_with_vulns):
        fmt = JSONFormatter()
        data = json.loads(fmt.format_summary(scan_result_with_vulns))
        assert data["critical"] == 1
        assert data["medium"] == 1


# ---------------------------------------------------------------------------
# SARIF formatter – branding
# ---------------------------------------------------------------------------
class TestSARIFFormatter:
    def test_tool_name_is_apogee(self, scan_completed, scan_result_with_vulns):
        fmt = SARIFFormatter()
        data = json.loads(fmt.format_scan(scan_completed, scan_result_with_vulns))
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Apogee"
        assert driver["informationUri"] == "https://0xapogee.com"

    def test_summary_tool_name(self, scan_result_empty):
        fmt = SARIFFormatter()
        data = json.loads(fmt.format_summary(scan_result_empty))
        assert data["runs"][0]["tool"]["driver"]["name"] == "Apogee"

    def test_sarif_version(self, scan_completed, scan_result_empty):
        fmt = SARIFFormatter()
        data = json.loads(fmt.format_scan(scan_completed, scan_result_empty))
        assert data["version"] == "2.1.0"

    def test_results_populated(self, scan_completed, scan_result_with_vulns):
        fmt = SARIFFormatter()
        data = json.loads(fmt.format_scan(scan_completed, scan_result_with_vulns))
        results = data["runs"][0]["results"]
        assert len(results) == 3

    def test_severity_mapping(self, scan_completed, scan_result_with_vulns):
        fmt = SARIFFormatter()
        data = json.loads(fmt.format_scan(scan_completed, scan_result_with_vulns))
        results = data["runs"][0]["results"]
        levels = {r["level"] for r in results}
        assert "error" in levels  # critical maps to error

    def test_location_info(self, scan_completed, scan_result_with_vulns):
        fmt = SARIFFormatter()
        data = json.loads(fmt.format_scan(scan_completed, scan_result_with_vulns))
        result = data["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "contracts/Token.sol"
        assert loc["region"]["startLine"] == 42


# ---------------------------------------------------------------------------
# JUnit formatter – branding
# ---------------------------------------------------------------------------
class TestJUnitFormatter:
    def _parse(self, xml_str):
        # strip XML declaration if present
        return ET.fromstring(xml_str.split("\n", 1)[1] if xml_str.startswith("<?xml") else xml_str)

    def test_testsuites_name_is_apogee(self, scan_completed, scan_result_with_vulns):
        fmt = JUnitFormatter()
        root = self._parse(fmt.format_scan(scan_completed, scan_result_with_vulns))
        assert root.get("name") == "Apogee Security Scan"

    def test_testsuite_name_is_apogee(self, scan_completed, scan_result_with_vulns):
        fmt = JUnitFormatter()
        root = self._parse(fmt.format_scan(scan_completed, scan_result_with_vulns))
        ts = root.find("testsuite")
        assert ts.get("name").startswith("Apogee - ")

    def test_classname_uses_0xapogee(self, scan_completed, scan_result_empty):
        fmt = JUnitFormatter()
        root = self._parse(fmt.format_scan(scan_completed, scan_result_empty))
        tc = root.find(".//testcase")
        assert tc.get("classname").startswith("0xapogee.")

    def test_summary_name_is_apogee(self, scan_result_with_vulns):
        fmt = JUnitFormatter()
        root = self._parse(fmt.format_summary(scan_result_with_vulns))
        assert root.get("name") == "Apogee Security Summary"

    def test_summary_classname_0xapogee(self, scan_result_empty):
        fmt = JUnitFormatter()
        root = self._parse(fmt.format_summary(scan_result_empty))
        tc = root.find(".//testcase")
        assert tc.get("classname") == "0xapogee.summary"

    def test_failure_counts(self, scan_completed, scan_result_with_vulns):
        fmt = JUnitFormatter()
        root = self._parse(fmt.format_scan(scan_completed, scan_result_with_vulns))
        # 1 critical + 0 high = 1 failure
        assert root.get("failures") == "1"

    def test_no_blocksecops_in_output(self, scan_completed, scan_result_with_vulns):
        fmt = JUnitFormatter()
        output = fmt.format_scan(scan_completed, scan_result_with_vulns)
        assert "blocksecops" not in output.lower()
        assert "BlockSecOps" not in output


# ---------------------------------------------------------------------------
# Table formatter
# ---------------------------------------------------------------------------
class TestTableFormatter:
    def test_format_scan_returns_string(self, scan_completed, scan_result_with_vulns):
        fmt = TableFormatter()
        output = fmt.format_scan(scan_completed, scan_result_with_vulns)
        assert isinstance(output, str)
        assert "COMPLETED" in output
        # Rich may truncate "CRITICAL" to "CR…" in narrow terminals
        assert "Reentrancy" in output or "Critical" in output or "CR" in output

    def test_format_empty_scan(self, scan_completed, scan_result_empty):
        fmt = TableFormatter()
        output = fmt.format_scan(scan_completed, scan_result_empty)
        assert "0" in output  # 0 vulnerabilities

    def test_format_summary_no_vulns(self, scan_result_empty):
        fmt = TableFormatter()
        output = fmt.format_summary(scan_result_empty)
        assert "No vulnerabilities found" in output

    def test_format_summary_with_vulns(self, scan_result_with_vulns):
        fmt = TableFormatter()
        output = fmt.format_summary(scan_result_with_vulns)
        assert "3" in output


# ---------------------------------------------------------------------------
# OutputFormat enum
# ---------------------------------------------------------------------------
class TestOutputFormat:
    def test_values(self):
        assert OutputFormat.TABLE == "table"
        assert OutputFormat.JSON == "json"
        assert OutputFormat.SARIF == "sarif"
        assert OutputFormat.JUNIT == "junit"

    def test_all_members(self):
        assert len(OutputFormat) == 4
