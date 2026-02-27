"""Regression tests ensuring the blocksecops → 0xapogee rename is complete.

These tests scan every source file, config file, and doc file for stale
references to the old branding.  They act as a safety net so that any
future change that accidentally re-introduces an old name is caught.
"""

import os
import re
from pathlib import Path

import yaml
import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "apogee_cli"


# ---------------------------------------------------------------------------
# 1. The old module directory must not exist
# ---------------------------------------------------------------------------
class TestDirectoryRename:
    def test_old_module_dir_does_not_exist(self):
        assert not (ROOT / "src" / "blocksecops_cli").exists()

    def test_new_module_dir_exists(self):
        assert SRC.is_dir()

    def test_expected_subpackages_exist(self):
        for sub in ("api", "commands", "formatters"):
            assert (SRC / sub).is_dir(), f"Missing subpackage: {sub}"
            assert (SRC / sub / "__init__.py").exists()


# ---------------------------------------------------------------------------
# 2. No stale "blocksecops" references in Python source
# ---------------------------------------------------------------------------
_ALLOWED_PATTERNS = re.compile(
    r"(api\.blocksecops\.com|docs\.blocksecops\.com|blocksecops\.com|"
    r"support@blocksecops\.com|github\.com/blocksecops)"
)


def _python_files():
    return list(SRC.rglob("*.py"))


class TestNoBlocSecOpsInSource:
    """Every .py file under src/ must be free of old branding."""

    @pytest.mark.parametrize("pyfile", _python_files(), ids=lambda p: str(p.relative_to(ROOT)))
    def test_no_blocksecops_in_python(self, pyfile):
        content = pyfile.read_text()
        # Remove allowed server-side URLs before checking
        cleaned = _ALLOWED_PATTERNS.sub("", content)
        occurrences = [
            (i + 1, line)
            for i, line in enumerate(cleaned.splitlines())
            if "blocksecops" in line.lower()
        ]
        assert occurrences == [], (
            f"Stale 'blocksecops' reference(s) in {pyfile.relative_to(ROOT)}:\n"
            + "\n".join(f"  L{n}: {l.strip()}" for n, l in occurrences)
        )


# ---------------------------------------------------------------------------
# 3. Non-Python config / doc files
# ---------------------------------------------------------------------------
class TestNoBlocSecOpsInConfigs:
    @pytest.mark.parametrize(
        "relpath",
        [
            ".pre-commit-hooks.yaml",
            ".gitignore",
            "hooks/pre-commit-hook.sh",
            "README.md",
            "pyproject.toml",
        ],
    )
    def test_no_blocksecops_in_file(self, relpath):
        filepath = ROOT / relpath
        if not filepath.exists():
            pytest.skip(f"{relpath} not found")
        content = filepath.read_text()
        cleaned = _ALLOWED_PATTERNS.sub("", content)
        occurrences = [
            (i + 1, line)
            for i, line in enumerate(cleaned.splitlines())
            if "blocksecops" in line.lower()
        ]
        assert occurrences == [], (
            f"Stale 'blocksecops' in {relpath}:\n"
            + "\n".join(f"  L{n}: {l.strip()}" for n, l in occurrences)
        )


# ---------------------------------------------------------------------------
# 4. New branding appears where expected
# ---------------------------------------------------------------------------
class TestNewBrandingPresent:
    def test_pyproject_package_name(self):
        content = (ROOT / "pyproject.toml").read_text()
        assert 'name = "0xapogee-cli"' in content

    def test_pyproject_console_script(self):
        content = (ROOT / "pyproject.toml").read_text()
        assert '0xapogee = "apogee_cli.main:cli"' in content

    def test_pyproject_wheel_package(self):
        content = (ROOT / "pyproject.toml").read_text()
        assert 'packages = ["src/apogee_cli"]' in content

    def test_config_app_name(self):
        from apogee_cli.config import APP_NAME
        assert APP_NAME == "0xapogee"

    def test_config_dir_path(self):
        from apogee_cli.config import CONFIG_DIR
        assert CONFIG_DIR.name == ".0xapogee"

    def test_version_string(self):
        from apogee_cli import __version__
        assert __version__ == "0.1.0"

    def test_main_app_name(self):
        from apogee_cli.main import app
        assert app.info.name == "0xapogee"

    def test_client_user_agent(self):
        from apogee_cli.api.client import ApogeeClient
        client = ApogeeClient(api_url="https://api.0xapogee.com", api_key="k")
        headers = client._get_headers()
        assert headers["User-Agent"] == "0xapogee-cli/0.1.0"

    def test_api_default_url(self):
        from apogee_cli.config import Config
        cfg = Config()
        assert cfg.api_url == "https://api.0xapogee.com"

    def test_settings_env_var_alias(self):
        """Settings class should read APOGEE_API_KEY, not BLOCKSECOPS_API_KEY."""
        from apogee_cli.config import Settings
        fields = Settings.model_fields
        assert "apogee_api_key" in fields
        assert "apogee_api_url" in fields
        # Old names must not exist
        assert "blocksecops_api_key" not in fields
        assert "blocksecops_api_url" not in fields


# ---------------------------------------------------------------------------
# 5. Pre-commit hooks YAML
# ---------------------------------------------------------------------------
class TestPreCommitHooks:
    @pytest.fixture(autouse=True)
    def _load(self):
        with open(ROOT / ".pre-commit-hooks.yaml") as f:
            self.hooks = yaml.safe_load(f)

    def test_hook_ids_use_new_name(self):
        for hook in self.hooks:
            assert hook["id"].startswith("0xapogee"), f"Hook id {hook['id']} not renamed"

    def test_hook_entries_use_new_command(self):
        for hook in self.hooks:
            assert hook["entry"].startswith("0xapogee"), f"entry={hook['entry']} not renamed"

    def test_hook_names_use_apogee(self):
        for hook in self.hooks:
            assert "Apogee" in hook["name"], f"name={hook['name']} not renamed"
            assert "BlockSecOps" not in hook["name"]


# ---------------------------------------------------------------------------
# 6. Shell hook
# ---------------------------------------------------------------------------
class TestShellHook:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = (ROOT / "hooks" / "pre-commit-hook.sh").read_text()

    def test_env_vars_renamed(self):
        assert "APOGEE_FAIL_ON" in self.content
        assert "APOGEE_TIMEOUT" in self.content
        assert "APOGEE_OUTPUT" in self.content
        assert "BLOCKSECOPS_" not in self.content

    def test_cli_command_renamed(self):
        assert "0xapogee scan run" in self.content
        assert "0xapogee auth status" in self.content

    def test_install_instruction_renamed(self):
        assert "pip install 0xapogee-cli" in self.content


# ---------------------------------------------------------------------------
# 7. README
# ---------------------------------------------------------------------------
class TestReadme:
    @pytest.fixture(autouse=True)
    def _load(self):
        self.content = (ROOT / "README.md").read_text()

    def test_title(self):
        assert "# Apogee CLI" in self.content

    def test_install_command(self):
        assert "pip install 0xapogee-cli" in self.content

    def test_cli_examples_use_new_name(self):
        assert "0xapogee auth login" in self.content
        assert "0xapogee scan run" in self.content

    def test_env_vars_documented(self):
        assert "APOGEE_API_KEY" in self.content
        assert "APOGEE_API_URL" in self.content

    def test_config_dir_documented(self):
        assert "~/.0xapogee/" in self.content


# ---------------------------------------------------------------------------
# 8. .gitignore
# ---------------------------------------------------------------------------
class TestGitignore:
    def test_new_config_dir(self):
        content = (ROOT / ".gitignore").read_text()
        assert ".0xapogee/" in content
        assert ".blocksecops/" not in content
