"""
Tests for Phase 9 - Secret Scanning & Zero Exposure Safety
"""

import ast
import pytest
from backend.analysis_context import AnalysisContext
from backend.detectors.secrets import SecretsDetector


def test_detect_rsa_private_key():
    detector = SecretsDetector()
    code = 'PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA...\\n-----END RSA PRIVATE KEY-----"'
    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="auth.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "SECRET"
    assert issues[0].severity == "CRITICAL"
    assert issues[0].start_line == 1

    # Verify Issue object contains zero raw secret values or extra fields
    dump = issues[0].model_dump()
    assert set(dump.keys()) == {"type", "severity", "file", "start_line", "end_line"}


def test_detect_aws_access_key():
    detector = SecretsDetector()
    code = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="aws_config.py")

    # AKIAIOSFODNN7EXAMPLE has 'example' substring so it's treated as placeholder
    issues = detector.detect(context)
    assert len(issues) == 0

    # Real formatted non-placeholder key
    code_real = 'aws_key = "AKIA1234567890ABCDEF"'
    tree_real = ast.parse(code_real)
    context_real = AnalysisContext(tree=tree_real, file="aws_config.py")
    issues_real = detector.detect(context_real)
    assert len(issues_real) == 1
    assert issues_real[0].type == "SECRET"
    assert issues_real[0].severity == "CRITICAL"


def test_detect_github_token():
    detector = SecretsDetector()
    code = 'github_pat = "ghp_123456789012345678901234567890123456"'
    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="config.py")

    issues = detector.detect(context)
    assert len(issues) == 1
    assert issues[0].type == "SECRET"
    assert issues[0].severity == "CRITICAL"


def test_ignore_placeholders():
    detector = SecretsDetector()
    code = '''
API_KEY = "your-api-key-here"
SECRET_KEY = "changeme"
TOKEN = "dummy_key_value"
    '''.strip()

    tree = ast.parse(code)
    context = AnalysisContext(tree=tree, file="settings.py")
    issues = detector.detect(context)
    assert len(issues) == 0


def test_secrets_text_scanner():
    detector = SecretsDetector()
    env_content = """
# Environment config
API_KEY=sk-1234567890123456789012345678901234
DUMMY=your-api-key
    """.strip()

    issues = detector.scan_text(".env", env_content)
    assert len(issues) == 1
    assert issues[0].type == "SECRET"
    assert issues[0].severity == "HIGH"
    assert issues[0].file == ".env"
    assert issues[0].start_line == 2


def test_secrets_changed_lines_filter():
    detector = SecretsDetector()
    env_content = "API_KEY=sk-1234567890123456789012345678901234\nAWS_KEY=AKIA1234567890ABCDEF\n"

    # Only line 2 changed
    issues = detector.scan_text(".env", env_content, changed_lines={2})
    assert len(issues) == 1
    assert issues[0].start_line == 2
    assert issues[0].severity == "CRITICAL"
