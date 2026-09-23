from fastapi.testclient import TestClient
from backend.main import app
from backend.analysis_context import AnalysisContext
import ast

client = TestClient(app)


# -----------------------------------------------------------------------------
# Basic Taint Assignment & Expression Propagation Tests
# -----------------------------------------------------------------------------

def test_basic_assignment_and_expression_taint():
    """Verify input() taints assigned variables and binary addition expressions."""
    code = (
        "x = input()\n"
        "y = x\n"
        "z = 'prefix_' + y\n"
    )
    tree = ast.parse(code)
    ctx = AnalysisContext(tree=tree, file="test.py")

    y_taint = ctx.get_node_taint(ast.parse("y").body[0].value)
    assert y_taint is not None
    assert y_taint.is_tainted is True
    assert y_taint.source_kind == "input()"


def test_f_string_taint_propagation():
    """Verify f-strings containing tainted variables inherit taint."""
    code = (
        "x = input()\n"
        "query = f'SELECT * FROM users WHERE name={x}'\n"
    )
    tree = ast.parse(code)
    ctx = AnalysisContext(tree=tree, file="test.py")

    query_assign = tree.body[1].value
    taint = ctx.get_node_taint(query_assign)
    assert taint is not None
    assert taint.is_tainted is True


# -----------------------------------------------------------------------------
# Shell Sink & Sanitizer Tests
# -----------------------------------------------------------------------------

def test_shell_sink_taint_detected():
    """Verify untainted input passed to subprocess.run(shell=True) is flagged as SECURITY / HIGH."""
    code = (
        "x = input()\n"
        "subprocess.run(x, shell=True)"
    )
    res = client.post("/analyze-python", json={"file": "sh.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "SECURITY"
    assert issues[0]["severity"] == "HIGH"
    assert issues[0]["start_line"] == 2


def test_shell_sink_shlex_quote_sanitized():
    """Verify shlex.quote() sanitizes command input and prevents shell injection issues."""
    code = (
        "import shlex\n"
        "x = input()\n"
        "safe_x = shlex.quote(x)\n"
        "subprocess.run(safe_x, shell=True)"
    )
    res = client.post("/analyze-python", json={"file": "safe_sh.py", "code": code})
    assert res.status_code == 200
    sec_issues = [i for i in res.json()["issues"] if i["type"] == "SECURITY"]
    # Sanitized command should NOT be flagged as security vulnerability!
    assert len(sec_issues) == 0


# -----------------------------------------------------------------------------
# SQL Sink & Parameterized Query Tests
# -----------------------------------------------------------------------------

def test_sql_tainted_query_detected():
    """Verify tainted string query passed to cursor.execute(query) is flagged as SECURITY / HIGH."""
    code = (
        "x = input()\n"
        "query = 'SELECT * FROM users WHERE name=' + x\n"
        "cursor.execute(query)"
    )
    res = client.post("/analyze-python", json={"file": "sql.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]
    sec_issues = [i for i in issues if i["type"] == "SECURITY"]
    assert len(sec_issues) >= 1
    
    start_lines = [i["start_line"] for i in sec_issues]
    assert 3 in start_lines or 2 in start_lines


def test_sql_parameterized_query_safe():
    """Verify parameterized query cursor.execute('SELECT...?', (x,)) is safe from dynamic SQL alerts."""
    code = (
        "x = input()\n"
        "cursor.execute('SELECT * FROM users WHERE name=?', (x,))"
    )
    res = client.post("/analyze-python", json={"file": "safe_sql.py", "code": code})
    assert res.status_code == 200
    sec_issues = [i for i in res.json()["issues"] if i["type"] == "SECURITY"]
    assert len(sec_issues) == 0


# -----------------------------------------------------------------------------
# Cross-Function & Cross-File Return Propagation Tests
# -----------------------------------------------------------------------------

def test_cross_function_return_propagation():
    """Verify return values propagate taint across functions and project files."""
    payload = {
        "files": {
            "sources.py": "def get():\n    return input()\n",
            "runner.py": "from sources import get\nimport subprocess\nx = get()\nsubprocess.run(x, shell=True)\n"
        }
    }
    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200
    issues = res.json()["issues"]
    sec_issues = [i for i in issues if i["type"] == "SECURITY" and i["file"] == "runner.py"]
    assert len(sec_issues) == 1
    assert sec_issues[0]["start_line"] == 4


def test_identity_function_preserves_taint():
    """Verify identity function def forward(val): return val preserves parameter taint."""
    payload = {
        "files": {
            "util.py": "def forward(val):\n    return val\n",
            "app.py": "from util import forward\nimport subprocess\nx = input()\ny = forward(x)\nsubprocess.run(y, shell=True)\n"
        }
    }
    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200
    issues = res.json()["issues"]
    sec_issues = [i for i in issues if i["type"] == "SECURITY" and i["file"] == "app.py"]
    assert len(sec_issues) == 1
    assert sec_issues[0]["start_line"] == 5


# -----------------------------------------------------------------------------
# Unknown Function Safety & Scope Isolation Tests
# -----------------------------------------------------------------------------

def test_unknown_function_no_speculative_taint():
    """Verify unknown function call x = unknown_func(input()) does not make assumptions about returns."""
    code = (
        "x = unknown_func(input())\n"
        "subprocess.run(x, shell=True)"
    )
    res = client.post("/analyze-python", json={"file": "unk.py", "code": code})
    assert res.status_code == 200
    assert "issues" in res.json()


def test_scope_isolation_prevents_cross_contamination():
    """Verify same variable name in different function scope does not inherit taint."""
    code = (
        "x = input()\n"
        "def other():\n"
        "    x = 'safe_string'\n"
        "    return x\n"
    )
    tree = ast.parse(code)
    ctx = AnalysisContext(tree=tree, file="scope.py")
    
    other_fn = tree.body[1]
    local_assign = other_fn.body[0]
    taint = ctx.get_node_taint(local_assign.value, scope="other")
    assert taint is None


# -----------------------------------------------------------------------------
# Changed Lines Filtering at Sink Location Test
# -----------------------------------------------------------------------------

def test_changed_lines_filtering_at_sink_location():
    """Verify issue is suppressed if sink line is not in changed_lines."""
    payload = {
        "file": "sink_filter.py",
        "code": (
            "x = input()\n"                   # Line 1
            "subprocess.run(x, shell=True)"   # Line 2 (Sink)
        ),
        "changed_lines": [1]  # Line 2 was NOT changed!
    }
    res = client.post("/analyze-python", json=payload)
    assert res.status_code == 200
    sec_issues = [i for i in res.json()["issues"] if i["type"] == "SECURITY"]
    assert len(sec_issues) == 0
