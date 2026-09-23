from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


# -----------------------------------------------------------------------------
# Local Data-Flow & Variable Tracking Tests
# -----------------------------------------------------------------------------

def test_data_flow_tracking_security():
    """
    Verify local variable assignments are tracked:
    user_input -> command -> subprocess.run(command, shell=True)
    """
    code = (
        "user_input = request.args['name']\n"
        "command = user_input\n"
        "subprocess.run(command, shell=True)"
    )
    res = client.post("/analyze-python", json={"file": "flow.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "SECURITY"
    assert issues[0]["start_line"] == 3


# -----------------------------------------------------------------------------
# SQL Construction & Parameterized Query Tests
# -----------------------------------------------------------------------------

def test_sql_dynamic_concatenation_detected():
    """
    Verify dynamic SQL string concatenation query = "SELECT..." + user_id
    and cursor.execute(query) produce a SECURITY / HIGH issue.
    """
    code = (
        "user_id = input()\n"
        "query = 'SELECT * FROM users WHERE id=' + user_id\n"
        "cursor.execute(query)"
    )
    res = client.post("/analyze-python", json={"file": "db.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]

    assert len(issues) >= 1
    sec_issues = [i for i in issues if i["type"] == "SECURITY"]
    assert len(sec_issues) >= 1
    assert sec_issues[0]["severity"] == "HIGH"


def test_sql_parameterized_query_ignored():
    """
    Verify parameterized query cursor.execute('SELECT...?', (user_id,))
    is NOT flagged by the dynamic SQL detector.
    """
    code = (
        "user_id = input()\n"
        "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
    )
    res = client.post("/analyze-python", json={"file": "safe_db.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]

    # Parameterized query should have 0 security issues!
    sec_issues = [i for i in issues if i["type"] == "SECURITY"]
    assert len(sec_issues) == 0


# -----------------------------------------------------------------------------
# Definite None Dereference Tests
# -----------------------------------------------------------------------------

def test_definite_none_dereference_detected():
    """
    Verify result = None followed by result.strip() produces BUG / MEDIUM.
    """
    code = (
        "result = None\n"
        "result.strip()"
    )
    res = client.post("/analyze-python", json={"file": "none.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]

    assert len(issues) == 1
    assert issues[0]["type"] == "BUG"
    assert issues[0]["severity"] == "MEDIUM"
    assert issues[0]["start_line"] == 2


def test_speculative_function_return_none_ignored():
    """
    Verify result = get_user() followed by result.strip() is NOT flagged as a None bug.
    CodeJev avoids speculative false positives when return values are unknown.
    """
    code = (
        "result = get_user()\n"
        "result.strip()"
    )
    res = client.post("/analyze-python", json={"file": "speculative.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]

    # Speculative returns should NOT produce a BUG issue!
    bug_issues = [i for i in issues if i["type"] == "BUG"]
    assert len(bug_issues) == 0


# -----------------------------------------------------------------------------
# Changed Line Filtering with Context Detectors
# -----------------------------------------------------------------------------

def test_contextual_detectors_respect_changed_lines():
    """
    Verify contextual issues outside changed_lines are filtered out.
    """
    code = (
        "result = None\n"       # Line 1
        "result.strip()\n"     # Line 2 (BUG)
        "val = 10"             # Line 3 (changed!)
    )
    payload = {
        "file": "context_filter.py",
        "code": code,
        "changed_lines": [3]
    }
    res = client.post("/analyze-python", json=payload)
    assert res.status_code == 200
    issues = res.json()["issues"]

    # Line 2 bug should be ignored because changed_lines=[3]!
    assert len(issues) == 0
