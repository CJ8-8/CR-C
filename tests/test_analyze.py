from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_sql_injection_detection_and_line_number():
    """
    Verify SQL injection pattern is detected on the exact line number.
    Code has 2 lines before the SQL query, so the query is at line 3.
    """
    payload = {
        "file": "auth.py",
        "code": "print(\"hello\")\n# line two comment\nquery = \"SELECT * FROM users WHERE id=\" + user_id"
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert "issues" in data
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    assert issue["type"] == "SECURITY"
    assert issue["severity"] == "HIGH"
    assert issue["file"] == "auth.py"
    assert issue["start_line"] == 3
    assert issue["end_line"] == 3


def test_eval_detection():
    """Verify eval(user_input) is detected as SECURITY / HIGH."""
    payload = {
        "file": "utils.py",
        "code": "result = eval(user_input)"
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    assert issue["type"] == "SECURITY"
    assert issue["severity"] == "HIGH"
    assert issue["file"] == "utils.py"
    assert issue["start_line"] == 1
    assert issue["end_line"] == 1


def test_print_debug_detection():
    """Verify print("debug") is detected as CODE_QUALITY / LOW."""
    payload = {
        "file": "service.py",
        "code": "# line 1\nprint(\"debug\")"
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    assert issue["type"] == "CODE_QUALITY"
    assert issue["severity"] == "LOW"
    assert issue["file"] == "service.py"
    assert issue["start_line"] == 2
    assert issue["end_line"] == 2


def test_clean_code_returns_empty_issues():
    """Verify clean code with no patterns returns issues: []."""
    payload = {
        "file": "clean.py",
        "code": "def add(a, b):\n    return a + b"
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["issues"] == []


def test_multiple_problems_in_same_file():
    """Verify multiple issues in the same file are detected at their respective lines."""
    payload = {
        "file": "mixed.py",
        "code": "print(\"debug\")\nvalue = eval(user_input)\nquery = \"SELECT * FROM users WHERE id=\" + user_id"
    }

    response = client.post("/analyze", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 3

    # Issue 1: line 1 (print debug)
    assert data["issues"][0]["type"] == "CODE_QUALITY"
    assert data["issues"][0]["start_line"] == 1

    # Issue 2: line 2 (eval)
    assert data["issues"][1]["type"] == "SECURITY"
    assert data["issues"][1]["start_line"] == 2

    # Issue 3: line 3 (sql concatenation)
    assert data["issues"][2]["type"] == "SECURITY"
    assert data["issues"][2]["start_line"] == 3
