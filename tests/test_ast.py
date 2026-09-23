from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_1_actual_eval_call():
    """Test 1: Actual eval() call is detected as SECURITY / HIGH with exact line number."""
    payload = {
        "file": "auth.py",
        "code": "user_input = 'data'\neval(user_input)"
    }

    response = client.post("/analyze-python", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    assert issue["type"] == "SECURITY"
    assert issue["severity"] == "HIGH"
    assert issue["file"] == "auth.py"
    assert issue["start_line"] == 2
    assert issue["end_line"] == 2


def test_2_string_containing_eval_is_ignored():
    """
    Test 2: String assignment containing 'eval(user_input)' MUST NOT trigger a security issue.
    This demonstrates the fundamental difference between text matching and AST structural analysis.
    """
    payload = {
        "file": "safe.py",
        "code": 'message = "eval(user_input)"'
    }

    response = client.post("/analyze-python", json=payload)
    assert response.status_code == 200

    data = response.json()
    # String literal is an ast.Constant/ast.Str, NOT an ast.Call node!
    assert data["issues"] == []


def test_3_actual_exec_call():
    """Test 3: Actual exec() call is detected as SECURITY / HIGH."""
    payload = {
        "file": "runner.py",
        "code": "exec(user_input)"
    }

    response = client.post("/analyze-python", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    assert issue["type"] == "SECURITY"
    assert issue["severity"] == "HIGH"
    assert issue["start_line"] == 1


def test_4_print_call():
    """Test 4: print() call is detected as CODE_QUALITY / LOW."""
    payload = {
        "file": "debug.py",
        "code": 'print("debug")'
    }

    response = client.post("/analyze-python", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    assert issue["type"] == "CODE_QUALITY"
    assert issue["severity"] == "LOW"
    assert issue["start_line"] == 1


def test_5_correct_ast_line_number():
    """Test 5: AST line numbers reflect padding lines before the call."""
    payload = {
        "file": "padded.py",
        "code": "x = 1\ny = 2\nz = 3\neval('data')"
    }

    response = client.post("/analyze-python", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1
    assert data["issues"][0]["start_line"] == 4


def test_6_multiline_call_line_range():
    """Test 6: Multi-line call captures start_line and end_line range."""
    payload = {
        "file": "multiline.py",
        "code": "result = eval(\n    user_input\n)"
    }

    response = client.post("/analyze-python", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    assert issue["start_line"] == 1
    assert issue["end_line"] == 3


def test_7_changed_line_filtering():
    """
    Test 7: eval() on line 1 (unchanged) vs eval() on line 5 (changed).
    When changed_lines=[5] is passed, ONLY line 5 should be reported.
    """
    payload = {
        "file": "diff_target.py",
        "code": "eval(old_input)\nx = 1\ny = 2\nz = 3\neval(new_input)",
        "changed_lines": [5]
    }

    response = client.post("/analyze-python", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    # Line 1 eval was ignored because it's not in changed_lines=[5]!
    assert issue["start_line"] == 5


def test_8_invalid_python_error_handling():
    """Test 8: Invalid Python syntax returns HTTP 400 Bad Request without crashing."""
    payload = {
        "file": "broken.py",
        "code": "def broken_func(:\n    return"
    }

    response = client.post("/analyze-python", json=payload)
    assert response.status_code == 400

    data = response.json()
    assert "Invalid Python syntax" in data["detail"]
