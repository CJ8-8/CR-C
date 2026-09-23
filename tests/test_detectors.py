from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


# -----------------------------------------------------------------------------
# Security Detector Tests
# -----------------------------------------------------------------------------

def test_security_eval_call():
    """Verify actual eval() call is detected as SECURITY / HIGH."""
    res = client.post("/analyze-python", json={"file": "a.py", "code": "eval(x)"})
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "SECURITY"
    assert issues[0]["severity"] == "HIGH"


def test_security_exec_call():
    """Verify actual exec() call is detected as SECURITY / HIGH."""
    res = client.post("/analyze-python", json={"file": "a.py", "code": "exec(x)"})
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "SECURITY"


def test_security_eval_in_string_ignored():
    """Verify string literal containing 'eval(' is NOT detected as security issue."""
    res = client.post("/analyze-python", json={"file": "a.py", "code": 'msg = "eval(x)"'})
    assert res.status_code == 200
    assert res.json()["issues"] == []


def test_security_subprocess_shell_true():
    """Verify subprocess.run(cmd, shell=True) is detected as SECURITY / HIGH."""
    code = "import subprocess\nsubprocess.run(cmd, shell=True)"
    res = client.post("/analyze-python", json={"file": "a.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "SECURITY"
    assert issues[0]["severity"] == "HIGH"
    assert issues[0]["start_line"] == 2


# -----------------------------------------------------------------------------
# Code Quality Detector Tests
# -----------------------------------------------------------------------------

def test_code_quality_print_call():
    """Verify print("debug") call is detected as CODE_QUALITY / LOW."""
    res = client.post("/analyze-python", json={"file": "a.py", "code": 'print("debug")'})
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "CODE_QUALITY"
    assert issues[0]["severity"] == "LOW"


def test_code_quality_print_in_string_ignored():
    """Verify string containing print('hello') is NOT detected."""
    res = client.post("/analyze-python", json={"file": "a.py", "code": 'msg = "print(\'hello\')"'})
    assert res.status_code == 200
    assert res.json()["issues"] == []


# -----------------------------------------------------------------------------
# Bug Detector Tests
# -----------------------------------------------------------------------------

def test_bug_bare_except():
    """Verify bare except: clause is detected as BUG / MEDIUM."""
    code = "try:\n    do_something()\nexcept:\n    pass"
    res = client.post("/analyze-python", json={"file": "a.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "BUG"
    assert issues[0]["severity"] == "MEDIUM"
    assert issues[0]["start_line"] == 3


def test_bug_normal_except_ignored():
    """Verify except Exception as exc: with active handling is NOT flagged as a swallowed exception."""
    code = "try:\n    do_something()\nexcept Exception as exc:\n    logger.error(exc)"
    res = client.post("/analyze-python", json={"file": "a.py", "code": code})
    assert res.status_code == 200
    assert res.json()["issues"] == []



def test_bug_mutable_default_arg():
    """Verify def func(items=[]): is detected as BUG / MEDIUM."""
    code = "def add_item(item, items=[]):\n    items.append(item)"
    res = client.post("/analyze-python", json={"file": "a.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "BUG"
    assert issues[0]["severity"] == "MEDIUM"
    assert issues[0]["start_line"] == 1


def test_bug_immutable_default_arg_ignored():
    """Verify def func(value=10): is NOT flagged as mutable default argument."""
    code = "def calc(value=10, flag=False, name='default'):\n    return value * 2"
    res = client.post("/analyze-python", json={"file": "a.py", "code": code})
    assert res.status_code == 200
    assert res.json()["issues"] == []


# -----------------------------------------------------------------------------
# Changed Lines Filtering Tests
# -----------------------------------------------------------------------------

def test_detector_engine_changed_lines_filtering():
    """Verify findings outside changed_lines are filtered out."""
    code = (
        "print('debug')\n"       # Line 1 (unchanged)
        "eval(user_input)\n"     # Line 2 (changed!)
        "def f(items=[]): pass"  # Line 3 (unchanged)
    )
    payload = {
        "file": "a.py",
        "code": code,
        "changed_lines": [2]
    }
    res = client.post("/analyze-python", json=payload)
    assert res.status_code == 200
    issues = res.json()["issues"]

    # Only line 2 eval(user_input) should be returned!
    assert len(issues) == 1
    assert issues[0]["type"] == "SECURITY"
    assert issues[0]["start_line"] == 2


def test_detector_engine_multiline_overlapping_changed_lines():
    """Verify multi-line issue overlapping changed_lines is retained."""
    code = (
        "try:\n"
        "    x = 1\n"
        "except:\n"              # Line 3
        "    pass"
    )
    payload = {
        "file": "a.py",
        "code": code,
        "changed_lines": [3]
    }
    res = client.post("/analyze-python", json=payload)
    assert res.status_code == 200
    issues = res.json()["issues"]
    assert len(issues) == 1
    assert issues[0]["type"] == "BUG"
    assert issues[0]["start_line"] == 3


# -----------------------------------------------------------------------------
# Combined Multi-Detector Integration Test
# -----------------------------------------------------------------------------

def test_detector_engine_combined_multi_detector_findings():
    """Verify multiple detectors return combined issues for a single file."""
    code = (
        "def process(items=[]):\n"                  # Line 1: BUG
        "    print('debug')\n"                      # Line 2: CODE_QUALITY
        "    try:\n"                                # Line 3
        "        eval(items)\n"                     # Line 4: SECURITY
        "        subprocess.run('ls', shell=True)\n"# Line 5: SECURITY
        "    except:\n"                             # Line 6: BUG
        "        pass"
    )
    res = client.post("/analyze-python", json={"file": "multi.py", "code": code})
    assert res.status_code == 200
    issues = res.json()["issues"]

    assert len(issues) == 5

    # Check detector types present
    types = [i["type"] for i in issues]
    assert types.count("BUG") == 2
    assert types.count("CODE_QUALITY") == 1
    assert types.count("SECURITY") == 2
