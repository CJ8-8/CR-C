from fastapi.testclient import TestClient
from backend.main import app
from backend.project_analyzer import ProjectAnalyzer

client = TestClient(app)


# -----------------------------------------------------------------------------
# Project Parsing & Indexing Tests
# -----------------------------------------------------------------------------

def test_project_analyzer_indexing():
    """Verify ProjectAnalyzer parses multiple files and indexes functions and imports."""
    files = {
        "auth.py": "def authenticate(user):\n    return True\n",
        "database.py": "def execute_query(q):\n    pass\n",
        "app.py": "from auth import authenticate\nimport database\n"
    }

    analyzer = ProjectAnalyzer(files)
    assert len(analyzer.trees) == 3
    assert "auth" in analyzer.module_index
    assert ("auth", "authenticate") in analyzer.func_index
    assert ("database", "execute_query") in analyzer.func_index

    # Check import index for app.py
    imports = analyzer.file_imports["app.py"]
    assert "authenticate" in imports
    assert imports["authenticate"] == ("auth", "authenticate")


# -----------------------------------------------------------------------------
# Cross-File Call Resolution & None Bug Test
# -----------------------------------------------------------------------------

def test_cross_file_none_bug():
    """
    Verify factory.py returning None causes app.py create().strip()
    to be flagged as BUG / MEDIUM localized to app.py.
    """
    payload = {
        "files": {
            "factory.py": "def create():\n    return None\n",
            "app.py": "from factory import create\nresult = create()\nresult.strip()\n"
        }
    }

    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200

    issues = res.json()["issues"]
    assert len(issues) == 1

    issue = issues[0]
    assert issue["type"] == "BUG"
    assert issue["severity"] == "MEDIUM"
    assert issue["file"] == "app.py"
    assert issue["start_line"] == 3


# -----------------------------------------------------------------------------
# Cross-File Security Flow (subprocess shell=True) Test
# -----------------------------------------------------------------------------

def test_cross_file_security_subprocess():
    """
    Verify input.py returning user string -> runner.py calling subprocess.run(shell=True)
    produces SECURITY / HIGH localized to runner.py.
    """
    payload = {
        "files": {
            "input.py": "def get_command(u):\n    return u\n",
            "runner.py": "from input import get_command\nimport subprocess\ncmd = get_command('data')\nsubprocess.run(cmd, shell=True)\n"
        }
    }

    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200

    issues = res.json()["issues"]
    assert len(issues) == 1

    issue = issues[0]
    assert issue["type"] == "SECURITY"
    assert issue["severity"] == "HIGH"
    assert issue["file"] == "runner.py"
    assert issue["start_line"] == 4


# -----------------------------------------------------------------------------
# Cross-File Dynamic SQL Construction Test
# -----------------------------------------------------------------------------

def test_cross_file_sql_injection():
    """
    Verify builder.py returning dynamic SQL string -> database.py calling cursor.execute(query)
    produces SECURITY / HIGH localized to database.py.
    """
    payload = {
        "files": {
            "builder.py": "def build_query(user_id):\n    return 'SELECT * FROM users WHERE id=' + user_id\n",
            "database.py": "from builder import build_query\nquery = build_query(user_id)\ncursor.execute(query)\n"
        }
    }

    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200

    issues = res.json()["issues"]
    sec_issues = [i for i in issues if i["type"] == "SECURITY"]
    assert len(sec_issues) >= 1

    # Check localization to database.py
    db_lines = [i["start_line"] for i in sec_issues if i["file"] == "database.py"]
    assert 3 in db_lines or 2 in db_lines


# -----------------------------------------------------------------------------
# Unknown Function Handling (Zero Speculative Findings) Test
# -----------------------------------------------------------------------------

def test_unknown_function_call_ignored():
    """
    Verify calling an unknown external library function get_user()
    does NOT produce speculative None bug findings.
    """
    payload = {
        "files": {
            "app.py": "result = get_user()\nresult.strip()\n"
        }
    }

    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200

    issues = res.json()["issues"]
    bug_issues = [i for i in issues if i["type"] == "BUG"]
    assert len(bug_issues) == 0


# -----------------------------------------------------------------------------
# Changed-Line Filtering per File Test
# -----------------------------------------------------------------------------

def test_project_changed_lines_filtering():
    """
    Verify findings outside changed_lines for a file are suppressed.
    """
    payload = {
        "files": {
            "factory.py": "def create():\n    return None\n",
            "app.py": "from factory import create\nres = create()\nres.strip()\n"  # Line 3 is bug
        },
        "changed_lines": {
            "app.py": [1, 2]  # Line 3 was NOT changed!
        }
    }

    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200

    issues = res.json()["issues"]
    # Line 3 bug should be suppressed because changed_lines for app.py is [1, 2]
    assert len(issues) == 0


# -----------------------------------------------------------------------------
# Cyclic Call Handling Test
# -----------------------------------------------------------------------------

def test_cyclic_function_calls_handling():
    """
    Verify A -> B -> C -> A cyclic call graph does not cause infinite recursion.
    """
    payload = {
        "files": {
            "a.py": "from b import func_b\ndef func_a():\n    return func_b()\n",
            "b.py": "from a import func_a\ndef func_b():\n    return func_a()\n"
        }
    }

    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200
    assert "issues" in res.json()


# -----------------------------------------------------------------------------
# Phase 9 Security Project Payload Test
# -----------------------------------------------------------------------------

def test_phase_9_project_security_analysis():
    """
    Verify POST /analyze-project analyzes requirements.txt, secrets, and configuration issues.
    """
    payload = {
        "files": {
            "requirements.txt": "requests==2.18.4\nflask\n",
            "settings.py": "DEBUG = True\nSECRET_KEY = \"ghp_123456789012345678901234567890123456\"\n",
            "client.py": "import requests\n\ndef fetch_data():\n    return requests.get(\"https://api.example.com\", verify=False)\n"
        }
    }

    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200

    issues = res.json()["issues"]
    types = {i["type"] for i in issues}

    assert "DEPENDENCY" in types
    assert "SECRET" in types
    assert "CONFIGURATION" in types

    # Verify requirements.txt vulnerable advisory issue
    req_vuln = next(i for i in issues if i["file"] == "requirements.txt" and i["start_line"] == 1)
    assert req_vuln["type"] == "DEPENDENCY"
    assert req_vuln["severity"] == "HIGH"

    # Verify settings.py secret issue
    secret_issue = next(i for i in issues if i["file"] == "settings.py" and i["start_line"] == 2)
    assert secret_issue["type"] == "SECRET"
    assert secret_issue["severity"] == "CRITICAL"

    # Verify client.py verify=False config issue
    cfg_issue = next(i for i in issues if i["file"] == "client.py" and i["start_line"] == 4)
    assert cfg_issue["type"] == "CONFIGURATION"
    assert cfg_issue["severity"] == "HIGH"


# -----------------------------------------------------------------------------
# Phase 10 Quality & Performance Payload Test
# -----------------------------------------------------------------------------

def test_phase_10_quality_performance_analysis():
    """
    Verify POST /analyze-project analyzes duplicate imports, repeated re.compile, and repeated += in loops.
    """
    payload = {
        "files": {
            "app.py": "import os\nimport os\nimport re\n\nresult = \"\"\ndef process(items):\n    global result\n    for item in items:\n        pattern = re.compile(r\"x\")\n        result += item\n    return result\n"
        }
    }

    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200

    issues = res.json()["issues"]
    types = [i["type"] for i in issues]

    assert "CODE_QUALITY" in types
    assert "PERFORMANCE" in types

    # Check duplicate import issue on line 2
    dup_imp = next(i for i in issues if i["start_line"] == 2)
    assert dup_imp["type"] == "CODE_QUALITY"

    # Check performance issues on lines 9 and 10 inside loop
    perf_lines = [i["start_line"] for i in issues if i["type"] == "PERFORMANCE"]
    assert 9 in perf_lines or 10 in perf_lines


# -----------------------------------------------------------------------------
# Phase 11 Mixed-Language Payload Test
# -----------------------------------------------------------------------------

def test_phase_11_mixed_language_analysis():
    """
    Verify POST /analyze-project analyzes Python, JavaScript, and TypeScript files together.
    """
    payload = {
        "files": {
            "app.py": "import subprocess\ncmd = input('Enter command: ')\nsubprocess.run(cmd, shell=True)\n",
            "frontend.js": "const input = getUserInput();\neval(input);\nconsole.log(\"debug\");\n",
            "types.ts": "const data: any = child_process.exec(cmd);\n"
        }
    }



    res = client.post("/analyze-project", json=payload)
    assert res.status_code == 200

    issues = res.json()["issues"]
    files = {i["file"] for i in issues}

    assert "app.py" in files
    assert "frontend.js" in files
    assert "types.ts" in files

    js_eval = next(i for i in issues if i["file"] == "frontend.js" and i["start_line"] == 2)
    assert js_eval["type"] == "SECURITY"
    assert js_eval["severity"] == "HIGH"

    ts_exec = next(i for i in issues if i["file"] == "types.ts" and i["start_line"] == 1)
    assert ts_exec["type"] == "SECURITY"
    assert ts_exec["severity"] == "HIGH"



