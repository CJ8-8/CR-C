from fastapi.testclient import TestClient
from backend.main import app
from backend.diff_parser import parse_unified_diff

client = TestClient(app)


def test_diff_parser_extracts_added_lines_and_line_numbers():
    """
    Verify parse_unified_diff accurately parses hunk header @@ -10,2 +10,3 @@
    and calculates 1-based target line numbers for added lines.
    """
    diff_text = (
        "@@ -10,2 +10,3 @@\n"
        " def login(user_id):\n"
        "-    return get_user(user_id)\n"
        "+    query = \"SELECT * FROM users WHERE id=\" + user_id\n"
        "+    return db.execute(query)"
    )

    parsed = parse_unified_diff(diff_text)
    assert len(parsed) == 2

    # Added line 1 -> target line 11 (after context line at 10)
    assert parsed[0].line_number == 11
    assert "SELECT *" in parsed[0].content

    # Added line 2 -> target line 12
    assert parsed[1].line_number == 12
    assert "db.execute" in parsed[1].content


def test_analyze_diff_detects_issue_on_added_line():
    """
    Verify POST /analyze-diff detects SQL injection on an added line (+),
    returning start_line=11 and end_line=11.
    """
    payload = {
        "file": "auth.py",
        "diff": (
            "@@ -10,2 +10,3 @@\n"
            " def login(user_id):\n"
            "-    return get_user(user_id)\n"
            "+    query = \"SELECT * FROM users WHERE id=\" + user_id\n"
            "+    return db.execute(query)"
        )
    }

    response = client.post("/analyze-diff", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert len(data["issues"]) == 1

    issue = data["issues"][0]
    assert issue["type"] == "SECURITY"
    assert issue["severity"] == "HIGH"
    assert issue["file"] == "auth.py"
    assert issue["start_line"] == 11
    assert issue["end_line"] == 11


def test_analyze_diff_ignores_deleted_lines():
    """
    Verify that an issue pattern inside a deleted line (-) is NOT flagged
    because it was removed from the codebase.
    """
    payload = {
        "file": "legacy.py",
        "diff": (
            "@@ -5,3 +5,2 @@\n"
            " def old_func():\n"
            "-    bad_query = \"SELECT * FROM users WHERE id=\" + user_id\n"
            "+    safe_query = get_safe_query()\n"
            "    return safe_query"
        )
    }

    response = client.post("/analyze-diff", json=payload)
    assert response.status_code == 200

    data = response.json()
    # The deleted line had SQL injection, but it was deleted, so issues should be empty
    assert data["issues"] == []


def test_analyze_diff_ignores_unchanged_context_lines():
    """
    Verify that issues on unchanged context lines (' ') are ignored,
    focusing ONLY on newly modified code.
    """
    payload = {
        "file": "service.py",
        "diff": (
            "@@ -20,3 +20,3 @@\n"
            "    print(\"debug\")\n"  # Context line (unchanged)
            "-    x = 1\n"
            "+    x = 2\n"          # Added line (safe change)
            "    return x"
        )
    }

    response = client.post("/analyze-diff", json=payload)
    assert response.status_code == 200

    data = response.json()
    # print("debug") is on context line 20, not added in this diff -> should be ignored!
    assert data["issues"] == []


def test_clean_diff_returns_empty_issues():
    """Verify clean diff with safe code additions returns issues: []."""
    payload = {
        "file": "clean.py",
        "diff": (
            "@@ -1,2 +1,3 @@\n"
            " def add(a, b):\n"
            "+    # new comment added\n"
            "    return a + b"
        )
    }

    response = client.post("/analyze-diff", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["issues"] == []
