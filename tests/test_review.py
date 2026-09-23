from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health_check():
    """Verify that the health check endpoint returns HTTP 200 and expected status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "CodeJev Engine" in data["service"]


def test_low_risk_pr_pass():
    """
    Test a low-risk PR: small safe feature change with passing tests and no security issues.
    Expected Decision: PASS
    """
    payload = {
        "title": "Fix typo in documentation",
        "description": "Fixes a minor typo in docstring",
        "language": "python",
        "files_changed": 1,
        "lines_added": 2,
        "lines_deleted": 2,
        "tests_passed": True,
        "security_findings": 0,
        "changed_code": "# fixed docstring typo"
    }

    response = client.post("/review", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["decision"] == "PASS"
    assert data["needs_review"] is False
    assert data["security_risk"] is False
    assert data["bug_risk"] is False
    assert data["risk_score"] < 30


def test_medium_risk_pr_review():
    """
    Test a medium-risk PR: failing tests or moderate refactor requiring human oversight.
    Expected Decision: REVIEW
    """
    payload = {
        "title": "Refactor data parsing module",
        "description": "Updates legacy data structures",
        "language": "python",
        "files_changed": 5,
        "lines_added": 80,
        "lines_deleted": 60,
        "tests_passed": False,  # Failing tests increases risk score
        "security_findings": 0,
        "changed_code": "def parse_data(raw):\n    return json.loads(raw)"
    }

    response = client.post("/review", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["decision"] == "REVIEW"
    assert data["needs_review"] is True
    assert data["bug_risk"] is True
    assert 30 <= data["risk_score"] < 70


def test_high_risk_security_pr_block():
    """
    Test a high-risk security PR: security finding present or unsafe SQL pattern.
    Expected Decision: BLOCK
    """
    payload = {
        "title": "Add user search endpoint",
        "description": "Queries users from database by search string",
        "language": "python",
        "files_changed": 3,
        "lines_added": 120,
        "lines_deleted": 20,
        "tests_passed": True,
        "security_findings": 1,
        "changed_code": "query = \"SELECT * FROM users WHERE id=\" + user_id"
    }

    response = client.post("/review", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["decision"] == "BLOCK"
    assert data["needs_review"] is True
    assert data["security_risk"] is True
    assert data["category"] == "SECURITY"
    assert data["risk_score"] >= 70
