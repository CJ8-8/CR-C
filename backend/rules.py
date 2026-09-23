"""
CodeJev Decision Engine - Temporary Rule-Based Prototype
=========================================================

NOTE FOR DEVELOPERS & LEARNERS:
This module contains a simple deterministic (if/else) rule engine.
It is NOT an AI or machine learning model yet.

In Phase 1, we use static rules to establish the system architecture:
Input (PR Data) -> Decision Engine (Rules) -> Structured Result (JSON response).

In future phases, this rule engine can be replaced or augmented by
trained CodeJev ML models, LLM evaluations, or static analysis tools.
"""

from backend.schemas import PRReviewRequest, PRReviewResponse


def evaluate_pr_review(request: PRReviewRequest) -> PRReviewResponse:
    """
    Evaluates an incoming Pull Request request using deterministic rules.

    Args:
        request (PRReviewRequest): Verified input containing PR metrics and code snippets.

    Returns:
        PRReviewResponse: Structured review decision.
    """
    # -------------------------------------------------------------------------
    # Rule 1: Security Risk Detection
    # -------------------------------------------------------------------------
    # Security risk is flagged if automated tools found security issues,
    # or if raw code snippets contain common dangerous anti-patterns.
    has_security_findings = request.security_findings > 0
    
    code_snippet = (request.changed_code or "").lower()
    has_sql_injection_pattern = "select " in code_snippet and "+" in code_snippet
    has_unsafe_eval = "eval(" in code_snippet or "exec(" in code_snippet
    has_insecure_code = has_sql_injection_pattern or has_unsafe_eval

    security_risk = has_security_findings or has_insecure_code

    # -------------------------------------------------------------------------
    # Rule 2: Bug Risk Detection
    # -------------------------------------------------------------------------
    # Bug risk is flagged if automated tests failed or if code churn is high.
    tests_failed = not request.tests_passed
    high_churn_untested = (request.lines_added + request.lines_deleted > 150) and tests_failed
    bug_risk = tests_failed or high_churn_untested

    # -------------------------------------------------------------------------
    # Rule 3: Breaking Change Detection
    # -------------------------------------------------------------------------
    # Detect breaking changes from keywords in title/description or massive deletions.
    title_and_desc = (request.title + " " + (request.description or "")).lower()
    has_breaking_keyword = "breaking" in title_and_desc or "deprecate" in title_and_desc
    massive_deletions = request.lines_deleted > 200
    breaking_change = has_breaking_keyword or massive_deletions

    # -------------------------------------------------------------------------
    # Rule 4: Risk Score Computation (0 - 100)
    # -------------------------------------------------------------------------
    calculated_score = 0

    if has_security_findings:
        calculated_score += 50 + (request.security_findings * 10)
    
    if has_insecure_code:
        calculated_score += 35

    if tests_failed:
        calculated_score += 30

    if breaking_change:
        calculated_score += 20

    total_line_changes = request.lines_added + request.lines_deleted
    if total_line_changes > 200:
        calculated_score += 15
    elif total_line_changes > 50:
        calculated_score += 5

    if request.files_changed > 10:
        calculated_score += 10

    # Clamp the risk score to be strictly within [0, 100]
    risk_score = max(0, min(100, calculated_score))

    # -------------------------------------------------------------------------
    # Rule 5: Categorization
    # -------------------------------------------------------------------------
    if security_risk:
        category = "SECURITY"
    elif bug_risk:
        category = "BUG"
    elif breaking_change:
        category = "REFACTOR"
    elif total_line_changes > 100:
        category = "REFACTOR"
    else:
        category = "FEATURE"

    # -------------------------------------------------------------------------
    # Rule 6: Final Decision (BLOCK / REVIEW / PASS)
    # -------------------------------------------------------------------------
    if risk_score >= 70 or security_risk:
        decision = "BLOCK"
    elif risk_score >= 30 or bug_risk or breaking_change:
        decision = "REVIEW"
    else:
        decision = "PASS"

    needs_review = decision in ("REVIEW", "BLOCK")

    # -------------------------------------------------------------------------
    # Rule 7: Confidence Level
    # -------------------------------------------------------------------------
    # Rule-based confidence estimation based on strength of deterministic signals
    if security_risk:
        confidence = 0.94
    elif tests_failed:
        confidence = 0.90
    else:
        confidence = 0.88

    # Return the validated Pydantic response object
    return PRReviewResponse(
        security_risk=security_risk,
        bug_risk=bug_risk,
        breaking_change=breaking_change,
        needs_review=needs_review,
        category=category,
        risk_score=risk_score,
        confidence=confidence,
        decision=decision,
    )
