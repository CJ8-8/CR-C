from typing import Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


# =============================================================================
# Phase 1 Models (Preserved)
# =============================================================================

class PRReviewRequest(BaseModel):
    """
    Data model representing incoming Pull Request information for Phase 1.
    """
    title: str = Field(
        ..., 
        description="The title of the pull request (e.g. 'Add login API')"
    )
    description: Optional[str] = Field(
        "", 
        description="Detailed description of the pull request changes"
    )
    language: str = Field(
        "python", 
        description="Primary programming language used in the PR"
    )
    files_changed: int = Field(
        0, 
        ge=0, 
        description="Total number of files modified"
    )
    lines_added: int = Field(
        0, 
        ge=0, 
        description="Number of lines of code added"
    )
    lines_deleted: int = Field(
        0, 
        ge=0, 
        description="Number of lines of code removed"
    )
    tests_passed: bool = Field(
        True, 
        description="Whether automated test suite passed successfully"
    )
    security_findings: int = Field(
        0, 
        ge=0, 
        description="Number of security flags or static analysis security issues detected"
    )
    changed_code: Optional[str] = Field(
        "", 
        description="Snippet or string representation of changed code for quick scan"
    )


class PRReviewResponse(BaseModel):
    """
    Data model representing the structured CodeJev decision outcome for Phase 1.
    """
    security_risk: bool = Field(
        ..., 
        description="True if security vulnerabilities or risks were identified"
    )
    bug_risk: bool = Field(
        ..., 
        description="True if there is a heightened risk of bugs or test failures"
    )
    breaking_change: bool = Field(
        ..., 
        description="True if changes may break backward compatibility"
    )
    needs_review: bool = Field(
        ..., 
        description="True if human developer review is required before merging"
    )
    category: str = Field(
        ..., 
        description="Primary category of change: SECURITY, BUG, PERFORMANCE, REFACTOR, FEATURE, OTHER"
    )
    risk_score: int = Field(
        ..., 
        ge=0, 
        le=100, 
        description="Calculated risk score from 0 (very safe) to 100 (critical risk)"
    )
    confidence: float = Field(
        ..., 
        ge=0.0, 
        le=1.0, 
        description="Decision engine confidence level between 0.0 (0%) and 1.0 (100%)"
    )
    decision: str = Field(
        ..., 
        description="Final decision action: PASS, REVIEW, or BLOCK"
    )


# =============================================================================
# Phase 2 Models (Issue Detection & Line Localization)
# =============================================================================

class Issue(BaseModel):
    """
    Represents a single detected code defect localized to a file and line number.
    """
    type: str = Field(
        ..., 
        description="Category of flaw: SECURITY, BUG, CODE_QUALITY, PERFORMANCE, BREAKING_CHANGE, OTHER"
    )
    severity: str = Field(
        ..., 
        description="Severity level: LOW, MEDIUM, HIGH, CRITICAL"
    )
    file: str = Field(
        ..., 
        description="Name or relative path of the file containing the issue"
    )
    start_line: int = Field(
        ..., 
        ge=1, 
        description="Starting 1-based line number of the issue in the file"
    )
    end_line: int = Field(
        ..., 
        ge=1, 
        description="Ending 1-based line number of the issue in the file"
    )

    @model_validator(mode="after")
    def validate_line_range(self):
        """Ensures that end_line is always greater than or equal to start_line."""
        if self.end_line < self.start_line:
            raise ValueError(
                f"end_line ({self.end_line}) cannot be smaller than start_line ({self.start_line})"
            )
        return self


class CodeAnalysisRequest(BaseModel):
    """
    Request body for POST /analyze containing file name and complete raw code string.
    """
    file: str = Field(
        ..., 
        description="Target filename (e.g. 'auth.py')"
    )
    code: str = Field(
        ..., 
        description="Complete string contents of the file to analyze"
    )


class CodeAnalysisResponse(BaseModel):
    """
    Response model for POST /analyze containing array of detected Issue objects.
    """
    issues: List[Issue] = Field(
        ..., 
        description="List of detected code issues localized by file and line number"
    )


# =============================================================================
# Phase 3 Models (Git Diff Parsing & Changed-Line Localization)
# =============================================================================

class DiffLine(BaseModel):
    """
    Represents an added/modified line parsed from a unified Git diff.
    """
    line_number: int = Field(
        ..., 
        ge=1, 
        description="Target 1-based line number of the added line in the new file version"
    )
    content: str = Field(
        ..., 
        description="The code content of the added line (without leading '+' marker)"
    )
    is_added: bool = Field(
        True, 
        description="True if this line represents newly added/modified code"
    )


class DiffAnalysisRequest(BaseModel):
    """
    Request body for POST /analyze-diff containing target file name and unified diff text.
    """
    file: str = Field(
        ..., 
        description="Target filename being analyzed (e.g. 'auth.py')"
    )
    diff: str = Field(
        ..., 
        description="Unified diff format text showing code modifications"
    )


# =============================================================================
# Phase 4 Models (Python AST Structural Analysis)
# =============================================================================

class PythonASTAnalysisRequest(BaseModel):
    """
    Request body for POST /analyze-python containing source code and optional changed lines filter.
    """
    file: str = Field(
        ..., 
        description="Target filename (e.g. 'auth.py')"
    )
    code: str = Field(
        ..., 
        description="Complete Python source code string to parse into an AST"
    )
    changed_lines: Optional[List[int]] = Field(
        None, 
        description="Optional list of 1-based line numbers. If provided, AST issues outside these lines are ignored."
    )


# =============================================================================
# Phase 7 & 12 Models (Multi-File Project Analysis & Dynamic Options)
# =============================================================================

class DynamicOptions(BaseModel):
    """
    Opt-in configuration options for dynamic test execution, runtime smoke testing, and fuzzing.
    """
    enabled: bool = Field(
        False, 
        description="True to enable opt-in dynamic execution (test, runtime, fuzzing)"
    )
    entrypoint: Optional[str] = Field(
        None, 
        description="Optional entrypoint function to execute for runtime smoke test (e.g. 'app.main')"
    )
    fuzz_target: Optional[str] = Field(
        None, 
        description="Optional target function to fuzz with generated boundary inputs (e.g. 'parser.parse')"
    )
    timeout_seconds: float = Field(
        3.0, 
        ge=0.5, 
        le=10.0, 
        description="Subprocess execution timeout limit in seconds"
    )
    max_fuzz_cases: int = Field(
        50, 
        ge=1, 
        le=500, 
        description="Maximum bounded fuzzing iterations per target function"
    )


class ProjectAnalysisRequest(BaseModel):
    """
    Request body for POST /analyze-project containing multiple files, changed lines, and opt-in dynamic options.
    """
    files: Dict[str, str] = Field(
        ..., 
        description="Dictionary mapping filename/relative path (e.g. 'auth.py') to raw source string"
    )
    changed_lines: Optional[Dict[str, List[int]]] = Field(
        None, 
        description="Optional dictionary mapping filename to list of 1-based changed line numbers"
    )
    dynamic: Optional[DynamicOptions] = Field(
        None, 
        description="Optional opt-in dynamic analysis settings for test runner, runtime runner, and fuzzing"
    )

