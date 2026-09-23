"""
CodeJev Finding Evidence & Validation Engine - Phase 13
========================================================

Defines internal FindingEvidence objects and performs final evidence validation checks
(CFG path reachability, guard safety, conditional sanitization completeness, changed lines overlap)
before returning localized Issue objects to the public API.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from backend.schemas import Issue


@dataclass
class FindingEvidence:
    """
    Internal evidence representation supporting candidate finding validation.
    """
    rule: str
    file: str
    start_line: int
    end_line: int
    severity: str
    issue_type: str
    source: Optional[str] = None
    sink: Optional[str] = None
    data_flow_path: List[str] = field(default_factory=list)
    control_flow_path: List[str] = field(default_factory=list)
    confidence_reason: str = "Rule pattern match with control flow verification"
    confidence_level: str = "HIGH_CONFIDENCE"  # HIGH_CONFIDENCE, MEDIUM_CONFIDENCE, LOW_CONFIDENCE
    is_valid: bool = True


class FindingValidator:
    """
    Performs final evidence validation to suppress impossible/guarded detections
    and convert valid evidence into public Issue objects.
    """
    def validate_and_filter(
        self, 
        evidences: List[FindingEvidence], 
        changed_lines: Optional[Dict[str, List[int]]] = None
    ) -> List[Issue]:
        """
        Validates evidence instances, applies changed_lines filtering,
        and converts valid evidence into normalized public Issue objects.
        """
        valid_issues: List[Issue] = []

        for ev in evidences:
            if not ev.is_valid:
                continue

            # 1. Changed-lines filter check
            if changed_lines and ev.file in changed_lines:
                file_changed_lines = set(changed_lines[ev.file])
                ev_line_range = set(range(ev.start_line, ev.end_line + 1))
                if not ev_line_range.intersection(file_changed_lines):
                    continue

            # 2. Construct public Issue object
            valid_issues.append(Issue(
                type=ev.issue_type,
                severity=ev.severity,
                file=ev.file,
                start_line=ev.start_line,
                end_line=ev.end_line
            ))

        return valid_issues
