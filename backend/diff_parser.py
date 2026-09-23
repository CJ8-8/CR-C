"""
CodeJev Unified Diff Parser - Phase 3 Prototype
================================================

NOTE FOR DEVELOPERS & LEARNERS:
This module parses standard Unified Git Diff format strings.
It identifies hunk headers (e.g. @@ -10,3 +10,4 @@), tracks target line numbers,
and extracts ONLY newly added or modified lines (prefixed with '+').

Unchanged lines (' ') are tracked to keep line numbers accurate,
and deleted lines ('-') are ignored because they no longer exist in the new code.
"""

import re
from typing import List
from backend.schemas import DiffLine


def parse_unified_diff(diff_text: str) -> List[DiffLine]:
    """
    Parses a unified diff string and returns a list of added/modified lines
    along with their exact 1-based target line numbers.

    Args:
        diff_text (str): Raw string in unified diff format.

    Returns:
        List[DiffLine]: List of added lines containing content and new line numbers.
    """
    added_lines: List[DiffLine] = []

    if not diff_text:
        return added_lines

    lines = diff_text.splitlines()
    current_new_line = 0
    in_hunk = False

    # Regex to match hunk headers like: @@ -10,3 +10,4 @@ or @@ -1 +1,2 @@
    hunk_header_pattern = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")

    for line in lines:
        # Check for hunk header @@ -old_start,count +new_start,count @@
        hunk_match = hunk_header_pattern.match(line)
        if hunk_match:
            current_new_line = int(hunk_match.group(1))
            in_hunk = True
            continue

        if not in_hunk:
            # Skip file header metadata like '--- a/file.py', '+++ b/file.py', 'diff --git ...'
            continue

        # Ignore diff file header markers if present inside hunk stream
        if line.startswith("+++") or line.startswith("---"):
            continue

        if line.startswith("+"):
            # Line added or modified in new version
            content = line[1:]
            added_lines.append(
                DiffLine(
                    line_number=current_new_line,
                    content=content,
                    is_added=True
                )
            )
            current_new_line += 1

        elif line.startswith("-"):
            # Line deleted from old version (does NOT exist in new file version)
            # Line number in new file does NOT increment
            continue

        else:
            # Unchanged context line (starts with ' ' or normal text)
            # Exists in new file version, so increment line count
            current_new_line += 1

    return added_lines
