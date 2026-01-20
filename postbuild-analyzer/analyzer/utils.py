"""Utility functions for the PostBuild Analyzer."""

import re
from typing import Dict, Any, List
from pathlib import Path


def redact_secrets(text: str, patterns: List[str] = None) -> str:
    """Redact sensitive information from text."""
    if patterns is None:
        patterns = [
            r"password\s*[=:]\s*['\"]?[^'\"\s]+['\"]?",
            r"api_key\s*[=:]\s*['\"]?[^'\"\s]+['\"]?",
            r"token\s*[=:]\s*['\"]?[^'\"\s]+['\"]?",
            r"sk_live_[a-zA-Z0-9]+",
            r"Bearer\s+[a-zA-Z0-9\._\-]+",
        ]
    
    redacted = text
    for pattern in patterns:
        redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted


def extract_file_line(evidence_dict: Dict[str, Any]) -> str:
    """Format file:line from evidence dict."""
    file = evidence_dict.get("file", "unknown")
    line = evidence_dict.get("line", 0)
    return f"{file}:{line}" if line else file


def truncate_text(text: str, max_length: int = 500) -> str:
    """Truncate text and add ellipsis."""
    if len(text) > max_length:
        return text[:max_length] + "...\n[truncated]"
    return text


def parse_pytest_output(output: str) -> Dict[str, int]:
    """Parse pytest output to extract test counts."""
    counts = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
    
    passed = len(re.findall(r"PASSED", output))
    failed = len(re.findall(r"FAILED", output))
    skipped = len(re.findall(r"SKIPPED", output))
    
    counts["passed"] = passed
    counts["failed"] = failed
    counts["skipped"] = skipped
    counts["total"] = passed + failed + skipped
    
    return counts


def format_diff(old: str, new: str, file_path: str = "file.py", context_lines: int = 3) -> str:
    """Generate a unified diff format patch."""
    import difflib
    
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=file_path,
        tofile=file_path,
        lineterm="",
        n=context_lines
    )
    
    return "".join(diff)


def categorize_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
    """Group findings by severity level."""
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    
    for finding in findings:
        severity = finding.get("severity", "low")
        if severity in by_severity:
            by_severity[severity].append(finding)
    
    return by_severity
