#!/usr/bin/env python3
"""
Post-build Code Analysis Agent for Python projects.
Generates machine-readable and human-readable analysis reports.
"""

import json
import os
import re
import sys
import time
import ast
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import subprocess
from urllib.parse import urlparse


@dataclass
class Finding:
    """Represents a single code analysis finding."""
    id: str
    title: str
    category: str  # bug, security, style, performance, test_gap, maintainability
    severity: str  # critical, high, medium, low
    description: str
    evidence: List[Dict[str, Any]]  # [{file, start_line, end_line, excerpt}]
    recommendation: str
    confidence: float
    patch: Optional[Dict[str, str]] = None  # {path, diff}
    tests_to_add: Optional[List[Dict[str, str]]] = None  # [{path, content}]


class PostBuildAnalyzer:
    """Main analyzer class for post-build code analysis."""

    def __init__(
        self,
        repo_path: str,
        build_log_path: Optional[str] = None,
        test_results_path: Optional[str] = None,
        coverage_report_path: Optional[str] = None,
        static_analysis_path: Optional[str] = None,
        commit_sha: Optional[str] = None,
        repo_url: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the PostBuild Analyzer.

        Args:
            repo_path: Root path of the repository
            build_log_path: Path to build log file
            test_results_path: Path to test results (JSON)
            coverage_report_path: Path to coverage report (JSON or XML)
            static_analysis_path: Path to static analysis output
            commit_sha: Git commit SHA
            repo_url: Git repository URL
            config: Configuration dictionary
        """
        self.repo_path = Path(repo_path)
        self.build_log_path = Path(build_log_path) if build_log_path else None
        self.test_results_path = Path(test_results_path) if test_results_path else None
        self.coverage_report_path = (
            Path(coverage_report_path) if coverage_report_path else None
        )
        self.static_analysis_path = (
            Path(static_analysis_path) if static_analysis_path else None
        )
        self.commit_sha = commit_sha or self._get_current_sha()
        self.repo_url = repo_url or self._get_repo_url()
        self.config = config or {}
        self.findings: List[Finding] = []
        self.start_time = time.time()

        # Load artifacts
        self.build_log = self._load_file(self.build_log_path) if self.build_log_path else ""
        self.test_results = self._load_json(self.test_results_path) if self.test_results_path else {}
        self.coverage_report = self._load_json(self.coverage_report_path) if self.coverage_report_path else {}
        self.static_analysis = self._load_json(self.static_analysis_path) if self.static_analysis_path else {}

    def _get_current_sha(self) -> str:
        """Get current git commit SHA."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()[:8] if result.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    def _get_repo_url(self) -> str:
        """Get repository URL from git remote."""
        try:
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    @staticmethod
    def _load_file(path: Path) -> str:
        """Load file contents."""
        try:
            if path.exists():
                return path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
        return ""

    @staticmethod
    def _load_json(path: Path) -> Dict[str, Any]:
        """Load JSON file."""
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def analyze(self) -> Tuple[Dict[str, Any], str]:
        """
        Run the complete analysis pipeline.

        Returns:
            Tuple of (machine_report_dict, human_report_markdown)
        """
        self.findings = []

        # Analysis steps
        self._analyze_build()
        self._analyze_tests()
        self._analyze_coverage()
        self._analyze_static_analysis()
        self._analyze_coding_standards()
        self._analyze_code_quality()

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 4))

        # Generate reports
        machine_report = self._generate_machine_report()
        human_report = self._generate_human_report(machine_report)

        return machine_report, human_report

    def _analyze_build(self) -> None:
        """Analyze build log for failures."""
        if not self.build_log:
            return

        # Check for common build errors
        error_patterns = [
            (r"ERROR", "Build error detected"),
            (r"FAILED", "Build failed"),
            (r"SyntaxError", "Syntax error in code"),
            (r"ImportError", "Import error during build"),
            (r"ModuleNotFoundError", "Missing module dependency"),
        ]

        for pattern, desc in error_patterns:
            if re.search(pattern, self.build_log, re.IGNORECASE):
                # Extract error context
                lines = self.build_log.split("\n")
                error_lines = [
                    (i, line) for i, line in enumerate(lines)
                    if re.search(pattern, line, re.IGNORECASE)
                ]

                for line_num, line in error_lines[:2]:  # Top 2 errors
                    context_start = max(0, line_num - 2)
                    context_end = min(len(lines), line_num + 3)
                    excerpt = "\n".join(lines[context_start:context_end])

                    finding = Finding(
                        id=f"build_{len(self.findings):03d}",
                        title=f"Build failure: {desc}",
                        category="bug",
                        severity="high",
                        description=f"Build log indicates: {desc}",
                        evidence=[{"file": "build.log", "line": line_num, "excerpt": excerpt}],
                        recommendation="Review the build log and fix the error. Run locally to reproduce.",
                        confidence=0.85,
                    )
                    self.findings.append(finding)

    def _analyze_tests(self) -> None:
        """Analyze test results."""
        if not self.test_results:
            return

        total = self.test_results.get("total", 0)
        passed = self.test_results.get("passed", 0)
        failed = self.test_results.get("failed", 0)
        skipped = self.test_results.get("skipped", 0)

        # Report failed tests
        if failed > 0:
            failures = self.test_results.get("failures", [])
            for failure in failures[:5]:  # Top 5 failures
                finding = Finding(
                    id=f"test_{len(self.findings):03d}",
                    title=f"Failing test: {failure.get('test_id', 'unknown')}",
                    category="bug",
                    severity="critical",
                    description=failure.get("message", "Test failed"),
                    evidence=[
                        {
                            "file": failure.get("file", "unknown"),
                            "line": failure.get("line", 0),
                            "excerpt": failure.get("stack_trace", ""),
                        }
                    ],
                    recommendation="Fix the failing test. Review the stack trace and debug locally.",
                    confidence=1.0,
                )
                self.findings.append(finding)

        # Report low test coverage
        if total > 0 and passed < total * 0.9:
            finding = Finding(
                id=f"test_{len(self.findings):03d}",
                title="Low test pass rate",
                category="test_gap",
                severity="high",
                description=f"Only {passed}/{total} tests passing ({100*passed/total:.1f}%)",
                evidence=[{"file": "test_results.json", "line": 0, "excerpt": json.dumps(self.test_results, indent=2)[:500]}],
                recommendation="Investigate and fix failing tests before merging.",
                confidence=0.95,
            )
            self.findings.append(finding)

    def _analyze_coverage(self) -> None:
        """Analyze code coverage."""
        if not self.coverage_report:
            return

        overall_percent = self.coverage_report.get("overall_percent", 0)
        files_below_threshold = self.coverage_report.get("files_below_threshold", [])

        # Report files below threshold
        threshold = self.config.get("coverage_threshold", 80)
        if files_below_threshold:
            for file_info in files_below_threshold[:3]:  # Top 3 files
                finding = Finding(
                    id=f"cov_{len(self.findings):03d}",
                    title=f"Low coverage: {file_info['file']}",
                    category="test_gap",
                    severity="medium",
                    description=f"{file_info['file']} has {file_info.get('percent', 0):.1f}% coverage (threshold: {threshold}%)",
                    evidence=[{"file": file_info["file"], "line": 0, "excerpt": f"Coverage: {file_info.get('percent', 0):.1f}%"}],
                    recommendation=f"Add tests to reach {threshold}% coverage. Focus on critical paths.",
                    confidence=1.0,
                )
                self.findings.append(finding)

    def _analyze_static_analysis(self) -> None:
        """Analyze static analysis results."""
        if not self.static_analysis:
            return

        # Process linter issues
        linters = self.static_analysis.get("linters", [])
        for linter_result in linters:
            tool = linter_result.get("tool", "linter")
            issues = linter_result.get("issues", [])

            for issue in issues[:3]:  # Top 3 per tool
                severity = self._map_severity(issue.get("severity", "low"))
                finding = Finding(
                    id=f"lint_{len(self.findings):03d}",
                    title=f"{tool}: {issue.get('message', 'Issue')}",
                    category="style",
                    severity=severity,
                    description=issue.get("message", "Linter issue"),
                    evidence=[
                        {
                            "file": issue.get("file", "unknown"),
                            "line": issue.get("line", 0),
                            "excerpt": f"Code: {issue.get('code', 'N/A')}",
                        }
                    ],
                    recommendation=f"Fix {tool} issue. Review {tool} documentation for details.",
                    confidence=0.8,
                )
                self.findings.append(finding)

        # Process security issues
        security = self.static_analysis.get("security", [])
        for sec_issue in security:
            tool = sec_issue.get("tool", "security_scanner")
            issues = sec_issue.get("issues", [])

            for issue in issues[:2]:  # Top 2 per tool
                finding = Finding(
                    id=f"sec_{len(self.findings):03d}",
                    title=f"Security: {issue.get('message', 'Vulnerability')}",
                    category="security",
                    severity="high",
                    description=issue.get("message", "Security vulnerability"),
                    evidence=[
                        {
                            "file": issue.get("file", "unknown"),
                            "line": issue.get("line", 0),
                            "excerpt": f"CWE: {issue.get('cwe', 'Unknown')}",
                        }
                    ],
                    recommendation=f"Fix security issue immediately. Refer to {issue.get('cwe', 'CWE')} for remediation.",
                    confidence=0.9,
                )
                self.findings.append(finding)

    def _analyze_code_quality(self) -> None:
        """Analyze code quality from source inspection."""
        # This is a placeholder for deeper source code analysis
        # In production, this would use AST analysis, complexity metrics, etc.
        pass

    def _analyze_coding_standards(self) -> None:
        """Analyze code against configurable coding standards."""
        standards = self.config.get("coding_standards", {})
        if not standards or not self.config.get("enable_coding_standards_check", False):
            return

        # Get all Python files in the repository
        python_files = list(self.repo_path.rglob("*.py"))
        
        # Filter out common non-code directories
        exclude_dirs = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "build", "dist"}
        python_files = [
            f for f in python_files 
            if not any(excluded in f.parts for excluded in exclude_dirs)
        ]

        violations = []

        for py_file in python_files[:50]:  # Limit to first 50 files to avoid timeout
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                
                # Check file-level standards
                violations.extend(self._check_file_standards(py_file, content, standards))
                
                # Parse and check code structure
                try:
                    tree = ast.parse(content)
                    violations.extend(self._check_ast_standards(py_file, tree, content, standards))
                except SyntaxError:
                    pass  # Skip files with syntax errors
                    
            except Exception:
                continue

        # Convert violations to findings
        for violation in violations[:10]:  # Top 10 violations
            severity = standards.get("violation_severities", {}).get(
                violation["rule"], "low"
            )
            finding = Finding(
                id=f"std_{len(self.findings):03d}",
                title=f"Coding Standard: {violation['title']}",
                category="style",
                severity=severity,
                description=violation["description"],
                evidence=[
                    {
                        "file": str(violation["file"].relative_to(self.repo_path)),
                        "line": violation.get("line", 0),
                        "excerpt": violation.get("excerpt", ""),
                    }
                ],
                recommendation=violation["recommendation"],
                confidence=0.75,
            )
            self.findings.append(finding)

    def _check_file_standards(self, py_file: Path, content: str, standards: Dict) -> List[Dict]:
        """Check file-level coding standards."""
        violations = []
        lines = content.split("\n")
        
        # Check file length
        max_file_lines = standards.get("max_file_lines", 500)
        if len(lines) > max_file_lines:
            violations.append({
                "file": py_file,
                "line": 1,
                "rule": "max_file_lines",
                "title": f"File exceeds {max_file_lines} lines",
                "description": f"File has {len(lines)} lines, exceeds limit of {max_file_lines}",
                "recommendation": f"Consider splitting this file into smaller modules",
                "excerpt": f"File length: {len(lines)} lines"
            })
        
        # Check for trailing whitespace
        if standards.get("trailing_whitespace", False):
            for i, line in enumerate(lines, 1):
                if line and line[-1].isspace():
                    violations.append({
                        "file": py_file,
                        "line": i,
                        "rule": "trailing_whitespace",
                        "title": "Trailing whitespace found",
                        "description": f"Line {i} has trailing whitespace",
                        "recommendation": "Remove trailing whitespace",
                        "excerpt": repr(line[-20:])
                    })
                    break  # Only report first occurrence per file
        
        # Check for tabs
        if standards.get("tabs_not_allowed", True):
            for i, line in enumerate(lines, 1):
                if "\t" in line:
                    violations.append({
                        "file": py_file,
                        "line": i,
                        "rule": "tabs_not_allowed",
                        "title": "Tab character used instead of spaces",
                        "description": f"Line {i} contains tab character(s)",
                        "recommendation": "Use spaces for indentation instead of tabs",
                        "excerpt": repr(line[:50])
                    })
                    break  # Only report first occurrence per file
        
        return violations

    def _check_ast_standards(self, py_file: Path, tree: ast.AST, content: str, standards: Dict) -> List[Dict]:
        """Check AST-based coding standards."""
        violations = []
        lines = content.split("\n")
        max_function_lines = standards.get("max_function_lines", 50)
        max_nested_levels = standards.get("max_nested_levels", 4)
        naming_conventions = standards.get("naming_conventions", {})
        docstring_required = standards.get("docstring_required", True)
        
        for node in ast.walk(tree):
            # Check function/method length
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_lines = node.end_lineno - node.lineno if node.end_lineno else 0
                
                if func_lines > max_function_lines:
                    violations.append({
                        "file": py_file,
                        "line": node.lineno,
                        "rule": "max_function_lines",
                        "title": f"Function '{node.name}' exceeds {max_function_lines} lines",
                        "description": f"Function has {func_lines} lines, exceeds limit of {max_function_lines}",
                        "recommendation": "Consider breaking this function into smaller, focused functions",
                        "excerpt": f"def {node.name}(...) at line {node.lineno}"
                    })
                
                # Check function naming convention
                if naming_conventions.get("function_pattern"):
                    pattern = naming_conventions["function_pattern"]
                    if not re.match(pattern, node.name):
                        violations.append({
                            "file": py_file,
                            "line": node.lineno,
                            "rule": "naming_convention",
                            "title": f"Function name '{node.name}' doesn't follow convention",
                            "description": f"Function name should match pattern: {pattern}",
                            "recommendation": f"Rename function to follow {pattern} pattern (snake_case)",
                            "excerpt": f"def {node.name}(...)"
                        })
                
                # Check for docstring
                if docstring_required:
                    docstring = ast.get_docstring(node)
                    if not docstring and node.name != "__init__":  # Allow __init__ without docstring
                        violations.append({
                            "file": py_file,
                            "line": node.lineno,
                            "rule": "missing_docstring",
                            "title": f"Function '{node.name}' missing docstring",
                            "description": "Function should have a docstring describing its purpose",
                            "recommendation": "Add a docstring to document the function's purpose, parameters, and return value",
                            "excerpt": f"def {node.name}(...)"
                        })
            
            # Check class naming convention
            elif isinstance(node, ast.ClassDef):
                if naming_conventions.get("class_pattern"):
                    pattern = naming_conventions["class_pattern"]
                    if not re.match(pattern, node.name):
                        violations.append({
                            "file": py_file,
                            "line": node.lineno,
                            "rule": "naming_convention",
                            "title": f"Class name '{node.name}' doesn't follow convention",
                            "description": f"Class name should match pattern: {pattern}",
                            "recommendation": f"Rename class to follow {pattern} pattern (PascalCase)",
                            "excerpt": f"class {node.name}(...)"
                        })
        
        return violations

    @staticmethod
    def _map_severity(severity_str: str) -> str:
        """Map external severity to standardized format."""
        severity_map = {
            "error": "high",
            "warning": "medium",
            "note": "low",
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        return severity_map.get(severity_str.lower(), "low")

    def _generate_machine_report(self) -> Dict[str, Any]:
        """Generate machine-readable JSON report."""
        build_status = "success" if self.test_results.get("failed", 0) == 0 else "failure"
        overall_status = "critical" if build_status == "failure" else "warning" if self.findings else "success"

        # Extract build log excerpt
        build_log_excerpt = ""
        if self.build_log:
            lines = self.build_log.split("\n")
            first_2k = "\n".join(lines[: len(lines) // 2])[:2000]
            last_2k = "\n".join(lines[max(0, len(lines) - 10):])[:2000]
            build_log_excerpt = f"{first_2k}\n... [truncated] ...\n{last_2k}"

        return {
            "version": "1.0.0",
            "repository": self.repo_url,
            "ref": self.commit_sha,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "overall_status": overall_status,
            "build_summary": {
                "build_status": build_status,
                "build_log_excerpt": build_log_excerpt,
            },
            "tests": {
                "total": self.test_results.get("total", 0),
                "passed": self.test_results.get("passed", 0),
                "failed": self.test_results.get("failed", 0),
                "skipped": self.test_results.get("skipped", 0),
                "failures": self.test_results.get("failures", []),
            },
            "coverage": {
                "overall_percent": self.coverage_report.get("overall_percent", 0),
                "files_below_threshold": self.coverage_report.get("files_below_threshold", []),
            },
            "static_analysis": self.static_analysis,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "confidence": f.confidence,
                    "patch": f.patch,
                    "tests_to_add": f.tests_to_add,
                }
                for f in self.findings
            ],
            "metadata": {
                "analysis_duration_seconds": time.time() - self.start_time,
                "agent_version": "1.0.0",
            },
        }

    def _generate_human_report(self, machine_report: Dict[str, Any]) -> str:
        """Generate human-readable Markdown report."""
        lines = [
            "# Post-Build Code Analysis Report",
            "",
            f"**Repository:** {self.repo_url}",
            f"**Commit:** {self.commit_sha}",
            f"**Timestamp:** {machine_report['timestamp_utc']}",
            "",
        ]

        # Status badge
        status = machine_report["overall_status"]
        status_emoji = {"critical": "🔴", "warning": "🟡", "success": "🟢"}.get(status, "⚪")
        lines.append(f"## Status: {status_emoji} **{status.upper()}**")
        lines.append("")

        # Quick summary
        tests = machine_report["tests"]
        coverage = machine_report["coverage"]
        findings_count = len(machine_report["findings"])

        lines.append("## Quick Summary")
        lines.append("")
        lines.append(f"- **Build:** {machine_report['build_summary']['build_status']}")
        lines.append(
            f"- **Tests:** {tests['passed']}/{tests['total']} passed "
            f"({100*tests['passed']/tests['total']:.1f}%)" if tests['total'] > 0 else "- **Tests:** N/A"
        )
        lines.append(f"- **Coverage:** {coverage['overall_percent']:.1f}%")
        lines.append(f"- **Issues Found:** {findings_count}")
        lines.append("")

        # Findings by severity
        severity_groups = {}
        for finding in machine_report["findings"]:
            sev = finding["severity"]
            if sev not in severity_groups:
                severity_groups[sev] = []
            severity_groups[sev].append(finding)

        if severity_groups:
            lines.append("## Findings by Severity")
            lines.append("")
            for severity in ["critical", "high", "medium", "low"]:
                if severity in severity_groups:
                    lines.append(f"### {severity.upper()} ({len(severity_groups[severity])})")
                    lines.append("")
                    for f in severity_groups[severity][:3]:  # Top 3 per severity
                        lines.append(f"**{f['title']}**")
                        lines.append(f"- Category: {f['category']}")
                        lines.append(f"- Confidence: {f['confidence']:.0%}")
                        lines.append(f"- {f['description']}")
                        lines.append("")

        # Recommended actions
        if machine_report["findings"]:
            lines.append("## Recommended Actions")
            lines.append("")
            for f in machine_report["findings"][:5]:
                lines.append(f"1. **{f['title']}** ({f['severity']})")
                lines.append(f"   - {f['recommendation']}")
            lines.append("")

        # Detailed findings
        lines.append("## Detailed Findings")
        lines.append("")
        for i, f in enumerate(machine_report["findings"], 1):
            lines.append(f"### Finding {i}: {f['title']}")
            lines.append("")
            lines.append(f"**Severity:** {f['severity'].upper()}")
            lines.append(f"**Category:** {f['category']}")
            lines.append(f"**Confidence:** {f['confidence']:.0%}")
            lines.append("")
            lines.append(f"**Description:** {f['description']}")
            lines.append("")

            if f["evidence"]:
                lines.append("**Evidence:**")
                for evidence in f["evidence"]:
                    lines.append(f"- File: `{evidence.get('file', 'unknown')}`")
                    if evidence.get("line"):
                        lines.append(f"  Line: {evidence['line']}")
                    if evidence.get("excerpt"):
                        excerpt = evidence["excerpt"][:200]
                        lines.append(f"  ```")
                        lines.append(f"  {excerpt}")
                        lines.append(f"  ```")
                lines.append("")

            lines.append(f"**Recommendation:** {f['recommendation']}")
            lines.append("")

        # Metadata
        lines.append("## Metadata")
        lines.append("")
        lines.append(f"- **Analysis Duration:** {machine_report['metadata']['analysis_duration_seconds']:.2f}s")
        lines.append(f"- **Agent Version:** {machine_report['metadata']['agent_version']}")
        lines.append("")

        return "\n".join(lines)

    def save_reports(self, output_dir: Path) -> Tuple[Path, Path]:
        """Save reports to disk."""
        output_dir.mkdir(parents=True, exist_ok=True)

        machine_report, human_report = self.analyze()

        # Save machine report
        machine_path = output_dir / "machine_report.json"
        machine_path.write_text(json.dumps(machine_report, indent=2), encoding="utf-8")

        # Save human report
        human_path = output_dir / "human_report.md"
        human_path.write_text(human_report, encoding="utf-8")

        return machine_path, human_path


def main():
    """CLI entry point."""
    import argparse
    import yaml

    parser = argparse.ArgumentParser(description="Post-build Code Analysis Agent")
    parser.add_argument("repo_path", help="Path to repository")
    parser.add_argument("--build-log", help="Path to build log file")
    parser.add_argument("--test-results", help="Path to test results JSON")
    parser.add_argument("--coverage-report", help="Path to coverage report JSON")
    parser.add_argument("--static-analysis", help="Path to static analysis JSON")
    parser.add_argument("--config", help="Path to configuration YAML file")
    parser.add_argument("--commit-sha", help="Git commit SHA")
    parser.add_argument("--repo-url", help="Repository URL")
    parser.add_argument("--output-dir", default="./reports", help="Output directory for reports")

    args = parser.parse_args()

    # Load configuration
    config = {}
    if args.config:
        config_path = Path(args.config)
        if config_path.exists():
            with open(config_path, "r") as f:
                config = yaml.safe_load(f) or {}

    analyzer = PostBuildAnalyzer(
        repo_path=args.repo_path,
        build_log_path=args.build_log,
        test_results_path=args.test_results,
        coverage_report_path=args.coverage_report,
        static_analysis_path=args.static_analysis,
        commit_sha=args.commit_sha,
        repo_url=args.repo_url,
        config=config,
    )

    machine_path, human_path = analyzer.save_reports(Path(args.output_dir))
    print(f"✓ Machine report: {machine_path}")
    print(f"✓ Human report: {human_path}")


if __name__ == "__main__":
    main()
