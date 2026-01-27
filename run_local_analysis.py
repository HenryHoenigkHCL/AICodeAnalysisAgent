#!/usr/bin/env python3
"""Local analysis runner for post-build reports."""

import sys
import json
import subprocess
from pathlib import Path
from analyzer.postbuild_analyzer import PostBuildAnalyzer


def run_local_analysis(repo_path: str = "C:\Users\henry.hoenigk\Repos\Neuer Ordner\analyzer\TestRepo") -> None:
    """
    Run full analysis locally.
    Collects build artifacts, runs tests, coverage, and static analysis.
    """
    repo_path = Path(repo_path)
    reports_dir = repo_path / "reports"
    reports_dir.mkdir(exist_ok=True)

    print("🔍 PostBuild Analyzer - Local Run")
    print("=" * 60)

    # Step 1: Run tests and collect results
    print("\n1️⃣  Running tests...")
    test_results = {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "failures": []}
    try:
        result = subprocess.run(
            ["python", "-m", "pytest", "sample_project/tests", "-v", "--tb=short"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Parse basic results
        output = result.stdout + result.stderr
        test_results["total"] = output.count("PASSED") + output.count("FAILED")
        test_results["passed"] = output.count("PASSED")
        test_results["failed"] = output.count("FAILED")
        
        test_results_path = reports_dir / "test_results.json"
        test_results_path.write_text(json.dumps(test_results, indent=2))
        print(f"   ✓ Tests: {test_results['passed']}/{test_results['total']} passed")
    except Exception as e:
        print(f"   ✗ Test execution failed: {e}")

    # Step 2: Run coverage
    print("\n2️⃣  Collecting coverage...")
    try:
        subprocess.run(
            ["python", "-m", "pytest", "sample_project/tests", "--cov=sample_project/src", "--cov-report=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        print("   ✓ Coverage report generated")
    except Exception as e:
        print(f"   ✗ Coverage collection failed: {e}")

    # Step 3: Run static analysis
    print("\n3️⃣  Running static analysis...")
    static_analysis = {"linters": [], "security": [], "type_checks": []}
    try:
        # flake8
        result = subprocess.run(
            ["python", "-m", "flake8", "sample_project/src", "--format=json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.stdout:
            issues = json.loads(result.stdout)
            static_analysis["linters"].append({"tool": "flake8", "issues": issues})
        print("   ✓ flake8 complete")
    except Exception as e:
        print(f"   ℹ flake8 skipped: {e}")

    try:
        # bandit
        result = subprocess.run(
            ["python", "-m", "bandit", "-r", "sample_project/src", "-f", "json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            security_issues = [
                {
                    "file": r["filename"],
                    "line": r["line_number"],
                    "message": r["issue_text"],
                    "severity": r["severity"],
                    "cwe": f"CWE-{r.get('test_id', '000')}",
                }
                for r in data.get("results", [])
            ]
            if security_issues:
                static_analysis["security"].append({"tool": "bandit", "issues": security_issues})
        print("   ✓ bandit complete")
    except Exception as e:
        print(f"   ℹ bandit skipped: {e}")

    static_analysis_path = reports_dir / "static_analysis.json"
    static_analysis_path.write_text(json.dumps(static_analysis, indent=2))

    # Step 4: Run analyzer
    print("\n4️⃣  Running PostBuild Analyzer...")
    analyzer = PostBuildAnalyzer(
        repo_path=str(repo_path),
        build_log_path=str(reports_dir / "build.log"),
        test_results_path=str(test_results_path),
        coverage_report_path=None,
        static_analysis_path=str(static_analysis_path),
    )

    machine_path, human_path = analyzer.save_reports(reports_dir)

    print("\n" + "=" * 60)
    print("✅ Analysis Complete!")
    print(f"\n📊 Reports saved:")
    print(f"   - {machine_path}")
    print(f"   - {human_path}")
    print("\n📖 View the human report:")
    print(f"   Open: {human_path.absolute()}")


if __name__ == "__main__":
    run_local_analysis(".")
