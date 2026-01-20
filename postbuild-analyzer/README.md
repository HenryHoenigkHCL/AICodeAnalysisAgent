# PostBuild Analyzer - Automated Code Analysis Agent

A comprehensive, production-ready Python agent for automated post-build code analysis. Generates structured machine-readable (JSON) and human-readable (Markdown) reports covering correctness, security, test coverage, and code quality.

## 🎯 Features

- **Build Failure Analysis**: Identifies root causes from build logs
- **Test Analysis**: Categorizes and prioritizes failing tests
- **Coverage Reporting**: Detects files below coverage threshold
- **Security Scanning**: Integrates bandit, reviews for CWE vulnerabilities
- **Linting & Style**: Aggregates flake8, mypy, ruff findings
- **Complexity Detection**: Identifies hotspots and refactor candidates
- **Dual Output**: 
  - `machine_report.json` – structured, automation-friendly
  - `human_report.md` – developer-friendly with recommendations
- **CI/CD Integration**: GitHub Actions workflow included
- **Local Development**: Run analysis locally during development

## 📁 Project Structure

```
postbuild-analyzer/
├── analyzer/
│   └── postbuild_analyzer.py       # Core analysis engine
├── sample_project/                 # Example Python project with issues
│   ├── src/
│   │   └── sample_module.py        # Contains intentional bugs/security issues
│   └── tests/
│       └── test_sample.py          # Unit tests
├── reports/                        # Generated reports + sample artifacts
│   ├── build.log
│   ├── test_results.json
│   ├── coverage_report.json
│   ├── static_analysis.json
│   ├── machine_report.json         # Generated
│   └── human_report.md             # Generated
├── .github/workflows/
│   └── analyze.yml                 # GitHub Actions workflow
├── run_local_analysis.py           # Local analysis runner
├── config.yaml                     # Configuration
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## 🚀 Quick Start

### 1. Setup Environment

```bash
cd postbuild-analyzer
pip install -r requirements.txt
```

### 2. Run Local Analysis

Analyze the sample project:

```bash
python run_local_analysis.py .
```

Or with custom paths:

```bash
python analyzer/postbuild_analyzer.py /path/to/repo \
  --build-log build.log \
  --test-results test_results.json \
  --coverage-report coverage.json \
  --static-analysis static_analysis.json \
  --output-dir ./reports
```

### 3. View Reports

- **Machine Report**: `reports/machine_report.json` (automation/parsing)
- **Human Report**: `reports/human_report.md` (for developers)

## 📊 Sample Output

### Machine Report (JSON)

```json
{
  "version": "1.0.0",
  "repository": "https://github.com/org/repo",
  "ref": "abc1234",
  "timestamp_utc": "2026-01-19T12:00:00Z",
  "overall_status": "warning",
  "build_summary": {
    "build_status": "failure",
    "build_log_excerpt": "..."
  },
  "tests": {
    "total": 5,
    "passed": 4,
    "failed": 1,
    "skipped": 0,
    "failures": [...]
  },
  "coverage": {
    "overall_percent": 72.5,
    "files_below_threshold": [...]
  },
  "findings": [
    {
      "id": "test_001",
      "title": "Failing test: test_parse_config_invalid",
      "category": "bug",
      "severity": "critical",
      "description": "IndexError: list index out of range",
      "confidence": 1.0,
      "recommendation": "Fix the failing test...",
      "evidence": [...]
    },
    ...
  ]
}
```

### Human Report (Markdown)

```markdown
# Post-Build Code Analysis Report

**Repository:** https://github.com/org/repo
**Commit:** abc1234
**Timestamp:** 2026-01-19T12:00:00Z

## Status: 🟡 **WARNING**

## Quick Summary
- **Build:** failure
- **Tests:** 4/5 passed (80%)
- **Coverage:** 72.5%
- **Issues Found:** 8

## Findings by Severity

### CRITICAL (1)
**Failing test: test_parse_config_invalid**
- Category: bug
- Confidence: 100%
- IndexError: list index out of range

...
```

## 🔧 Configuration

Edit `config.yaml` to customize:

```yaml
coverage_threshold: 80              # Minimum coverage required
complexity_threshold: 10            # Max cyclomatic complexity
severity_mappings:
  critical: [security, failing_tests]
enable_security_scan: true
enable_type_check: true
auto_create_pr: false               # Auto-create PRs for fixes
conservative_mode: true             # Suggest only, don't auto-apply
```

## 📋 Inputs (Build Artifacts)

The analyzer accepts the following inputs:

| Input | Format | Optional | Description |
|-------|--------|----------|-------------|
| `build_log` | Text file | Yes | stdout/stderr from build |
| `test_results` | JSON | Yes | Test summary: `{total, passed, failed, failures[]}` |
| `coverage_report` | JSON | Yes | Coverage data: `{overall_percent, files_below_threshold[]}` |
| `static_analysis` | JSON | Yes | Linter/security results: `{linters[], security[], type_checks[]}` |
| `commit_sha` | String | Yes | Git commit SHA (auto-detected if in git repo) |
| `repo_url` | String | Yes | Repository URL (auto-detected if in git repo) |

### Example: Generate test_results.json

```bash
pytest tests/ -v --json-report --json-report-file=test_results.json
```

### Example: Generate coverage_report.json

```bash
pytest tests/ --cov=src --cov-report=json:coverage_report.json
```

### Example: Generate static_analysis.json

```bash
python -m flake8 src --format=json > static_analysis.json
python -m bandit -r src -f json >> static_analysis.json
```

## 🔍 Analysis Categories

### Bug
- Failing tests
- Null dereferences
- Type errors
- Index/Key errors

### Security
- Hardcoded credentials (CWE-798)
- Use of eval() (CWE-95)
- SQL injection risks (CWE-89)
- Insecure deserialization (CWE-502)

### Test Gap
- Low coverage (<threshold)
- Missing tests for critical paths
- Flaky tests

### Performance
- High complexity (cyclomatic)
- Inefficient algorithms
- Memory leaks

### Style
- Linting issues
- Formatting violations
- Naming conventions

### Maintainability
- High complexity
- Long functions/classes
- Deep nesting

## 🤖 Using with CI/CD

### GitHub Actions

1. **Add workflow** (already included):
   ```bash
   cp .github/workflows/analyze.yml <your-repo>/.github/workflows/
   ```

2. **Commit and push**:
   ```bash
   git add .github/workflows/analyze.yml
   git commit -m "Add PostBuild Analyzer"
   git push
   ```

3. **View reports** in Actions → Artifacts

### Other CI Systems (Jenkins, GitLab, CircleCI)

Adapt the workflow. Core command:
```bash
python analyzer/postbuild_analyzer.py . \
  --build-log build.log \
  --test-results test_results.json \
  --coverage-report coverage.json \
  --static-analysis static_analysis.json
```

## 📝 Integration with Copilot

The analyzer is designed to work with Copilot for enhanced analysis:

1. **Copilot analyzes findings** – you can feed findings to Copilot for:
   - Root cause analysis
   - Fix suggestions with code diffs
   - Test recommendations

2. **Example prompt for Copilot**:
   ```
   Analyze this failing test and suggest a fix:
   
   Test: test_parse_config_invalid
   Error: IndexError: list index out of range
   File: src/sample_module.py, line 8
   Code: first_line = lines[0]
   
   Provide a code patch and unit test.
   ```

## 📊 Report Confidence Scores

Each finding includes a confidence score (0.0–1.0):

- **1.0** = Certain (e.g., test failure, static tool output)
- **0.9** = High confidence (e.g., security scanner finding)
- **0.8** = Good confidence (e.g., linter issue)
- **0.6–0.7** = Medium (e.g., heuristic-based detection)

## 🔐 Security & Privacy

- **Secret Redaction**: Secrets and credentials in logs are flagged (not printed)
- **No External Calls**: Pure local analysis (no telemetry)
- **Open Source**: Audit the code before deployment

## 🛠️ Customization

### Add Custom Analyzers

1. Extend `PostBuildAnalyzer` class:
   ```python
   class CustomAnalyzer(PostBuildAnalyzer):
       def _analyze_custom(self):
           # Your analysis logic
           pass
   ```

2. Call in `analyze()` method:
   ```python
   def analyze(self):
       self._analyze_build()
       self._analyze_custom()  # Your method
       ...
   ```

### Modify Report Format

Edit `_generate_human_report()` and `_generate_machine_report()` methods.

## 🧪 Testing the Analyzer

Run on the sample project:

```bash
python run_local_analysis.py .
```

Expected outputs:
- ✅ `reports/machine_report.json` – structured findings
- ✅ `reports/human_report.md` – readable report
- 📋 3-5 findings including:
  - 1 failing test (critical)
  - 2-3 low coverage files (medium)
  - 2 security issues (high)
  - 1-2 linting issues (low)

## 📚 Resources

- **Copilot Docs**: https://copilot.github.com
- **Bandit (Security)**: https://bandit.readthedocs.io
- **Coverage.py**: https://coverage.readthedocs.io
- **flake8 (Linting)**: https://flake8.pycqa.org

## 📄 License

MIT License – use freely in your projects.

## 🤝 Contributing

Improvements welcome! Submit issues or PRs to extend:
- Additional static analysis tools
- Custom heuristics
- Report formats
- CI/CD integrations

## ❓ FAQ

**Q: Can I run this offline?**
A: Yes! The analyzer is purely local and requires no external services.

**Q: Does it support other languages?**
A: Currently Python-focused. Extensions for Go, Java, JavaScript welcome.

**Q: How do I integrate with my CI/CD?**
A: Copy the GitHub Actions workflow or adapt the core command for your platform.

**Q: Can findings be auto-fixed?**
A: Not by default (conservative mode). Enable `auto_create_pr` in config for low-risk fixes.

---

**Made with ❤️ by GitHub Copilot**
