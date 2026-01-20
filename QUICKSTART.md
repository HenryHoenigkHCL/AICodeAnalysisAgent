# Quick Start Guide for PostBuild Analyzer

## Installation

```bash
pip install -r requirements.txt
```

## Running Locally

### Option 1: Using the convenience script

```bash
python run_local_analysis.py .
```

### Option 2: Direct CLI

```bash
python analyzer/postbuild_analyzer.py . \
  --build-log reports/build.log \
  --test-results reports/test_results.json \
  --coverage-report reports/coverage_report.json \
  --static-analysis reports/static_analysis.json \
  --output-dir reports
```

## View Reports

After running, open the generated reports:

- **Machine Report** (JSON): `reports/machine_report.json`
- **Human Report** (Markdown): `reports/human_report.md`

The human report will look like this in any text editor or markdown viewer:

```
# Post-Build Code Analysis Report

Repository: https://github.com/...
Commit: abc1234
Timestamp: 2026-01-19T12:00:00Z

## Status: 🟡 **WARNING**

## Quick Summary
- Build: failure
- Tests: 4/5 passed (80%)
- Coverage: 72.5%
- Issues Found: 8

... detailed findings ...
```

## Key Files to Know

| File | Purpose |
|------|---------|
| `analyzer/postbuild_analyzer.py` | Core analysis engine |
| `run_local_analysis.py` | Convenience script for local runs |
| `config.yaml` | Configuration (thresholds, options) |
| `reports/` | Generated reports directory |
| `.github/workflows/analyze.yml` | GitHub Actions workflow |

## Next Steps

1. **Copy to your project**: Place `postbuild-analyzer` in your repository
2. **Add to CI**: Push `.github/workflows/analyze.yml` to trigger on push/PR
3. **Customize**: Edit `config.yaml` for your project's needs
4. **Run locally**: Use `run_local_analysis.py` during development

## Troubleshooting

**Q: ModuleNotFoundError when running?**
A: Ensure you're in the right directory and dependencies are installed:
```bash
cd postbuild-analyzer
pip install -r requirements.txt
python run_local_analysis.py .
```

**Q: No reports generated?**
A: Check that sample artifacts exist in `reports/`:
```bash
ls -la reports/
```

Should have: `build.log`, `test_results.json`, `coverage_report.json`, `static_analysis.json`

**Q: How do I run on my own project?**
A: Collect your artifacts first, then point to them:
```bash
python analyzer/postbuild_analyzer.py /path/to/my/repo \
  --build-log /path/to/build.log \
  --test-results /path/to/test_results.json \
  ...
```

---

**Need help?** See `README.md` for full documentation.
