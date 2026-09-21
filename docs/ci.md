# CI & config

## Config profiles

Save a reusable profile (JSON, or YAML with `pyyaml`) instead of long command lines:

```json
{ "site": "https://staging/login", "user": "alice", "success": ["Welcome"],
  "skip": ["cache"], "min_score": 80, "fail_on": "vulnerable" }
```

```bash
loginscan --config profile.json --i-own-this
```

CLI flags override the config.

## Gating

- `--fail-on {vulnerable,warning,never}` — what makes the run exit `1`.
- `--min-score N` — fail if the score is below `N`.
- `--baseline file` / `--write-baseline file` — accept existing findings so only **new**
  issues fail the build.

## GitHub Action

```yaml
name: loginscan
on: [push]
permissions:
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: bayraktarulku/loginscan@v1
        with:
          site: https://staging.example.com/login
          user: alice
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: loginscan.sarif
```

Using the action asserts you are authorized to test the target.
