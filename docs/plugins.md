# Writing a plugin

loginscan discovers extra checks from the `loginscan.checks` entry-point group. A check is any
object with a `CHECK` name and `run(client, cfg) -> list[Finding]` — a plain function works too
(its entry-point name becomes the check name).

```python
# mypkg/mycheck.py
from loginscan.models import Finding, Severity, Status

CHECK = "mycheck"

def run(client, cfg):
    resp = client.get(cfg.url)
    if resp.header("x-powered-by"):
        return [Finding(CHECK, Status.WARNING, Severity.LOW,
                        "Tech stack disclosed", "X-Powered-By header is present.",
                        remediation="Remove the X-Powered-By header.")]
    return [Finding(CHECK, Status.OK, Severity.INFO, "No tech disclosure", "")]
```

```toml
# mypkg/pyproject.toml
[project.entry-points."loginscan.checks"]
mycheck = "mypkg.mycheck"
```

After `pip install mypkg`:

```bash
loginscan --list-checks      # shows "mycheck"
loginscan --site ... --i-own-this   # runs it automatically
```

## The client

`client` is an `HttpClient` with a request budget. Useful methods:

- `client.get(url, headers=None)` and `client.request(method, url, data=..., content_type=...)`
- `client.burst(method, url, data, n, content_type)` — n concurrent requests (for race tests)
- `client.remaining` — remaining request budget

Keep checks **low-volume and non-destructive**, and return findings with a clear remediation.
