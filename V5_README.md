# CyberScope V5

CyberScope V5 extends the existing CyberScope project with a separated, conservative SQL-injection *signal-check* module and clean JSON + Markdown reporting.

## Safety and scope
- Use only on systems you own or where you have explicit written authorisation.
- The calling application must pass both `authorised=True` and `allowlisted=True`. Connect this to the app's existing allowlist/consent workflow.
- This module does not enumerate databases/tables/users, dump records, crack credentials, run stacked queries, run time-delay exploitation, or invoke sqlmap.
- A response difference or database-like error is only a signal. It is not proof of SQL injection.
- Keep testing in scope, at low request volume, and stop if the application becomes unstable.

## What is included
- `v5/sqli_signals.py`: curl-backed HTTP GET checks (falls back to Python HTTP client if curl is absent), conservative query-parameter quote-character comparison, evidence capture, and JSON + Markdown report generation.
- Existing V4 files are preserved in the archive.
- The module is intentionally separate from existing checks and reporting.

## Integration example
```python
from v5.sqli_signals import safe_sql_signal_check, write_reports

# Only set these booleans after the existing app has independently verified
# written permission and exact allowlist membership.
results = safe_sql_signal_check(
    "https://staging.example.test/search?q=sample",
    authorised=True,
    allowlisted=True,
)
json_path, markdown_path = write_reports(results, "reports", "https://staging.example.test")
print(json_path, markdown_path)
```

Do not hard-code the flags to `True` in a public-facing scanner. Wire them to the app's authorization and allowlist state. Do not scan third-party systems without permission.

## Dependencies
The signal module uses the Python standard library and `curl` if installed. Existing V4 dependencies and launch instructions remain in the existing README/project files.

## Limitations
- It checks only the first three URL query parameters.
- It performs one baseline and one single-quote comparison per parameter with delays.
- It does not test POST/JSON bodies, authentication workflows, second-order SQLi, blind SQLi, or database contents.
- False negatives are possible; false positives are possible.
