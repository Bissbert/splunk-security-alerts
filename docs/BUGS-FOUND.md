[← back to the overview](../README.md)

# Bugs found

| # | Entry | Status |
|---|---|---|
| 1 | `tests/test_searches.py` looks for `savedsearches.conf` in the wrong place | Fixed in [`766ed2d`](https://github.com/Bissbert/splunk-security-alerts/commit/766ed2d) |
| 2 | `tests/run_tests.sh` checks paths from an older layout | Fixed in [`09e066d`](https://github.com/Bissbert/splunk-security-alerts/commit/09e066d) |
| 3 | The validator marks every search after the first error as failed | Open |
| 4 | The bracket check counts brackets inside quoted regexes | Open |

Entries 3 and 4 turned up once entries 1 and 2 were fixed and the validator
ran for the first time, in the Linux run described in
[How measurements were made](measurement.md). Because of entry 4, both test
entry points currently exit 1 on a search that is valid SPL.

## 1. `tests/test_searches.py` looks for `savedsearches.conf` in the wrong place

**Status:** fixed in [`766ed2d`](https://github.com/Bissbert/splunk-security-alerts/commit/766ed2d).

**What happened:** the test built `default/savedsearches.conf` relative to the
repository root. The file is at
`security_alerts_app/default/savedsearches.conf`, so the test exited before
loading any configuration:

```text
Error: Configuration file not found at .../default/savedsearches.conf
```

**What changed:** the path now resolves beneath `security_alerts_app/default`.
The test loads all 13 searches and validates them.

## 2. `tests/run_tests.sh` checks paths from an older layout

**Status:** fixed in [`09e066d`](https://github.com/Bissbert/splunk-security-alerts/commit/09e066d).

**What happened:** the runner changed into `tests/` and checked
`../default/*.conf`, `../lookups/`, `../dashboards/` and `../scripts/deploy.sh`.
The first check failed and the script exited:

```text
Test 1: Checking configuration files...
  ✗ ../default/savedsearches.conf missing
```

**What changed:** every path now points into `security_alerts_app/`,
`deployment/` and `docs/`. In the Linux run all four configuration files, all
five lookups and both dashboards are found, and both dashboards pass
`xmllint`. The runner then reaches the Python validation and exits with its
status.

## 3. The validator marks every search after the first error as failed

**Status:** open.

**File:** `tests/test_searches.py:52`

**What happens:** `validate_search_syntax` ends with
`return len(self.errors) == 0`. `self.errors` collects errors for every search
checked so far, so once one search has an error, every later search is
reported as failed even when it has none. The summary shows the mismatch:

```text
Validating: Privilege Escalation Detected
  ✗ Search syntax errors found
Validating: Data Exfiltration Attempt
  ✗ Search syntax errors found
...
Total searches: 13
Valid searches: 1
Errors: 1
```

**Possible fix:** remember `len(self.errors)` at the start of the method and
return whether it grew.

## 4. The bracket check counts brackets inside quoted regexes

**Status:** open.

**File:** `tests/test_searches.py:40-41`

**What happens:** the check compares the number of `[` and `]` characters in
the whole query. **Privilege Escalation Detected** matches `su` log lines with
the regex `"su\\[.*authentication success"`. That `[` is escaped inside a
quoted string, so the SPL is valid, but the check reports:

```text
✗ Privilege Escalation Detected: Unbalanced square brackets
```

This is the only error, and it makes `python3 tests/test_searches.py` and
`bash tests/run_tests.sh` exit 1.

**Possible fix:** skip quoted strings before counting brackets, which is what
SPL subsearch brackets need anyway.

## Reproduce

```sh
sh tools/linux-run.sh
```

The relevant sections of the output are `python3 tests/test_searches.py` and
`bash tests/run_tests.sh`; a recorded run is in
[`media/captures/linux-run.txt`](../media/captures/linux-run.txt).
