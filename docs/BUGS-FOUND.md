[← back to the overview](../README.md)

# Bugs found

| # | Entry | Status |
|---|---|---|
| 1 | `tests/test_searches.py` looks for `savedsearches.conf` in the wrong place | Fixed in [`766ed2d`](https://github.com/Bissbert/splunk-security-alerts/commit/766ed2d) |
| 2 | `tests/run_tests.sh` checks paths from an older layout | Fixed in [`09e066d`](https://github.com/Bissbert/splunk-security-alerts/commit/09e066d) |
| 3 | The validator marks every search after the first error as failed | Fixed in [`5ac4449`](https://github.com/Bissbert/splunk-security-alerts/commit/5ac4449) (#4) |
| 4 | The bracket check counts brackets inside quoted regexes | Fixed in [`5ac4449`](https://github.com/Bissbert/splunk-security-alerts/commit/5ac4449) (#5) |
| 5 | Failed Authentication Spike looks up `malicious_ips.csv` by a column it does not have | Fixed in [`5b3e4c7`](https://github.com/Bissbert/splunk-security-alerts/commit/5b3e4c7) (#6) |

Entries 3 and 4 turned up once entries 1 and 2 were fixed and the validator
ran for the first time, in the Linux run described in
[How measurements were made](measurement.md). Entry 5 turned up while writing
the unit tests that check lookup fields against the shipped CSV headers. With
all five fixed, `python3 tests/test_searches.py` reports 13 of 13 searches
valid and both test entry points exit 0.

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

**Status:** fixed in [`5ac4449`](https://github.com/Bissbert/splunk-security-alerts/commit/5ac4449) (#4).

**File:** `tests/test_searches.py`, `validate_search_syntax`

**What happened:** the method ended with `return len(self.errors) == 0`.
`self.errors` collects errors for every search checked so far, so once one
search had an error, every later search was reported as failed even when it
had none. The summary showed the mismatch:

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

**What changed:** the method records `len(self.errors)` when it starts and
returns whether the count stayed the same, so each search is judged on its own
errors.

**Check:** `test_validator.PerSearchResultTest` validates a broken search
followed by a valid one, and `ConfigRunTest.test_counts_only_the_broken_search`
runs a whole config with one bad stanza and expects exactly one failure. Both
fail with the old return line.

## 4. The bracket check counts brackets inside quoted regexes

**Status:** fixed in [`5ac4449`](https://github.com/Bissbert/splunk-security-alerts/commit/5ac4449) (#5).

**File:** `tests/test_searches.py`, `validate_search_syntax`

**What happened:** the check compared the number of `[` and `]` characters in
the whole query. **Privilege Escalation Detected** matches `su` log lines with
the regex `"su\\[.*authentication success"`. That `[` is escaped inside a
quoted string, so the SPL is valid, but the check reported:

```text
✗ Privilege Escalation Detected: Unbalanced square brackets
```

This was the only error, and it made `python3 tests/test_searches.py` and
`bash tests/run_tests.sh` exit 1.

**What changed:** a new `scan_spl` helper returns the query with double-quoted
strings removed (backslash escapes included) and reports an unterminated
quote. The quote, parenthesis and bracket checks run on that text, and the
balance check now also catches a closing bracket before its opening one.

**Check:** `test_validator.SyntaxCheckTest` covers brackets and parentheses
inside quotes, real subsearch brackets, unbalanced and reversed brackets, and
unterminated quotes. `ShippedConfigTest` expects all 13 shipped searches to be
valid; with the old check it sees 12 and one error.

## 5. Failed Authentication Spike looks up `malicious_ips.csv` by a column it does not have

**Status:** fixed in [`5b3e4c7`](https://github.com/Bissbert/splunk-security-alerts/commit/5b3e4c7) (#6).

**File:** `security_alerts_app/default/savedsearches.conf`, stanza
`[Failed Authentication Spike]`

**What happened:** the search ran
`lookup malicious_ips.csv src_ip OUTPUT is_malicious`. The header of
`malicious_ips.csv` is
`dest_ip,is_malicious,threat_type,confidence,last_seen,source`; there is no
`src_ip` column. Splunk rejects a lookup on a field the table does not have,
so the `is_malicious="true"` branch that raises the result severity to `high`
could never apply.

**What changed:** the search matches the table's `dest_ip` column against the
event's source address:
`lookup malicious_ips.csv dest_ip AS src_ip OUTPUT is_malicious`. The other
two searches that use this lookup already match on `dest_ip`.

**Check:** `test_app_files.LookupFilesTest.test_search_lookup_fields_exist_in_the_csv`
reads every `lookup <file>.csv` in the saved searches and checks that the match
and `OUTPUT` fields are columns in the shipped CSV. It fails on the old search.

## Reproduce

```sh
sh tests/docker.sh     # the full test suite in python:3.12-slim-bookworm
sh tools/linux-run.sh  # the measurement run, including the tests
```

The relevant sections of the measurement output are
`python3 tests/test_searches.py`, `python3 -m unittest test_validator test_app_files`
and `bash tests/run_tests.sh`; a recorded run is in
[`media/captures/linux-run.txt`](../media/captures/linux-run.txt).
