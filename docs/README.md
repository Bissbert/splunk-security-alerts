# Documentation

The component write-ups below are the source-backed documentation for the
checked-in Splunk app. Start with the overview, then use the alert reference
when investigating a rule and the operations page when deploying it.

| Write-up | Covers |
|---|---|
| [Architecture overview](architecture-overview.md) | Event parsing, enrichment, saved searches, dashboards, and result flow. |
| [Alert reference](alert-reference.md) | Implemented alert lifecycle, severity and routing matrix, and one row per alert. |
| [Data and enrichment](data-and-enrichment.md) | Props, transforms, macros, lookup files, and missing lookup references. |
| [Operations](operations.md) | Deployment flow, source-only checks, dashboards, and current validation limits. |
| [Measurement](measurement.md) | The Linux container run: every reported number, the test results, and what was not covered. |
| [Bugs found](BUGS-FOUND.md) | Two fixed test-path bugs and two open validator bugs. |

Numbers in the component write-ups are measurements of repository files unless
they are explicitly marked as unmeasured. The measurement script has no
Splunk, network, or third-party runtime dependency:

```sh
python3 tools/measure_alerts.py
```

[← back to the overview](../README.md)
