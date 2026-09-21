# Splunk Security Alerts

This repository is a Splunk app that turns security-relevant events into
scheduled saved-search results. It supplies field extractions, reusable search
macros, lookup-backed enrichment, alert definitions, dashboards, and a secure
deployment script. The checked-in files describe the detection logic; a live
Splunk instance and correctly ingested data are still required to observe alert
results.

```mermaid
flowchart LR
    E["Security events<br/>Linux, Windows, network, application"]
    P["props.conf<br/>field extraction"]
    I["Splunk indexes"]
    S["savedsearches.conf<br/>scheduled searches"]
    X["Enrichment<br/>lookups, macros, transforms"]
    Q{"Search result<br/>and suppression"}
    N["Notable event<br/>explicitly configured"]
    D["XML dashboards"]
    A["Analyst review"]

    E --> P --> I --> S
    X --> S
    S --> Q
    Q --> N --> A
    Q --> D --> A

    style E fill:#1f6feb,stroke:#58a6ff,color:#fff
    style S fill:#238636,stroke:#3fb950,color:#fff
    style Q fill:#9e6a03,stroke:#d29922,color:#fff
    style A fill:#8250df,stroke:#bc8cff,color:#fff
```

## Quick start

From the repository root, inspect the checked-in configuration without a
Splunk installation:

```sh
python3 tools/measure_alerts.py
```

This command is verified in this checkout. It reads the app's `.conf`, `.csv`,
and dashboard files and reports the inventory used by the documentation. It
does not execute SPL or contact Splunk.

To deploy to a real Splunk host, review the secure deployment script first and
then run it from the repository root on a host where `SPLUNK_HOME` points to an
installed Splunk instance:

```sh
./deployment/deploy_secure.sh --no-restart
```

The deployment command was not run in this documentation pass because this
workspace has no Splunk instance. It performs host-level changes, asks for
credentials, and defaults to writing a log outside the repository. See
[Operations](docs/operations.md) before using it.

## Architecture

The app has source-side stages that parse incoming events, enrich them with
repository data, evaluate scheduled searches, and present or route results.
The exact relationship between the files is shown in
[the architecture write-up](docs/architecture-overview.md).

## Capabilities

| Capability | Source of truth | What it does |
|---|---|---|
| Event parsing | `default/props.conf` | Extracts fields from Linux, Windows, network, web, application, container, database, and security-tool logs. |
| Search reuse | `default/macros.conf` | Provides reusable index, time, identity, IP, process, risk, and parsing expressions. |
| Enrichment and routing | `default/transforms.conf` and `lookups/` | Defines lookup tables, field extraction rules, event routing, and classifications. |
| Detection | `default/savedsearches.conf` | Schedules searches for authentication, access, process, persistence, network, integrity, and correlation signals. |
| Visualization | `default/data/ui/views/*.xml` | Defines the Security Operations and SSH Monitoring dashboards. |
| Deployment | `deployment/deploy_secure.sh` | Validates, backs up, copies, permissions, and optionally restarts a Splunk app. |

## Measured repository inventory

These are source measurements from `python3 tools/measure_alerts.py`, not
runtime or detection-performance benchmarks.

| Artifact | Measured value |
|---|---:|
| Saved-search stanzas | 13 |
| Static severity `5` / `4` / `3` | 4 / 5 / 4 |
| Searches with `alert.track = 1` | 13 |
| Searches with suppression enabled | 6 |
| Searches with `action.notable = 1` | 1 |
| Searches with `action.email = 1` | 0 |
| Searches with `action.script = 1` | 0 |
| Lookup CSV files | 7 |
| `macros.conf` / `props.conf` / `transforms.conf` stanzas | 24 / 14 / 42 |
| Dashboard views | 2 |
| Dashboard panels: security operations / SSH monitoring | 10 / 12 |

The alert names, thresholds, windows, suppression keys, routing, and false
positive notes are in the [alert reference](docs/alert-reference.md). The
measurement method and unverified areas are in
[How measurements were made](docs/measurement.md).

## Repository layout

```text
security_alerts_app/
├── bin/                 validation helper
├── default/             app metadata, searches, parsing, macros, transforms,
│                        dashboards, and permissions
└── lookups/             CSV enrichment and allow-list data
deployment/              standard and secure deployment scripts
docs/                    source-backed diagrams and operating notes
scripts/                 hooks and package creation
security/                policies, playbooks, and security documentation
tests/                   repository validation scripts
tools/                   measurement scripts used by this documentation
```

## Known limitations

- The repository does not contain a Splunk instance, sample event corpus, or
  live alert history. Search execution, detection latency, dashboard rendering,
  and false-positive rates are therefore not measured here.
- The saved searches configure a single explicit notable action. No email or
  script action is enabled in the checked-in stanzas, so the old claim of
  broad smart notification coverage is not supported by this source tree.
- The alert lifecycle implemented by the app ends at a tracked or routed search
  result. Analyst triage, escalation, resolution, and case management are
  operating procedures, not states implemented in these files.
- Seven lookup references in the configuration do not have matching CSV files.
  The exact names are listed in [Data and enrichment](docs/data-and-enrichment.md).
- The existing test scripts still use paths from an older app layout and fail
  before validating the current files. This pass records that failure and does
  not change application behavior.
- The secure deployment script was not run. It requires a live Splunk host,
  suitable permissions, credentials, and host-level tools.

## Documentation

Start with the [documentation index](docs/README.md), then use the component
write-ups for the alert lifecycle, configuration flow, enrichment data, and
operations. Every published measurement is explained in
[docs/measurement.md](docs/measurement.md).
