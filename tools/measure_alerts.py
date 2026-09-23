#!/usr/bin/env python3
"""Measure the repository's checked-in Splunk configuration.

This script intentionally reads only repository files.  It does not require a
Splunk instance and does not claim that the searches have run in Splunk.
"""

from __future__ import annotations

import configparser
import csv
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "security_alerts_app"
DEFAULT = APP / "default"
LOOKUPS = APP / "lookups"
VIEWS = DEFAULT / "data" / "ui" / "views"


def load_conf(path: Path) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(interpolation=None)
    parser.optionxform = str
    with path.open(encoding="utf-8") as handle:
        parser.read_file(handle)
    return parser


def stanza_count(path: Path) -> int:
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines()
               if line.startswith("[") and line.endswith("]"))


def severity_literals(text: str) -> list[str]:
    return sorted(set(re.findall(
        r'"(critical|high|medium|low|info)"', text,
        flags=re.IGNORECASE,
    )))


def alert_measurements() -> tuple[configparser.RawConfigParser, list[str]]:
    path = DEFAULT / "savedsearches.conf"
    parser = load_conf(path)
    names = parser.sections()
    print(f"saved_searches={len(names)}")

    static_severity = Counter(
        parser[name].get("alert.severity", "unset") for name in names
    )
    print("static_severity_counts=" + ",".join(
        f"{key}:{static_severity[key]}" for key in sorted(static_severity)
    ))

    schedules = Counter(parser[name].get("cron_schedule", "unset") for name in names)
    print("schedule_counts=" + ",".join(
        f"{key}:{schedules[key]}" for key in sorted(schedules)
    ))

    suppressed = [name for name in names
                  if parser[name].get("alert.suppress", "0") == "1"]
    print(f"suppressed_searches={len(suppressed)}")

    tracked = [name for name in names
               if parser[name].get("alert.track", "0") == "1"]
    print(f"tracked_searches={len(tracked)}")

    for action in ("action.notable", "action.email", "action.script"):
        enabled = [name for name in names if parser[name].get(action, "0") == "1"]
        print(f"{action.replace('.', '_')}_enabled={len(enabled)}")
        if enabled:
            print(f"{action.replace('.', '_')}_names=" + " | ".join(enabled))

    print("alerts:")
    for name in names:
        search = parser[name].get("search", "")
        dynamic = severity_literals(search)
        lookups = sorted(set(re.findall(r"([A-Za-z0-9_]+\.csv)", search)))
        actions = [action for action in ("notable", "email", "script")
                   if parser[name].get(f"action.{action}", "0") == "1"]
        route = ",".join(actions) if actions else "none-configured"
        dynamic_value = ",".join(dynamic) if dynamic else "none"
        lookup_value = ",".join(lookups) if lookups else "none"
        print(
            "  "
            f"{name} | static={parser[name].get('alert.severity', 'unset')} "
            f"| cron={parser[name].get('cron_schedule', 'unset')} "
            f"| window={parser[name].get('dispatch.earliest_time', 'unset')}.."
            f"{parser[name].get('dispatch.latest_time', 'unset')} "
            f"| dynamic={dynamic_value} | route={route} "
            f"| suppression={parser[name].get('alert.suppress', '0')} "
            f"| lookup={lookup_value}"
        )
    return parser, names


def lookup_measurements() -> None:
    files = sorted(LOOKUPS.glob("*.csv"))
    print(f"lookup_files={len(files)}")
    for path in files:
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.reader(handle))
        header = rows[0] if rows else []
        print(
            f"  {path.name} | columns={len(header)} | data_rows="
            f"{max(len(rows) - 1, 0)}"
        )


def configuration_measurements() -> None:
    for name in ("macros.conf", "props.conf", "transforms.conf"):
        path = DEFAULT / name
        print(f"{name}_stanzas={stanza_count(path)}")

    views = sorted(VIEWS.glob("*.xml"))
    print(f"dashboard_views={len(views)}")
    for path in views:
        root = ET.parse(path).getroot()
        panels = len(root.findall(".//panel"))
        print(f"  {path.name} | panels={panels}")

    referenced = set()
    for path in sorted(DEFAULT.glob("*.conf")):
        referenced.update(re.findall(r"([A-Za-z0-9_]+\.csv)",
                                     path.read_text(encoding="utf-8")))
    present = {path.name for path in LOOKUPS.glob("*.csv")}
    missing = sorted(referenced - present)
    print(f"lookup_references={len(referenced)}")
    print("missing_lookup_references=" + (", ".join(missing) if missing else "none"))


def main() -> int:
    print(f"repository={ROOT}")
    alert_measurements()
    lookup_measurements()
    configuration_measurements()
    return 0


if __name__ == "__main__":
    sys.exit(main())
