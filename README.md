# splunk-security-alerts

![GitHub last commit](https://img.shields.io/github/last-commit/Bissbert/splunk-security-alerts)

> Reusable detection-as-code Splunk app — 13 production-tuned saved searches, lookup-driven allowlisting, two dashboards, and incident-response playbooks in one deployable package.

## Why

Writing Splunk alerts from scratch means reinventing the same SPL patterns for brute-force, privilege escalation, lateral movement, and data exfiltration over and over. This app provides a version-controlled, CI-tested baseline that you adjust to your environment rather than author from zero. It pairs with [posix-ids](https://github.com/Bissbert/posix-ids), which generates the host-level JSON events that these searches consume.

## Quick start

```bash
git clone https://github.com/Bissbert/splunk-security-alerts.git
cd splunk-security-alerts

# Automated deploy (prompts for Splunk admin password and install path)
./deployment/deploy_secure.sh

# Manual copy
cp -r security_alerts_app /opt/splunk/etc/apps/
chown -R splunk:splunk /opt/splunk/etc/apps/security_alerts_app
/opt/splunk/bin/splunk restart

# Edit your environment's trusted IPs before enabling alerts
nano security_alerts_app/lookups/authorized_ips.csv
```

## How it works

- `security_alerts_app/default/savedsearches.conf` — 13 saved searches running on 5- or 10-minute schedules, covering: unauthorized SSH access, privilege escalation, data exfiltration, brute-force login, lateral movement, new admin account creation, C2 communication, persistence mechanisms, port scanning, critical file changes, unusual protocols, credential abuse, and attack chain correlation.
- `security_alerts_app/default/props.conf` / `transforms.conf` — field extractions and lookup-backed transforms for log normalization.
- `security_alerts_app/lookups/` — CSV allowlists for authorized IPs, users, scanners, hosts, and known-bad IPs. Edit these to reduce false positives.
- `security_alerts_app/default/data/ui/views/` — Security Operations Center dashboard and SSH Monitoring dashboard.
- `security_alerts_app/bin/security_validator.py` — Python helper that validates lookup integrity and configuration on deploy.
- `security/playbooks/` — incident-response playbooks and a SOC operations runbook.
- `deployment/deploy_secure.sh` — hardened deploy script with SHA-256 verification and permission enforcement.
- `tests/test_searches.py` — Python-based search validation; `tests/run_tests.sh` runs the suite.

## Configuration

All tuning is done through lookup CSV files and Splunk's saved search threshold parameters:

| File | Purpose |
|---|---|
| `lookups/authorized_ips.csv` | IPs that bypass the unauthorized-access alert |
| `lookups/authorized_users.csv` | Accounts excluded from privilege-escalation checks |
| `lookups/malicious_ips.csv` | Known-bad IPs used in exfiltration risk scoring |
| `lookups/sensitive_hosts.csv` | High-value hosts that raise alert severity |

Splunk version 8.0 or later required (Enterprise or Cloud). Logs must be indexed before alerts fire.

## Status

Actively maintained.

## License

MIT
