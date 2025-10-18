# Splunk Security Alerts

A comprehensive security alerting framework for Splunk designed to monitor and detect potential security incidents in hybrid production environments.

## Overview

This repository contains production-ready Splunk configurations for detecting:
- Unauthorized SSH access attempts
- Persistence mechanisms
- Lateral movement
- Data exfiltration
- Privilege escalation
- Account manipulation
- Suspicious network activity

## Features

- **Real-time Security Monitoring**: Continuous monitoring of system, network, and application logs
- **Threat Detection**: Advanced correlation searches for identifying security incidents
- **Dashboard Visualization**: Interactive dashboards for security operations
- **Automated Alerting**: In-app notifications and popup alerts for critical events
- **Threat Intelligence Integration**: Lookup tables for known malicious IPs and domains
- **Customizable Thresholds**: Easily adjustable alert parameters

## Prerequisites

- Splunk Enterprise 8.2+ or Splunk Cloud
- Administrative access to Splunk
- Log forwarding configured for:
  - System logs (syslog, Windows Event Logs)
  - Network logs (firewall, IDS/IPS)
  - Application logs
  - Authentication logs

## Installation

### Method 1: Manual Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/splunk-security-alerts.git
cd splunk-security-alerts
```

2. Copy the app to your Splunk apps directory:
```bash
cp -r . $SPLUNK_HOME/etc/apps/security_alerts/
```

3. Restart Splunk:
```bash
$SPLUNK_HOME/bin/splunk restart
```

4. Navigate to the app in Splunk Web and configure data inputs

### Method 2: Deployment Server

1. Copy the app to your deployment server:
```bash
cp -r . $SPLUNK_HOME/etc/deployment-apps/security_alerts/
```

2. Create a server class and assign clients
3. Deploy the app through the Deployment Server interface

### Method 3: Using the Deployment Script

```bash
./scripts/deploy.sh <splunk_host> <admin_user>
```

## Configuration

### 1. Update Lookup Tables

Update the lookup tables in `lookups/` directory:

- `authorized_ips.csv`: Add your organization's authorized IP ranges
- `malicious_ips.csv`: Update with current threat intelligence
- `sensitive_hosts.csv`: List your critical infrastructure systems
- `authorized_users.csv`: Maintain list of legitimate admin users

### 2. Customize Alert Thresholds

Edit `default/savedsearches.conf` to adjust:
- Alert frequencies
- Threshold values
- Time windows
- Severity levels

### 3. Configure Index Names

Update index references in searches if your environment uses custom index names:
- Default: `index=main` or `index=security`
- Update in `default/macros.conf`

## Alert Categories

### Critical Alerts

| Alert Name | Description | Default Threshold |
|------------|-------------|-------------------|
| Unauthorized SSH Access | Detects SSH login attempts from non-whitelisted IPs | > 3 attempts in 5 minutes |
| Privilege Escalation | Identifies sudo/UAC elevation from unusual accounts | Any occurrence |
| Data Exfiltration | Monitors large outbound transfers to external IPs | > 100MB in 10 minutes |
| Persistence Creation | Detects creation of scheduled tasks, services, or cron jobs | Any suspicious creation |

### High Priority Alerts

| Alert Name | Description | Default Threshold |
|------------|-------------|-------------------|
| Lateral Movement | Tracks unusual service-to-service authentication | > 5 unique targets in 15 minutes |
| Account Manipulation | Monitors account creation, deletion, and privilege changes | Any unauthorized change |
| Command and Control | Identifies potential C2 beacon activity | Periodic connections > 1 hour |
| Suspicious Process Execution | Detects known malicious process patterns | Any occurrence |

### Medium Priority Alerts

| Alert Name | Description | Default Threshold |
|------------|-------------|-------------------|
| Failed Authentication Spike | Monitors authentication failure rates | > 10 failures in 5 minutes |
| Port Scanning Activity | Detects reconnaissance attempts | > 20 ports in 1 minute |
| Unusual Network Protocols | Identifies non-standard protocol usage | Any occurrence |
| File Integrity Violations | Monitors critical file modifications | Any unauthorized change |

## Dashboards

### Security Operations Dashboard
- Real-time threat overview
- Alert timeline and distribution
- Top attacking IPs and targeted systems
- Authentication summary

### SSH Monitoring Dashboard
- SSH access patterns
- Geographic distribution of connections
- Failed vs successful attempts
- Unauthorized access attempts timeline

### Incident Response Dashboard
- Active incidents summary
- Alert correlation timeline
- Affected systems overview
- Response metrics

## Testing

Run the test suite to validate configurations:

```bash
cd tests/
python test_searches.py
python test_lookups.py
./run_tests.sh
```

## Log Source Requirements

### System Logs
- Linux: `/var/log/secure`, `/var/log/auth.log`, `/var/log/messages`
- Windows: Security, System, and Application event logs
- Container logs: Docker/Kubernetes audit logs

### Network Logs
- Firewall logs (allow/deny events)
- IDS/IPS alerts
- NetFlow/sFlow data
- DNS query logs

### Application Logs
- Web server access/error logs
- Database audit logs
- Application authentication logs
- API access logs

## Maintenance

### Daily Tasks
- Review critical alerts
- Update threat intelligence lookups
- Validate alert accuracy

### Weekly Tasks
- Tune alert thresholds based on false positive rates
- Update authorized IP/user lists
- Review dashboard performance

### Monthly Tasks
- Audit search performance
- Update documentation
- Review and archive old alerts

## Troubleshooting

### Common Issues

1. **No alerts firing**
   - Verify data is being indexed
   - Check search time range
   - Validate index names in searches

2. **Too many false positives**
   - Review and update lookup tables
   - Adjust threshold values
   - Add exclusion filters

3. **Performance issues**
   - Optimize search queries
   - Adjust search schedules
   - Review resource allocation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security Considerations

- Regularly update threat intelligence feeds
- Review and audit alert configurations
- Maintain least privilege access to Splunk
- Encrypt sensitive lookup data
- Regular backup of configurations

## Support

For issues, questions, or contributions:
- Open an issue in this repository
- Consult Splunk documentation
- Review logs in `$SPLUNK_HOME/var/log/splunk/`

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Splunk Security Essentials
- MITRE ATT&CK Framework
- Community threat intelligence contributors

---

**Version**: 1.0.0
**Last Updated**: 2025-01-18
**Maintained By**: Security Operations Team