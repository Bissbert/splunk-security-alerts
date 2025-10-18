# Splunk Security Alerts

A comprehensive, professionally structured security alerting framework for Splunk designed to monitor and detect potential security incidents in hybrid production environments.

## Overview

This repository contains a production-ready Splunk application for enterprise security monitoring and threat detection. The framework has been reorganized following Splunk best practices for easy deployment, maintenance, and scalability.

## Project Structure

```
splunk-alerting/
├── security_alerts_app/          # Main Splunk application
│   ├── bin/                     # Python scripts and executables
│   ├── default/                 # Default configurations
│   │   ├── app.conf            # Application metadata
│   │   ├── savedsearches.conf  # Alert definitions
│   │   ├── props.conf          # Field extractions
│   │   ├── transforms.conf     # Data transformations
│   │   ├── macros.conf         # Search macros
│   │   └── data/ui/views/      # Dashboard definitions
│   ├── lookups/                # Lookup tables for threat intelligence
│   ├── local/                  # Local customizations (gitignored)
│   └── metadata/               # Object permissions
├── security/                    # Security documentation
│   ├── playbooks/              # Incident response playbooks
│   ├── policies/               # Security policies
│   └── documentation/          # Security improvements and guides
├── docs/                       # General documentation
│   ├── configuration/          # Configuration guides
│   ├── integration/            # Integration documentation
│   └── operations/             # Operational procedures
├── deployment/                 # Deployment scripts
│   ├── deploy.sh              # Standard deployment
│   └── deploy_secure.sh       # Hardened deployment
└── tests/                      # Test suite
    ├── test_searches.py       # Search validation
    └── run_tests.sh           # Test runner

```

## Features

- **Real-time Security Monitoring**: Continuous monitoring of system, network, and application logs
- **Advanced Threat Detection**: Correlation searches aligned with MITRE ATT&CK framework
- **Dashboard Visualization**: Interactive dashboards for SOC operations
- **Automated Alerting**: Multi-channel alert delivery (in-app, email, webhook)
- **Threat Intelligence Integration**: Dynamic lookup tables for IOCs
- **Security Hardening**: Built-in security configurations and best practices
- **Modular Architecture**: Easy to extend and customize

## Detection Capabilities

### Critical Security Events
- Unauthorized SSH access attempts
- Privilege escalation activities
- Data exfiltration attempts
- Persistence mechanism creation
- Lateral movement detection
- Account manipulation
- Command and control communication
- Suspicious process execution

### Compliance Monitoring
- Failed authentication tracking
- File integrity monitoring
- Access control violations
- Configuration changes
- Audit log tampering

## Prerequisites

- **Splunk Enterprise**: Version 8.2+ or Splunk Cloud
- **Access Requirements**: Administrative privileges for app installation
- **Data Sources**:
  - System logs (syslog, Windows Event Logs)
  - Network logs (firewall, IDS/IPS)
  - Application logs
  - Authentication logs
  - Cloud service logs (AWS, Azure, GCP)

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Bissbert/splunk-security-alerts.git
cd splunk-alerting

# Deploy using the automated script
./deployment/deploy.sh --splunk-home /opt/splunk
```

### Secure Installation (Recommended)

```bash
# Use the hardened deployment script
./deployment/deploy_secure.sh --splunk-home /opt/splunk

# This includes:
# - File integrity verification
# - Secure permission settings
# - Automated backups
# - Health checks
```

### Manual Installation

1. **Copy the application:**
```bash
cp -r security_alerts_app $SPLUNK_HOME/etc/apps/
```

2. **Set permissions:**
```bash
chmod -R 755 $SPLUNK_HOME/etc/apps/security_alerts_app
chown -R splunk:splunk $SPLUNK_HOME/etc/apps/security_alerts_app
```

3. **Restart Splunk:**
```bash
$SPLUNK_HOME/bin/splunk restart
```

## Configuration Guide

### 1. Initial Setup

After installation, navigate to **Apps > Security Alerts** in Splunk Web and:

1. Verify data inputs are configured
2. Update lookup tables with environment-specific data
3. Configure alert actions (email, webhook, etc.)
4. Set appropriate index names in macros

### 2. Customize Lookup Tables

Update the CSV files in `security_alerts_app/lookups/`:

| File | Purpose | Format |
|------|---------|--------|
| `authorized_ips.csv` | Whitelisted IP addresses | ip,description,owner |
| `malicious_ips.csv` | Known malicious IPs | ip,threat_type,source |
| `sensitive_hosts.csv` | Critical infrastructure | hostname,ip,criticality |
| `authorized_users.csv` | Privileged accounts | username,role,department |
| `critical_files.csv` | Monitored file paths | path,system,hash |
| `authorized_scanners.csv` | Security tools | ip,tool_name,owner |
| `standard_protocols.csv` | Allowed protocols | protocol,port,service |

### 3. Alert Customization

Edit `security_alerts_app/default/savedsearches.conf` to adjust:

```conf
[SSH - Unauthorized Access Attempt]
# Adjust the threshold
search = ... | where failure_count > 5  # Default: 3
# Change the schedule
cron_schedule = */5 * * * *  # Every 5 minutes
# Modify severity
alert.severity = 3  # 1=info, 2=low, 3=medium, 4=high, 5=critical
```

### 4. Index Configuration

Update index names in `security_alerts_app/default/macros.conf`:

```conf
[security_index]
definition = index=security OR index=main

[network_index]
definition = index=network OR index=firewall
```

## Alert Priority Matrix

| Priority | Response Time | Examples | Action |
|----------|--------------|----------|--------|
| **Critical** | < 15 min | Data exfil, ransomware | Immediate incident response |
| **High** | < 1 hour | Privilege escalation | Security team investigation |
| **Medium** | < 4 hours | Suspicious logins | SOC analyst review |
| **Low** | < 24 hours | Policy violations | Scheduled review |
| **Info** | Weekly | Compliance checks | Reporting only |

## Dashboards

### Security Operations Center (SOC) Dashboard
- Real-time threat overview
- Alert timeline and statistics
- Top threats and targets
- Mean time to detect (MTTD) metrics

### SSH Monitoring Dashboard
- Authentication patterns and anomalies
- Geographic access distribution
- Failed vs successful attempts
- Brute force detection

### Incident Response Dashboard
- Active incident tracking
- Alert correlation timeline
- Affected systems mapping
- Response team assignments

## Testing and Validation

```bash
# Run the complete test suite
cd tests/
./run_tests.sh

# Test specific components
python test_searches.py --component ssh_alerts
python test_searches.py --validate-lookups

# Verify deployment
cd ../deployment/
./deploy_secure.sh --verify-only
```

## Security Hardening

The framework includes several security enhancements:

1. **File Integrity Monitoring**: SHA-256 checksums for all configurations
2. **Access Controls**: Restrictive permissions via metadata
3. **Secure Deployment**: Automated security validation
4. **Audit Logging**: Comprehensive deployment and change tracking
5. **Input Validation**: Sanitization of all user inputs
6. **Encrypted Storage**: Support for encrypted lookup tables

## Operational Procedures

### Daily Operations
- Review critical and high priority alerts
- Update threat intelligence feeds
- Validate detection accuracy
- Check system health metrics

### Weekly Maintenance
- Tune alert thresholds based on false positive analysis
- Update authorized IP and user lists
- Review dashboard performance
- Generate executive reports

### Monthly Tasks
- Comprehensive search optimization
- Documentation updates
- Alert rule effectiveness review
- Backup verification

## Troubleshooting Guide

### Common Issues and Solutions

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| No alerts firing | Check data ingestion | Verify index names and time ranges |
| High false positives | Threshold too sensitive | Adjust thresholds, update whitelists |
| Performance degradation | Inefficient searches | Optimize SPL, adjust schedules |
| Missing dashboards | Incorrect paths | Verify views directory structure |
| Lookup failures | File permissions | Check lookup file permissions |

### Debug Commands

```bash
# Check app status
$SPLUNK_HOME/bin/splunk list app

# Validate configurations
$SPLUNK_HOME/bin/splunk btool check

# Review search logs
tail -f $SPLUNK_HOME/var/log/splunk/searches.log

# Test specific alert
$SPLUNK_HOME/bin/splunk search "| savedsearch \"SSH - Unauthorized Access Attempt\""
```

## Integration Guide

### SIEM Integration
- Splunk Enterprise Security (ES) compatible
- Common Information Model (CIM) compliant
- Supports SOAR playbook automation

### Threat Intelligence Feeds
- MISP integration ready
- STIX/TAXII support
- Custom IOC import scripts

### Notification Channels
- Email alerts with custom templates
- Slack/Teams webhook integration
- PagerDuty/ServiceNow incidents
- Custom script actions

## Performance Optimization

### Search Acceleration
```conf
# Add to savedsearches.conf
acceleration = true
acceleration.earliest_time = -7d
acceleration.max_concurrent = 2
```

### Resource Management
- Implement search scheduling windows
- Use summary indexing for historical analysis
- Leverage data model acceleration
- Configure search head pooling

## Security Compliance

This framework supports compliance monitoring for:
- PCI DSS (Payment Card Industry)
- HIPAA (Healthcare)
- SOC 2
- ISO 27001
- NIST Cybersecurity Framework
- CIS Controls

## Support and Resources

### Documentation
- Full documentation in `/docs` directory
- Security playbooks in `/security/playbooks`
- Architecture overview in `/docs/architecture-overview.md`

### Getting Help
- GitHub Issues: Report bugs and request features
- Wiki: Detailed configuration examples
- Community Forum: Share use cases and solutions

### Useful Links
- [Splunk Documentation](https://docs.splunk.com)
- [MITRE ATT&CK](https://attack.mitre.org)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)

## Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes following our coding standards
4. Add tests for new functionality
5. Submit a pull request with detailed description

## License

MIT License - See [LICENSE](LICENSE) file for details

## Acknowledgments

- Splunk Security Research Team
- MITRE ATT&CK Framework Contributors
- Open Source Threat Intelligence Community
- SOC Teams worldwide for feedback and improvements

---

**Version**: 2.0.0
**Last Updated**: 2025-01-18
**Maintained By**: Security Operations Team
**Repository**: https://github.com/Bissbert/splunk-security-alerts