# Alert Tuning Guide

## Overview

This guide provides instructions for tuning security alerts to reduce false positives and improve detection accuracy in your environment.

## General Tuning Principles

1. **Start Conservative**: Begin with higher thresholds and gradually reduce them
2. **Monitor False Positives**: Track and analyze false positive rates
3. **Environment-Specific**: Adjust based on your organization's normal behavior
4. **Regular Review**: Schedule monthly reviews of alert effectiveness
5. **Document Changes**: Keep a log of all tuning modifications

## Alert-Specific Tuning

### Unauthorized SSH Access

**Default Threshold**: Any successful SSH from non-whitelisted IP

**Tuning Parameters**:
- `authorized_ips.csv`: Update with all legitimate source IPs
- Time window: Adjust if legitimate users connect from dynamic IPs
- Geographic filtering: Add country-based filters if appropriate

**Common False Positives**:
- VPN IP changes
- Cloud provider IP ranges
- Third-party support access

**Recommended Actions**:
1. Review all SSH sources weekly
2. Maintain updated IP whitelist
3. Consider implementing jump hosts

### Failed Authentication Spike

**Default Threshold**: >10 failures in 5 minutes

**Tuning Parameters**:
```
| where failed_attempts > 10  # Adjust this value
```

**Environment Considerations**:
- Large environments: Increase to 20-30
- High-security zones: Decrease to 5
- Application servers: May need higher thresholds

### Data Exfiltration

**Default Threshold**: >100MB to external IPs in 10 minutes

**Tuning Parameters**:
```
| where total_mb > 100  # Adjust based on normal traffic
```

**Factors to Consider**:
- Backup operations
- Cloud storage usage
- Content delivery networks
- Video conferencing

### Privilege Escalation

**Default Threshold**: Any escalation from non-admin account

**Tuning Parameters**:
- Update `authorized_users.csv` with approved admin accounts
- Define approved service accounts
- Set time-based exceptions (maintenance windows)

### Lateral Movement

**Default Threshold**: >5 unique targets in 15 minutes

**Tuning Parameters**:
```
| where unique_targets > 5  # Adjust based on admin activity
```

**Consider**:
- System administrators' normal activity
- Automated management tools
- Monitoring systems

## Threshold Adjustment Matrix

| Environment Type | Failed Auth | Data Exfil | Lateral Movement | Port Scan |
|-----------------|-------------|------------|------------------|-----------|
| Small (<100 users) | 5 | 50MB | 3 | 10 |
| Medium (100-1000) | 10 | 100MB | 5 | 20 |
| Large (>1000) | 20 | 500MB | 10 | 50 |
| High Security | 3 | 25MB | 2 | 5 |

## Time Window Adjustments

### Peak Hours Modifications
```spl
| eval threshold_multiplier = case(
    date_hour >= 8 AND date_hour <= 17, 1.5,  # Business hours
    date_hour >= 0 AND date_hour <= 6, 0.5,   # Night hours
    1=1, 1.0  # Default
)
| eval adjusted_threshold = base_threshold * threshold_multiplier
```

### Weekend Adjustments
```spl
| eval is_weekend = if(date_wday=0 OR date_wday=6, 1, 0)
| eval threshold = if(is_weekend=1, weekend_threshold, weekday_threshold)
```

## Lookup Table Maintenance

### Weekly Updates Required

1. **authorized_ips.csv**
   - Add new office locations
   - Update VPN ranges
   - Remove decommissioned IPs

2. **authorized_users.csv**
   - Add new administrators
   - Remove terminated employees
   - Update role changes

3. **sensitive_hosts.csv**
   - Add new critical systems
   - Update asset values
   - Remove decommissioned servers

### Monthly Reviews

1. **malicious_ips.csv**
   - Import threat intelligence feeds
   - Remove outdated entries
   - Verify active threats

2. **critical_files.csv**
   - Add new configuration files
   - Update monitoring scope
   - Review file paths

## Performance Optimization

### Search Optimization

1. **Use specific indexes**:
```spl
index=security OR index=network  # Better than index=*
```

2. **Filter early**:
```spl
index=security EventCode=4625  # Filter at index time
| stats count by user  # Then aggregate
```

3. **Limit time ranges**:
```spl
earliest=-15m latest=now  # Minimize data scanned
```

### Resource Management

- Schedule non-critical alerts during off-peak hours
- Use summary indexing for historical analysis
- Implement alert throttling to prevent storms

## Testing Changes

### Before Production

1. **Clone the search**: Create a test version
2. **Run in Report mode**: Don't enable alerting initially
3. **Validate results**: Review for false positives
4. **Gradual rollout**: Start with warning severity

### Validation Checklist

- [ ] Run search for last 7 days
- [ ] Count false positives
- [ ] Verify true positives detected
- [ ] Check search performance
- [ ] Review with security team
- [ ] Document configuration changes

## Alert Suppression

### Preventing Alert Fatigue

```spl
alert.suppress = 1
alert.suppress.fields = src_ip,user,host
alert.suppress.period = 1h
```

### Throttling Configuration

- **Critical alerts**: No suppression
- **High alerts**: 30-minute suppression
- **Medium alerts**: 1-hour suppression
- **Low alerts**: 4-hour suppression

## Metrics and KPIs

### Track These Metrics

1. **False Positive Rate**: (False Positives / Total Alerts) × 100
2. **Mean Time to Detect**: Average time from event to alert
3. **Alert Volume**: Alerts per day by severity
4. **Coverage**: Percentage of MITRE ATT&CK techniques detected

### Monthly Report Template

```
Month: _______

Alert Statistics:
- Total Alerts: _____
- Critical: _____
- High: _____
- Medium: _____
- Low: _____

False Positive Analysis:
- FP Rate: _____%
- Top FP Alert: _______
- Action Taken: _______

Tuning Changes Made:
- Alert: _______
- Change: _______
- Result: _______

Recommendations:
1. _______
2. _______
3. _______
```

## Troubleshooting Common Issues

### High False Positive Rate

1. Review lookup tables for accuracy
2. Increase thresholds incrementally
3. Add more specific filters
4. Consider time-based exceptions

### Missed Detections

1. Decrease thresholds carefully
2. Expand search criteria
3. Add additional data sources
4. Review field extractions

### Performance Issues

1. Optimize search syntax
2. Reduce search frequency
3. Limit time range
4. Use acceleration/summary indexing

## Best Practices

1. **Document Everything**: Keep detailed change logs
2. **Test Incrementally**: Make one change at a time
3. **Communicate Changes**: Inform the team about modifications
4. **Regular Reviews**: Schedule monthly tuning sessions
5. **Learn from Incidents**: Update alerts based on real attacks
6. **Baseline Normal**: Understand your environment's patterns
7. **Collaborate**: Work with IT teams to understand legitimate activity