# 🔧 Simple Troubleshooting Guide

Having problems? This guide helps you fix common issues quickly.

---

## 🚫 Problem: No Alerts Coming In

### Quick Checks (Try These First)
1. **Is Splunk running?**
   ```bash
   # Check if Splunk is running
   sudo systemctl status splunkd

   # You should see: "active (running)"
   # If not, start it:
   sudo systemctl start splunkd
   ```

2. **Are logs coming in?**
   - Go to Splunk web interface
   - Search: `index=* earliest=-15m | stats count`
   - **Should see:** Numbers > 0
   - **If 0:** Your systems aren't sending logs!

3. **Are alerts enabled?**
   - Go to Settings → Searches, Reports, and Alerts
   - Look for 🟢 green dots (enabled)
   - **If red:** Click to enable them

### Still Not Working?
**The system might not be sending logs. Check:**
- Is the server online? Can you ping it?
- Is the log forwarding service running?
- Did someone change firewall rules?

---

## 😫 Problem: Too Many False Alerts

### Quick Fix Options

1. **For "Unauthorized SSH" alerts:**
   ```bash
   # Add trusted IP to whitelist
   # Edit this file:
   nano security_alerts_app/lookups/authorized_ips.csv

   # Add a line like:
   203.0.113.5,true,Bob working from home
   ```

2. **For "Failed Login" alerts:**
   ```
   Change the threshold from 10 to 20 attempts:

   1. Go to Settings → Searches, Reports, and Alerts
   2. Find "failed_auth_spike_detection"
   3. Edit → Change "where count > 10" to "where count > 20"
   4. Save
   ```

3. **For "Large Transfer" alerts:**
   - Identify your backup servers
   - Add them to the whitelist
   - Or schedule alerts to skip backup windows (2-4 AM)

### Pro Tip: Track False Positives
Keep a list:
```
Alert: unauthorized_ssh
Reason: VPN IP range not whitelisted
Fix: Added 10.8.0.0/24 to authorized_ips.csv
Date: [Today]
```

---

## 🐌 Problem: Splunk Is Really Slow

### Speed It Up

1. **Too much data?**
   ```bash
   # Check disk space
   df -h

   # Should have at least 20% free
   # If full, delete old data:
   /opt/splunk/bin/splunk clean eventdata -index main -oldest-time 30d
   ```

2. **Searches taking forever?**
   - Use specific time ranges (not "All Time")
   - Search specific indexes: `index=security` not `index=*`
   - Limit results: Add `| head 1000` to searches

3. **Dashboard slow to load?**
   - Reduce time range: Last 4 hours instead of 24
   - Remove real-time searches (they're resource heavy)
   - Schedule searches to run in background

### Quick Performance Check
```bash
# Check system resources
top
# Look for CPU% and MEM%
# Splunk shouldn't use more than 70% consistently
```

---

## ❌ Problem: Can't Login to Splunk

### Reset Your Password

1. **If you're admin:**
   ```bash
   # Reset admin password
   /opt/splunk/bin/splunk edit user admin -password newpassword123! -auth admin:currentpassword
   ```

2. **If you forgot admin password:**
   ```bash
   # Stop Splunk
   sudo systemctl stop splunkd

   # Reset to default
   echo "admin:changeme" > /opt/splunk/etc/passwd

   # Start Splunk
   sudo systemctl start splunkd

   # Login with admin/changeme then CHANGE IT!
   ```

3. **Account locked out?**
   - Wait 5 minutes (auto-unlock)
   - Or ask another admin to unlock

---

## 🔍 Problem: Alert Fired But Can't Find the Event

### Finding the Source Event

1. **Check the alert details:**
   - Click on the alert in the dashboard
   - Look for "View results" or "View events"
   - Note the time range

2. **Search manually:**
   ```spl
   # Basic search template
   index=[index_name] earliest="10/18/2024:14:00:00" latest="10/18/2024:15:00:00"
   | search [keywords from alert]
   ```

3. **Common reasons you can't find it:**
   - Looking in wrong time range (check timezone!)
   - Event was in different index
   - Data delay (event came in late)
   - Someone already deleted/cleaned it up

### Pro Search Tips
```spl
# Find SSH events
index=security OR index=linux_secure "sshd"

# Find failed logins
index=* "failed" OR "denied" OR "invalid user"

# Find large transfers
index=network bytes_out>104857600
```

---

## 📡 Problem: Specific System Not Sending Logs

### Diagnose the Issue

1. **Check if system is online:**
   ```bash
   # Can you reach it?
   ping system-name

   # Can you SSH to it?
   ssh system-name
   ```

2. **Check log forwarding on that system:**
   ```bash
   # For Linux systems with rsyslog
   systemctl status rsyslog

   # Check config points to Splunk
   grep "*.* @@splunk-server" /etc/rsyslog.conf
   ```

3. **Test sending a log:**
   ```bash
   # Send test message
   logger "TEST: Alert test from $(hostname) at $(date)"

   # Check if it arrived in Splunk
   # Search: index=* "TEST: Alert test"
   ```

### Common Fixes
- Restart log service: `systemctl restart rsyslog`
- Check firewall: Port 514 (syslog) or 9997 (Splunk) open?
- Disk full on source system? Check with `df -h`

---

## 🎯 Problem: Don't Understand What an Alert Means

### Quick Reference for Alert Fields

| Field | What It Means | Example |
|-------|---------------|---------|
| src_ip | Where attack came from | 185.234.218.123 |
| dest_ip | System being attacked | 10.0.0.5 |
| user | Account involved | admin, root, bob |
| action | What happened | blocked, allowed, failed |
| count | How many times | 47 |
| bytes_out | Data size transferred | 1048576 (1MB) |

### Understanding Time Stamps
```
_time = 2024-10-18 15:30:45
Means: October 18, 2024 at 3:30:45 PM

earliest = -15m@m
Means: 15 minutes ago, rounded to the minute

latest = now
Means: Right now
```

---

## 🆘 Problem: Major Incident - Everything Is on Fire!

### DON'T PANIC - Follow These Steps

1. **BREATHE** - Take 3 deep breaths

2. **ASSESS** - What's actually broken?
   - [ ] Can users still work?
   - [ ] Is data being stolen RIGHT NOW?
   - [ ] Are systems being destroyed?

3. **CONTAIN** - Stop the damage
   ```bash
   # Emergency network isolation
   # Block all external traffic (nuclear option!)
   iptables -I INPUT -i eth0 -j DROP
   iptables -I OUTPUT -o eth0 -j DROP
   ```

4. **ESCALATE** - Get help
   - Call team lead: [Phone]
   - Call manager: [Phone]
   - Page on-call: [Pager]

5. **DOCUMENT** - Write down everything
   - Time you noticed
   - What you saw
   - What you did
   - Who you called

---

## 💡 General Troubleshooting Tips

### The Golden Rules
1. **Check the obvious first** - Is it plugged in? Is it turned on?
2. **Read the error message** - It often tells you exactly what's wrong
3. **Google the error** - Someone else had this problem before
4. **Check what changed** - Updates? New configs? Maintenance?
5. **Ask for help** - No shame in not knowing something

### Useful Commands Cheat Sheet
```bash
# Check if service is running
systemctl status [service-name]

# Check network connectivity
ping [ip-address]
telnet [ip-address] [port]

# Check disk space
df -h

# Check system resources
top
htop

# Check recent logs
tail -f /var/log/syslog
journalctl -f

# Find files
find / -name "filename" 2>/dev/null

# Check who's logged in
who
w
last
```

---

## 📝 When All Else Fails

### Information to Gather for Support

When asking for help, provide:
1. **What you're trying to do**
2. **Exact error message** (screenshot!)
3. **What you already tried**
4. **When it last worked**
5. **What changed recently**

### Support Contacts
- Splunk Support: support@splunk.com
- GitHub Issues: https://github.com/Bissbert/splunk-security-alerts/issues
- Team Chat: [Your team channel]
- Knowledge Base: [Your wiki]

---

## 🎓 Prevention - Stop Problems Before They Start

### Daily Health Checks
- [ ] Check disk space > 20% free
- [ ] Verify all systems sending logs
- [ ] Review any error messages in Splunk
- [ ] Test one alert to ensure they fire

### Weekly Maintenance
- [ ] Review and tune false positives
- [ ] Update IP whitelists
- [ ] Check for Splunk updates
- [ ] Clean up old data if needed

### Monthly Tasks
- [ ] Review all alert thresholds
- [ ] Update documentation
- [ ] Test incident response procedures
- [ ] Train on new features

---

**Remember:** Every problem has a solution. Stay calm, be methodical, and don't be afraid to ask for help! 🚀