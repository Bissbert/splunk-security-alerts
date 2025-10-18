# 🚨 Understanding Your Security Alerts

This guide explains each security alert in simple terms - what it means, why it matters, and what to do about it.

---

## 📊 Alert Severity Levels

Think of alert severity like weather warnings:

| Level | Icon | Response Time | What It Means | Real-World Example |
|-------|------|---------------|---------------|-------------------|
| **CRITICAL** | 🔴 | Immediately | Major attack happening NOW | Fire in the building |
| **HIGH** | 🟠 | Within 1 hour | Serious issue developing | Smoke detected |
| **MEDIUM** | 🟡 | Within 4 hours | Suspicious activity | Door left unlocked |
| **LOW** | 🟢 | Next day | Worth investigating | Strange noise heard |

---

## 🔴 CRITICAL Alerts - Drop Everything!

### 1. Unauthorized SSH Access
**Plain English:** Someone logged into your server from an unknown location

**What you'll see:**
```
ALERT: SSH login from 185.234.218.123 (Russia)
Server: web-server-01
User: admin
Status: SUCCESS
```

**Why it's critical:** If someone has SSH access, they can:
- Delete all your data
- Install malware
- Steal sensitive information
- Use your server to attack others

**What to do RIGHT NOW:**
1. **Block the IP address** (the script will show you how)
2. **Check what they did:** Look at their command history
3. **Change passwords** for the compromised account
4. **Check other servers** - they might have spread

**Is it a false positive?**
Check if:
- ✅ It's your CEO traveling abroad
- ✅ It's a developer working from home
- ✅ It's a scheduled maintenance window

---

### 2. Data Being Stolen (Exfiltration)
**Plain English:** Large amounts of data are being sent outside your network

**What you'll see:**
```
ALERT: Large data transfer detected
Source: database-server
Destination: 45.32.108.44 (Unknown)
Size: 2.3 GB
Files: customer_database.sql
```

**Why it's critical:** Your data might be:
- Customer information being stolen
- Trade secrets being copied
- Passwords being harvested
- Compliance violation (GDPR fines!)

**What to do RIGHT NOW:**
1. **Kill the connection** - Stop the transfer immediately
2. **Identify what was taken** - Check transfer logs
3. **Check the source** - Is it a legitimate backup?
4. **Legal requirements** - You may need to report this within 72 hours

---

## 🟠 HIGH Priority Alerts - Respond Quickly

### 3. New Admin Account Created
**Plain English:** Someone created a new administrator account

**What you'll see:**
```
ALERT: New administrator account
Account Name: backdoor_admin
Created By: www-data (suspicious!)
Time: 02:34 AM
```

**Why it's serious:**
- Attackers create accounts to maintain access
- Could be an insider threat
- Might indicate system compromise

**Quick Check Questions:**
1. Did IT create this account? (Check your ticket system)
2. Is this during a maintenance window?
3. Who is www-data and why can they create admins?

**What to do:**
1. **Disable the account** immediately
2. **Call the supposed creator** - verify it was them
3. **Check account permissions** - what can it access?
4. **Review audit logs** - what else happened around this time?

---

### 4. Someone Scanning Your Network
**Plain English:** Someone is checking which services you're running (like a burglar checking doors and windows)

**What you'll see:**
```
ALERT: Port scan detected
Source: 10.0.0.157 (internal!)
Targets: Multiple servers
Ports Scanned: 1-65535 (full scan)
```

**Why it matters:**
- Preparation for an attack
- Could be malware looking for targets
- Might be compromised internal system

**Is it legitimate?**
- ✅ Scheduled vulnerability scan
- ✅ IT team troubleshooting
- ❌ Random workstation scanning servers

---

## 🟡 MEDIUM Priority Alerts - Investigate Soon

### 5. Multiple Failed Logins
**Plain English:** Someone is trying many passwords (like trying many keys in a lock)

**What you'll see:**
```
ALERT: Brute force attempt
Target Account: admin
Failed Attempts: 47
Time Window: 5 minutes
Source IPs: Multiple (botnet?)
```

**What to check:**
1. **Is the account locked?** (It should be after 5 attempts)
2. **Are they trying common passwords?** (password123, admin, etc.)
3. **Multiple IPs or just one?** (Botnet vs single attacker)

**Quick Response:**
- Block the source IPs
- Ensure account lockout is working
- Check if any attempts succeeded
- Consider requiring MFA

---

## 📋 Alert Decision Tree

Here's a simple flowchart for any alert:

```
Alert Fires
    ↓
Is it CRITICAL? → YES → Stop what you're doing, respond now
    ↓ NO
Is it HIGH? → YES → Respond within 1 hour
    ↓ NO
Is it MEDIUM? → YES → Add to today's investigation list
    ↓ NO
LOW → Check tomorrow or assign to junior analyst
```

---

## 🎯 Real Examples - What Does Normal Look Like?

### Normal Activity (Don't Worry)
- ✅ Failed login followed by successful (someone mistyped password)
- ✅ Large data transfer to your backup server at 2 AM
- ✅ Port scan from your vulnerability scanner (10.0.0.50)
- ✅ New account created with approved ticket number

### Suspicious Activity (Investigate)
- ⚠️ Failed logins from 20 different countries
- ⚠️ Data transfer to Dropbox at 3 AM
- ⚠️ Port scan from Bob's workstation
- ⚠️ New account with name "test" or "temp"

### Definite Attack (Respond Immediately)
- 🚨 Successful login from North Korea
- 🚨 Database dump to residential IP address
- 🚨 Port scan followed by exploitation attempts
- 🚨 Account created named "backdoor" or with $$ in name

---

## 📱 Your Daily Alert Routine

### Morning (First Thing)
1. **Check CRITICAL alerts** first - any overnight emergencies?
2. **Review HIGH alerts** - anything need immediate attention?
3. **Count total alerts** - normal volume or spike?

### Throughout the Day
- **Respond to CRITICAL** within 15 minutes
- **Investigate HIGH** within the hour
- **Queue MEDIUM** for investigation
- **Batch process LOW** when time permits

### Before Leaving
- **Hand over** any active investigations
- **Document** what you found today
- **Set up** monitoring for ongoing issues

---

## 💡 Pro Tips for New Analysts

### Reducing False Positives
1. **Learn your environment**
   - What's normal for YOUR network?
   - When does maintenance happen?
   - Who works late/weekends?

2. **Update the whitelists**
   - Add your office IPs
   - Include work-from-home IPs
   - Add partner companies

3. **Tune the thresholds**
   - Start high, lower gradually
   - Document why you changed them
   - Review monthly

### Investigation Shortcuts
- **Always check:** Who, What, When, Where, Why
- **Look for patterns:** Same time? Same user? Same target?
- **Check multiple sources:** Don't trust single log entries
- **Document everything:** Future you will thank you

---

## 🆘 When to Escalate

Escalate to senior analyst or manager when:

1. **You see confirmed compromise**
   - Actual malware running
   - Data confirmed stolen
   - Admin account compromised

2. **You're not sure**
   - Better safe than sorry
   - Two brains better than one
   - Learning opportunity

3. **Legal/Compliance issues**
   - Customer data involved
   - Regulatory requirements
   - Potential breach notification

4. **It's spreading**
   - Multiple systems affected
   - Lateral movement detected
   - Can't contain alone

---

## 📚 Learning Resources

### Practice Scenarios
Try these in your test environment:
1. Generate failed SSH logins - see the alert
2. Create large file transfer - watch detection
3. Run a port scan - observe response

### Further Reading
- [Handling Your First Incident](./your-first-incident.md)
- [Daily SOC Operations](../02-daily-operations/morning-checklist.md)
- [Alert Tuning Guide](../03-advanced-topics/tuning-alerts.md)

### Remember
- 🎯 Not every alert is an attack
- 📚 Learn what's normal for YOUR environment
- 🤝 Ask questions - everyone was new once
- 📝 Document your investigations
- 💪 You'll get faster with practice

---

**Questions?** Check the [Glossary](../00-getting-started/glossary.md) or ask your team lead. You've got this! 🚀