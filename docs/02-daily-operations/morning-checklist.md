# ☀️ Daily Security Monitoring Checklist

Start your day right with this simple checklist. Print it out or keep it handy!

---

## 🌅 Morning Startup (First 30 Minutes)

### ☕ First 5 Minutes - Quick Health Check
- [ ] **Check your email** - Any overnight emergencies?
- [ ] **Open Splunk dashboard** - System running normally?
- [ ] **Check CRITICAL alerts queue** - Anything need immediate action?
- [ ] **Review handover notes** - What did night shift leave for you?
- [ ] **Grab coffee** ☕ - You'll need it!

### 📊 Next 10 Minutes - Alert Review
Check each alert queue and note the counts:

| Priority | Normal Count | Today's Count | Action Needed? |
|----------|-------------|---------------|----------------|
| 🔴 CRITICAL | 0-1 | ___ | Yes/No |
| 🟠 HIGH | 2-5 | ___ | Yes/No |
| 🟡 MEDIUM | 10-20 | ___ | Yes/No |
| 🟢 LOW | 20-50 | ___ | Yes/No |

**Is today's count way higher than normal?**
- [ ] Yes → Possible incident in progress! Escalate!
- [ ] No → Continue with normal review

### 🔍 Next 15 Minutes - Deep Dive Critical/High Alerts

For each CRITICAL or HIGH alert, fill this out:

**Alert #1**
- **Alert Name:** _______________________
- **Time:** ___________
- **Affected System:** _______________________
- **Source IP:** _______________________
- **Quick Assessment:**
  - [ ] Definitely malicious
  - [ ] Probably false positive
  - [ ] Need more investigation
- **Action Taken:** _______________________

*(Copy for each alert)*

---

## 🏃 Hourly Checks (5 minutes each hour)

Set a reminder for every hour to:

### ⏰ Top of Each Hour
- [ ] **New CRITICAL alerts?** → Respond immediately
- [ ] **New HIGH alerts?** → Add to investigation queue
- [ ] **Systems still responsive?** → Check dashboard loads
- [ ] **Any user complaints?** → Check tickets/chat

### 📝 Quick Status Update
```
Hour: _____
Alerts Handled: _____
New Issues: _____
Status: Green / Yellow / Red
```

---

## 🍽️ Lunch Break Handover

Before you go to lunch:
- [ ] **Update ticket status** - Mark what you're working on
- [ ] **Note any ongoing investigations**
- [ ] **Set out-of-office if needed**
- [ ] **Tell colleague about any critical issues**

---

## 🌆 End of Day Wrap-Up (Last 30 Minutes)

### 📋 Investigation Status
Complete for each investigation:

| Ticket # | Issue | Status | Next Steps | Hand Over? |
|----------|-------|--------|------------|------------|
| | | ⬜ Resolved | | |
| | | ⬜ Ongoing | | |
| | | ⬜ Escalated | | |

### 🔄 Handover Preparation
- [ ] **Document all open investigations**
- [ ] **Flag any systems to watch**
- [ ] **Update team channel/wiki**
- [ ] **Send handover email if needed**

### 📊 Daily Statistics
Record for monthly reporting:
- Total Alerts Reviewed: _____
- Critical Incidents: _____
- False Positives: _____
- Actual Threats Stopped: _____

---

## 🚨 Emergency Response Quick Card

**If you see a CRITICAL alert:**

1. **DON'T PANIC** - Take a breath
2. **ASSESS** - Real threat or false positive?
3. **CONTAIN** - Stop it from spreading
4. **ESCALATE** - Tell your manager
5. **DOCUMENT** - Write down everything

### 🔥 Incident In Progress Checklist
- [ ] **Screenshot the alert**
- [ ] **Note the time**
- [ ] **Identify affected systems**
- [ ] **Begin containment actions**
- [ ] **Notify manager/senior analyst**
- [ ] **Start incident ticket**
- [ ] **Begin evidence collection**

---

## 📝 Daily Notes Template

Copy and use this template for your daily notes:

```markdown
## Security Monitoring Log - [DATE]

### Morning Review
- Start Time:
- Alert Queue Status: Normal / Elevated / Critical
- Overnight Issues: None / See below

### Investigations
1. [Time] - [Alert Type] - [System]
   - Status: Resolved/Ongoing
   - Finding: True Positive/False Positive
   - Action: [What you did]

### Issues for Follow-up
- [ ]
- [ ]

### End of Day
- Stop Time:
- Handover Items:
- Systems to Watch:

### Notes/Observations
[Any patterns, concerns, or suggestions]
```

---

## 💡 Daily Pro Tips

### Time Savers
- **Create browser bookmarks** for common Splunk searches
- **Use keyboard shortcuts** (Ctrl+Enter to run search)
- **Keep common commands handy** (IP blocks, password resets)
- **Template your responses** for common false positives

### Stay Organized
- **One investigation at a time** when possible
- **Use ticket numbers** in all documentation
- **Take screenshots** of important findings
- **Update status regularly** so team knows progress

### Stay Sharp
- **Take breaks** - Alert fatigue is real
- **Ask questions** - No shame in not knowing
- **Share findings** - Help the team learn
- **Celebrate wins** - You stopped an attack? Great job!

---

## 🎯 Weekly Goals Tracker

Track your improvement:

| Week | Mon | Tue | Wed | Thu | Fri | Goal |
|------|-----|-----|-----|-----|-----|------|
| Alerts Handled | | | | | | 100 |
| Avg Response Time | | | | | | <15min |
| False Positive % | | | | | | <30% |

---

## 🆘 Who to Call

Keep these contacts handy:

| Role | Name | Contact | When to Call |
|------|------|---------|--------------|
| Team Lead | _______ | _______ | Escalations |
| Senior Analyst | _______ | _______ | Technical help |
| Manager | _______ | _______ | Major incidents |
| IT Support | _______ | _______ | System issues |
| Legal | _______ | _______ | Data breaches |

---

## 📚 Quick Reference Links

Bookmark these:
- 🔍 [Splunk Main Dashboard](http://your-splunk:8000/security_dashboard)
- 📖 [Alert Meanings](../01-for-beginners/understanding-alerts.md)
- 🆘 [Troubleshooting Guide](../99-reference/troubleshooting-simple.md)
- 📝 [Incident Template](./incident-template.md)
- 🔐 [Password Reset Tool](http://your-tools/password-reset)
- 🚫 [IP Block Script](../scripts/block-ip.sh)

---

**Remember:** You're the first line of defense! Every alert you investigate properly could prevent a major breach. You've got this! 💪