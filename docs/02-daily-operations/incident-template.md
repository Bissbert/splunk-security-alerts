# 🚨 Incident Response Template

**Copy this template when handling any security incident**

---

## 📋 Incident Quick Info

| Field | Details |
|-------|---------|
| **Incident ID:** | INC-2024-_____ |
| **Date/Time Detected:** | _____ |
| **Severity:** | 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW |
| **Analyst Name:** | _____ |
| **Status:** | 🔄 Active / ⏸️ Contained / ✅ Resolved |

---

## 🎯 Initial Assessment (First 5 Minutes)

### What Happened?
**Alert that fired:** _____
**In simple words:** _____
(Example: "Someone tried to login from Russia")

### Is This Real or False Positive?
- [ ] **Real threat** - Take immediate action!
- [ ] **False positive** - Document why and close
- [ ] **Unsure** - Escalate to senior analyst

### Quick Impact Check
- **Systems affected:** _____
- **Data at risk:** _____
- **Users impacted:** _____
- **Business services down?** Yes / No

---

## 🔍 Investigation Steps (Next 15 Minutes)

### 1. What Do We Know?
- **Source IP address:** _____
  - [ ] Check reputation (is it malicious?)
  - [ ] Geolocate (where is it from?)
  - [ ] Internal or external?

- **Target system:** _____
  - [ ] What does this system do?
  - [ ] What data does it hold?
  - [ ] Who normally accesses it?

- **User account involved:** _____
  - [ ] Legitimate user?
  - [ ] Account compromised?
  - [ ] Privileged account?

### 2. Timeline of Events
```
[Time] - First suspicious activity
[Time] - Alert triggered
[Time] - Investigation started
[Time] - [Add events as you find them]
```

### 3. Evidence Collected
- [ ] Screenshots taken
- [ ] Logs exported
- [ ] Network captures saved
- [ ] File samples collected

**Evidence Location:** _____ (folder path or ticket number)

---

## 🛡️ Containment Actions (If Real Threat)

### Immediate Actions Taken
- [ ] **Block source IP**
  ```bash
  # Command used:
  ```
- [ ] **Disable user account**
  ```bash
  # Command used:
  ```
- [ ] **Isolate affected system**
  ```bash
  # Command used:
  ```
- [ ] **Reset passwords**
- [ ] **Revoke sessions/tokens**

### Results
- **Threat contained?** Yes / No / Partially
- **Attack stopped?** Yes / No / Unknown
- **Spread prevented?** Yes / No / Unknown

---

## 📞 Communication

### Who Was Notified?
- [ ] Team lead - Time: _____
- [ ] Manager - Time: _____
- [ ] System owner - Time: _____
- [ ] Users affected - Time: _____
- [ ] Legal/Compliance (if needed) - Time: _____

### Status Updates Sent
- [ ] Initial notification
- [ ] Hourly updates
- [ ] Resolution notice
- [ ] Post-incident report

---

## 🔧 Recovery Actions

### Steps to Return to Normal
1. [ ] Verify threat eliminated
2. [ ] Restore from clean backup (if needed)
3. [ ] Re-enable accounts/access
4. [ ] Remove IP blocks (if false positive)
5. [ ] Monitor for recurrence

### Validation
- [ ] Systems functioning normally
- [ ] Users can access resources
- [ ] No signs of persistent threat
- [ ] Monitoring enhanced for this issue

---

## 📝 Resolution Summary

### What Was It?
- [ ] **Real attack** - Successfully stopped
- [ ] **Real attack** - Partially successful (damage done)
- [ ] **False positive** - Normal activity misidentified
- [ ] **Authorized test** - Pen test or security scan

### Root Cause
**Why did this happen?**
_____

**How did they get in? (if applicable)**
_____

### Damage Assessment
- **Data stolen?** Yes / No / Unknown
  - If yes, what: _____
- **Systems compromised?** Yes / No / Unknown
  - If yes, which: _____
- **Credentials exposed?** Yes / No / Unknown
  - If yes, which: _____

---

## 💡 Lessons Learned

### What Went Well?
1. _____
2. _____

### What Could Be Better?
1. _____
2. _____

### Action Items to Prevent Recurrence
- [ ] _____
- [ ] _____
- [ ] _____

### Documentation Updates Needed
- [ ] Update playbook for this scenario
- [ ] Add to known false positives
- [ ] Tune alert threshold
- [ ] Update whitelist/blacklist

---

## 📊 Metrics for Reporting

| Metric | Value |
|--------|-------|
| Time to Detect | _____ minutes |
| Time to Respond | _____ minutes |
| Time to Contain | _____ minutes |
| Time to Resolve | _____ minutes |
| Total Downtime | _____ minutes |
| Users Affected | _____ |
| Systems Affected | _____ |

---

## 🏁 Closure Checklist

Before closing this incident:
- [ ] All immediate threats addressed
- [ ] Systems returned to normal
- [ ] Evidence properly preserved
- [ ] Stakeholders notified of resolution
- [ ] Documentation complete
- [ ] Ticket updated and closed
- [ ] Lessons learned documented
- [ ] Follow-up actions assigned

### Final Status
- **Incident Closed:** Date/Time: _____
- **Closed By:** _____
- **Approval:** Manager signature/approval: _____

---

## 📎 Attachments and References

List any related documents:
- Ticket #: _____
- Screenshot location: _____
- Log archive: _____
- Related incidents: _____
- Vendor case #: _____

---

## 🗒️ Additional Notes

_[Space for any additional observations, concerns, or recommendations]_

---

**Remember:**
- Be thorough but don't delay critical actions
- When in doubt, escalate
- Document everything as you go
- Learn from every incident

---

*Template Version: 1.0 | Last Updated: [Current Date]*