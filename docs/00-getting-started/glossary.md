# 📚 Security Terms Glossary

This glossary explains technical terms in simple language. Terms are grouped by category for easy reference.

---

## 🔍 Security Monitoring Terms

### Alert
**What it means:** A notification that something suspicious happened
**Example:** "Alert: Someone tried to login from Russia"
**In real life:** Like a smoke alarm going off - needs investigation

### False Positive
**What it means:** An alert that fires but isn't actually a problem
**Example:** Alert says "attack" but it's just the CEO working from home
**In real life:** Like a car alarm triggered by thunder

### IOC (Indicator of Compromise)
**What it means:** Evidence that a security incident occurred
**Example:** Strange files in system folders, unusual network connections
**In real life:** Like finding a broken window or muddy footprints

### SOC (Security Operations Center)
**What it means:** The team that monitors and responds to security alerts
**Example:** The people watching security dashboards 24/7
**In real life:** Like a building's security office with camera monitors

### SIEM (Security Information and Event Management)
**What it means:** Software that collects and analyzes security logs
**Example:** Splunk, QRadar, ArcSight
**In real life:** Like a super-smart security camera system that notices patterns

---

## 🔐 Attack Terms

### Brute Force
**What it means:** Trying many passwords until one works
**Example:** Trying "password1", "password2", "password3"...
**In real life:** Like trying every key on a keyring

### C2/C&C (Command and Control)
**What it means:** How hackers remotely control compromised systems
**Example:** Malware calling home for instructions
**In real life:** Like a puppet master pulling strings

### Data Exfiltration
**What it means:** Stealing and sending out data
**Example:** Copying customer database and uploading to external server
**In real life:** Like a thief loading stolen goods into a truck

### Lateral Movement
**What it means:** Moving from one compromised system to another
**Example:** Hacking the receptionist PC, then jumping to accounting
**In real life:** Like a burglar moving from room to room

### Persistence
**What it means:** Ensuring continued access even after reboot
**Example:** Installing backdoor that starts automatically
**In real life:** Like making a copy of the house key

### Privilege Escalation
**What it means:** Getting higher-level access than you should have
**Example:** Regular user becoming admin
**In real life:** Like a visitor getting the master key

---

## 🖥️ Network & System Terms

### IP Address
**What it means:** A computer's address on the network
**Example:** 192.168.1.100 or 10.0.0.5
**In real life:** Like a house street address

### Port
**What it means:** A numbered endpoint for network connections
**Example:** Port 22 (SSH), Port 80 (Web), Port 443 (Secure Web)
**In real life:** Like different doors into a building

### SSH (Secure Shell)
**What it means:** Secure way to remotely control Linux/Unix systems
**Example:** IT admin connecting to server to run commands
**In real life:** Like remote controlling a computer securely

### Subnet/CIDR
**What it means:** A range of IP addresses
**Example:** 10.0.0.0/24 means IPs from 10.0.0.1 to 10.0.0.254
**In real life:** Like "all houses on this street"

### Firewall
**What it means:** Software/hardware that blocks unwanted network traffic
**Example:** Blocking all connections from China if you don't do business there
**In real life:** Like a bouncer at a club checking IDs

---

## 📊 Splunk-Specific Terms

### Index
**What it means:** Where Splunk stores different types of data
**Example:** index=security, index=network
**In real life:** Like different filing cabinets for different documents

### SPL (Search Processing Language)
**What it means:** The language used to search in Splunk
**Example:** `index=security "failed login" | stats count by user`
**In real life:** Like Google search but for logs

### Dashboard
**What it means:** Visual display of important security metrics
**Example:** Charts showing attack attempts, top threats
**In real life:** Like a car's dashboard showing speed, fuel, etc.

### Lookup Table
**What it means:** List of reference data Splunk uses
**Example:** List of known bad IP addresses
**In real life:** Like a phone book or contact list

### Search Head
**What it means:** Splunk server where you run searches
**Example:** The Splunk web interface you log into
**In real life:** Like the computer terminal you work at

---

## 🛡️ Security Concepts

### Authentication
**What it means:** Proving you are who you say you are
**Example:** Entering username and password
**In real life:** Like showing your ID card

### Authorization
**What it means:** What you're allowed to do after logging in
**Example:** Admin can delete files, regular user cannot
**In real life:** Like having keys to certain rooms but not others

### Encryption
**What it means:** Scrambling data so only authorized people can read it
**Example:** HTTPS websites, encrypted hard drives
**In real life:** Like writing in a secret code

### Hash
**What it means:** A fingerprint of a file or password
**Example:** MD5: 5d41402abc4b2a76b9719d911017c592
**In real life:** Like a tamper-evident seal

### Whitelist/Allowlist
**What it means:** List of approved items
**Example:** IP addresses allowed to connect
**In real life:** Like a guest list at an event

### Blacklist/Blocklist
**What it means:** List of banned items
**Example:** Known malicious IP addresses
**In real life:** Like a "do not serve" list at a store

---

## 🚨 Incident Response Terms

### Containment
**What it means:** Stopping an attack from spreading
**Example:** Disconnecting infected computer from network
**In real life:** Like quarantining a sick patient

### Eradication
**What it means:** Completely removing the threat
**Example:** Deleting malware, closing backdoors
**In real life:** Like exterminating pests from a building

### Forensics
**What it means:** Investigating to understand what happened
**Example:** Analyzing logs to find how hacker got in
**In real life:** Like CSI investigating a crime scene

### Incident
**What it means:** A security event that needs response
**Example:** Successful hack, data breach, malware infection
**In real life:** Like a break-in or theft

### Playbook
**What it means:** Step-by-step instructions for handling incidents
**Example:** "What to do when SSH attack detected"
**In real life:** Like emergency evacuation procedures

---

## 🔧 Linux/Unix Terms

### Cron/Crontab
**What it means:** Scheduled tasks in Linux
**Example:** Backup script running every night at 2 AM
**In real life:** Like setting your coffee maker timer

### Root
**What it means:** The super-administrator account in Linux
**Example:** Can do anything on the system
**In real life:** Like having the master key to everything

### Sudo
**What it means:** Running a command with administrator privileges
**Example:** `sudo apt install software`
**In real life:** Like asking the manager to override something

### Systemd
**What it means:** System that manages services in modern Linux
**Example:** Starting web server when system boots
**In real life:** Like the startup routine for your computer

### SUID
**What it means:** Files that run with owner's permissions
**Example:** passwd command needs root access to change passwords
**In real life:** Like a valet key that only starts the car

---

## 📈 Metrics & Monitoring Terms

### Baseline
**What it means:** Normal behavior pattern
**Example:** Usually 100 logins per hour during business hours
**In real life:** Like knowing your normal body temperature

### Threshold
**What it means:** Limit that triggers an alert when crossed
**Example:** Alert if more than 10 failed logins in 5 minutes
**In real life:** Like a speed limit

### Correlation
**What it means:** Connecting related events
**Example:** Failed login + new user created + data download = attack
**In real life:** Like connecting puzzle pieces

### Anomaly
**What it means:** Something unusual compared to normal
**Example:** Login at 3 AM when user never works nights
**In real life:** Like your cat suddenly acting strange

---

## 🌐 Compliance Terms

### GDPR
**What it means:** European privacy law
**Example:** Must protect EU citizen data, report breaches in 72 hours
**In real life:** Like consumer protection laws

### PCI-DSS
**What it means:** Credit card security standards
**Example:** Must encrypt cardholder data, have firewall
**In real life:** Like safety standards for handling money

### NIST
**What it means:** US government security framework
**Example:** Guidelines for cybersecurity best practices
**In real life:** Like building codes for security

---

## 📝 Quick Reference

**Most Important Terms for Beginners:**
1. **Alert** - Something suspicious happened
2. **SOC** - Your security team
3. **IP Address** - Computer's network address
4. **SSH** - Remote access to servers
5. **Dashboard** - Visual security display
6. **Incident** - Security event needing response
7. **False Positive** - Alert that's not real threat
8. **Whitelist** - Approved list
9. **Threshold** - Alert trigger limit
10. **Playbook** - Response instructions

---

**Need a term explained that's not here?**
Check the [Advanced Glossary](../99-reference/advanced-glossary.md) or ask your team lead!