# 🚀 Quick Start Guide - Get Running in 15 Minutes

Welcome! This guide will help you set up Splunk security monitoring quickly and easily.

## 📋 Before You Start (5 minutes)

### What You'll Need:
- ✅ **Splunk installed** (version 8.0 or newer)
- ✅ **Admin access** to your Splunk instance
- ✅ **Network access** to the systems you want to monitor
- ✅ **15 minutes** of your time

### What This Does:
This security monitoring system will alert you when:
- 🚨 Someone tries to access your servers from unauthorized locations
- 🔐 Suspicious activities happen on your systems
- 📊 Security incidents need your attention

---

## 🎯 Step 1: Download the Security App (2 minutes)

Open your terminal (Command Prompt on Windows, Terminal on Mac/Linux) and run:

```bash
# Download the security monitoring app
git clone https://github.com/Bissbert/splunk-security-alerts.git

# Go into the folder
cd splunk-security-alerts
```

**What just happened?** You downloaded all the security monitoring rules and dashboards.

**Trouble?** If git isn't installed, download the ZIP file from: https://github.com/Bissbert/splunk-security-alerts/archive/main.zip

---

## 🔧 Step 2: Install to Splunk (3 minutes)

Run this simple command:

```bash
# Install the app (you'll be asked for your Splunk admin password)
./deployment/deploy_secure.sh
```

The installer will:
- ✅ Copy files to the right places
- ✅ Set up your dashboards
- ✅ Configure the security alerts
- ✅ Restart Splunk to activate everything

**What to expect:** You'll see green checkmarks as each step completes.

---

## 🛡️ Step 3: Set Your Trusted IP Addresses (5 minutes)

This is **CRITICAL** - tell the system which IP addresses are allowed to access your servers:

1. **Open the trusted IPs file:**
   ```bash
   # Edit the file with your preferred editor
   nano security_alerts_app/lookups/authorized_ips.csv
   ```

2. **Add your office/home IP addresses:**
   ```csv
   ip,authorized,description
   10.0.0.0/8,true,Internal network
   192.168.1.0/24,true,Office network
   203.0.113.5,true,Admin home IP
   ```

3. **Save the file** (Ctrl+X, then Y, then Enter in nano)

**Why this matters:** Anyone connecting from IPs NOT in this list will trigger security alerts!

---

## ✅ Step 4: Verify Everything Works (3 minutes)

1. **Open Splunk in your browser:**
   ```
   http://your-splunk-server:8000
   ```

2. **Go to the Security Dashboard:**
   - Click "Apps" → "Security Alerts"
   - You should see the main security dashboard

3. **Run a test search** to make sure data is coming in:
   ```
   Click "Search & Reporting" and paste:

   index=* | head 10

   Click the green search button
   ```

   **You should see:** Recent log entries from your systems

---

## 🎉 Step 5: You're Protected! (2 minutes)

### What's Now Active:

| Alert | What It Catches | When You'll Be Notified |
|-------|-----------------|-------------------------|
| 🚨 **SSH Attacks** | Login attempts from unknown locations | Immediately |
| 👤 **New Admin Users** | Unexpected account creation | Within 5 minutes |
| 📤 **Data Theft** | Large data transfers outside | Within 15 minutes |
| 🔍 **Port Scans** | Someone scanning your network | Within 30 minutes |

### Your Security Status:
- **13 security alerts** actively monitoring
- **2 dashboards** for visualization
- **24/7 protection** enabled

---

## 📱 What to Do When You Get an Alert

When an alert fires, you'll see it in the Splunk interface. Here's what to do:

1. **Don't panic!** - Not all alerts are real attacks
2. **Click on the alert** to see details
3. **Check the source IP** - Is it from a known location?
4. **Follow the playbook** - Each alert has step-by-step instructions

Example alert:
```
⚠️ ALERT: SSH login attempt from 185.234.218.123 (Russia)
User: admin
Time: 2024-10-18 15:45:23
Status: Failed
Action Required: Check if this is authorized
```

---

## 🆘 Need Help?

### Common Issues and Quick Fixes:

**"I'm not seeing any data"**
- Check that your systems are sending logs to Splunk
- Run: `index=* earliest=-1h | stats count` - should be > 0

**"Too many false alerts"**
- Add more trusted IPs to the authorized_ips.csv file
- Adjust thresholds in Settings → Alert Configuration

**"Deployment script failed"**
- Make sure you have admin rights
- Try running with sudo: `sudo ./deployment/deploy_secure.sh`

### Get Support:
- 📧 Check our [Troubleshooting Guide](../99-reference/troubleshooting-simple.md)
- 💬 Visit [GitHub Issues](https://github.com/Bissbert/splunk-security-alerts/issues)
- 📚 Read the [full documentation](../01-for-beginners/understanding-alerts.md)

---

## 🎓 Next Steps - Level Up Your Security

Ready for more? Here's what to explore next:

1. **[Understanding Your Alerts](../01-for-beginners/understanding-alerts.md)** - Learn what each alert means
2. **[Daily Security Tasks](../02-daily-operations/morning-checklist.md)** - Build good security habits
3. **[Customize Your Alerts](../03-advanced-topics/custom-alerts.md)** - Tune for your environment

---

**🎉 Congratulations!** You now have enterprise-grade security monitoring protecting your systems. The hardest part is done - from here, it only gets easier!