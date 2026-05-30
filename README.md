# 🛡️ SIEM Threat Detection Lab Using Splunk & Atomic Red Team

> **Author:** Mounik Biswas  
> **Domain:** Blue Team | Detection Engineering | SOC Operations

---

## 📌 Project Overview

This project simulates a small-scale **Security Operations Centre (SOC)** environment built to practice real-world threat detection using **Splunk** as a SIEM platform. A **Windows 10 virtual machine** was configured as the victim machine to generate event logs and simulate adversary behavior using **Atomic Red Team**, while an **Ubuntu Server VM** hosted **Splunk Enterprise** to ingest and analyze the data.

The project emphasizes detection of key attack techniques aligned with the **MITRE ATT&CK framework**, including suspicious PowerShell execution, brute-force login attempts, and registry-based persistence. Multiple Splunk dashboards, alerts, reports, and correlation rules were developed to monitor these activities in real-time.

---

## 🧰 Tools & Technologies

| Tool | Role |
|------|------|
| **Splunk Enterprise** | SIEM — log ingestion, search, dashboards & alerts |
| **Splunk Universal Forwarder** | Log forwarding from Windows VM to Splunk |
| **Sysmon (SwiftOnSecurity config)** | Deep Windows telemetry collection |
| **Atomic Red Team** | Safe adversary technique simulation (MITRE-mapped) |
| **Windows 10 VM** | Victim / attack simulation machine |
| **Ubuntu Server 22.04 VM** | SIEM server hosting Splunk Enterprise |
| **VirtualBox** | Hypervisor for VM management |

---

## 🏗️ Lab Architecture

```
┌──────────────────────────────┐        ┌──────────────────────────────┐
│      Windows 10 VM           │        │     Ubuntu Server 22.04 VM   │
│    (Victim Machine)          │        │       (SIEM Server)          │
│                              │        │                              │
│  ┌─────────────────────┐     │        │   ┌──────────────────────┐   │
│  │  Atomic Red Team    │     │  Logs  │   │  Splunk Enterprise   │   │
│  │ (Attack Simulation) │     │ ──────►│   │  (Ingest, Search,    │   │
│  └─────────────────────┘     │        │   │   Dashboard, Alerts) │   │
│  ┌─────────────────────┐     │        │   └──────────────────────┘   │
│  │       Sysmon        │     │        │                              │
│  │ (Deep Telemetry)    │     │        └──────────────────────────────┘
│  └─────────────────────┘     │
│  ┌─────────────────────┐     │
│  │ Universal Forwarder │     │
│  │  (Log Forwarding)   │     │
│  └─────────────────────┘     │
└──────────────────────────────┘
        VirtualBox (Host)
```

---

## 🧠 MITRE ATT&CK Techniques Detected

| Use Case | Technique ID | Technique Name |
|---|---|---|
| Suspicious PowerShell Execution | T1059.001 | Command & Scripting Interpreter: PowerShell |
| Brute Force Login Attempts | T1110.001 | Brute Force: Password Guessing |
| Registry Key Persistence | T1547.001 | Boot/Logon Autostart Execution: Registry Keys |
| Brute Force → Successful Login | T1110 + T1078 | Valid Accounts Used After Brute Force |
| PowerShell → Registry Persistence | T1059.001 + T1547.001 | Multi-Stage Persistence with Scripting |

---

## 📊 Splunk Features Implemented

- ✅ **Real-time dashboards** with visual detection panels
- ✅ **Alerts** triggered by SPL-based detection logic
- ✅ **Correlation rules** for multi-stage attack chain detection
- ✅ **Saved reports** for threat hunting and audit use cases
- ✅ **Advanced SPL queries** for anomaly detection

---

## 🚀 Lab Setup & Execution Guide

### 1. Set Up Virtual Machines
- Create two VMs in **VirtualBox**:
  - `Windows 10` — Victim machine
  - `Ubuntu Server 22.04` — SIEM server
- Configure both VMs on a **Host-Only** or **NAT Network** adapter so they can communicate

### 2. Install Splunk Enterprise (Ubuntu Server)
```bash
wget -O splunk.deb "https://download.splunk.com/..."
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
```
- Access the Splunk Web UI at `http://<ubuntu-ip>:8000`

### 3. Install Sysmon on Windows 10 VM
```powershell
# Download Sysmon and SwiftOnSecurity config
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### 4. Install & Configure Splunk Universal Forwarder (Windows VM)
```powershell
# After installation, configure outputs.conf to point to Splunk server
[tcpout]
defaultGroup = splunk-server

[tcpout:splunk-server]
server = <ubuntu-ip>:9997
```
- Add `inputs.conf` to forward Windows Event Logs and Sysmon logs

### 5. Verify Log Ingestion in Splunk
```spl
index=* sourcetype=WinEventLog | head 10
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | head 10
```

### 6. Simulate Attacks with Atomic Red Team (Windows VM)
```powershell
# Install Atomic Red Team
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam

# Simulate Brute Force (T1110.001)
Invoke-AtomicTest T1110.001

# Simulate PowerShell Execution (T1059.001)
Invoke-AtomicTest T1059.001

# Simulate Registry Persistence (T1547.001)
Invoke-AtomicTest T1547.001
```

### 7. Detect & Visualize in Splunk
Run SPL queries, build dashboards, and configure alerts (see Detection Queries section below).

---

## 🔍 Sample SPL Detection Queries

### Suspicious PowerShell Execution
```spl
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=1 Image="*powershell.exe*"
| stats count by CommandLine, ParentCommandLine, User
| where count > 1
```

### Brute Force Login Attempts
```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 10
| sort -count
```

### Brute Force Followed by Successful Login (Correlation)
```spl
index=* sourcetype=WinEventLog:Security
| eval event_type=if(EventCode=4625,"failed","success")
| where EventCode=4625 OR EventCode=4624
| stats values(event_type) as event_sequence count by Account_Name
| where mvfind(event_sequence,"failed") >= 0 AND mvfind(event_sequence,"success") >= 0
```

### Registry Persistence Detection
```spl
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
| table _time, User, Image, TargetObject, Details
```

### PowerShell → Registry Persistence (Multi-Stage Correlation)
```spl
index=* sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
(EventCode=1 Image="*powershell.exe*") OR (EventCode=13 TargetObject="*\\Run*")
| transaction Computer maxspan=5m
| where eventcount >= 2
```

---

## 🔔 Alerts Configured

| Alert Name | Trigger Condition | Severity |
|---|---|---|
| Brute Force Detected | >10 failed logins from same source | High |
| Suspicious PowerShell | PowerShell spawned with encoded/hidden args | Medium |
| Registry Persistence | Write to `HKLM\...\Run` or `HKCU\...\Run` | High |
| Multi-Stage Attack Chain | PowerShell + registry write within 5 minutes | Critical |

---

## 📝 Key Learnings

- Configured **end-to-end log forwarding** from a Windows endpoint to a SIEM using Splunk Universal Forwarder
- Deployed **Sysmon** with an industry-standard config for high-fidelity Windows telemetry
- Safely simulated **MITRE ATT&CK-mapped adversary techniques** using Atomic Red Team
- Wrote **advanced SPL queries** including multi-event correlation and statistical anomaly detection
- Built **real-time dashboards** and **alert rules** to emulate a live SOC detection workflow
- Strengthened **detection engineering** skills by tuning rules to reduce false positives

---

## 📸 Screenshots

Screenshots of dashboards, alerts, reports, and test results are available in the `/screenshots/` folder.

---

## 🔗 Resources & References
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) — Community Sysmon configuration
- [MITRE ATT&CK Framework](https://attack.mitre.org/) — Adversary tactics and techniques knowledge base
- [Splunk Enterprise](https://www.splunk.com/) — SIEM platform
- [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html) — Lightweight log forwarder
- [Invoke-AtomicRedTeam PowerShell Module](https://github.com/redcanaryco/invoke-atomicredteam) — PowerShell wrapper for Atomic Red Team

---

> **Author:** Mounik Biswas  
> **Certifications:** CCNA Essentials | CompTIA Security+  
> **Domain:** Blue Team | SOC Operations | Security Analyst 

> 💡 *This lab was built purely for educational purposes in an isolated virtual environment. All attack simulations were conducted in a controlled setting with no impact on production systems.*
