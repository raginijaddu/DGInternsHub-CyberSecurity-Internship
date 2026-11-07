# DG Interns Hub: Week 3

**Linux Logs, Sysmon, auditd and Snort Setup**

| | |
|---|---|
| **Programme** | DG Interns Hub |
| **Week** | 3 |
| **Deadline** | 7 November 2026, 11:59 pm |
| **Deliverables** | [Report (PDF)](Week3_Report.pdf), [Presentation](Week3_Presentation.pptx), this README |

---

## Contents

1. [Summary](#1-summary)
2. [Lab Environment](#2-lab-environment)
3. [Folder Structure](#3-folder-structure)
4. [Tasks Completed](#4-tasks-completed)
5. [Sysmon (Windows)](#5-sysmon-windows)
6. [auditd (Ubuntu)](#6-auditd-ubuntu)
7. [Snort Setup](#7-snort-setup)
8. [Nmap SYN Scan Rule (MITRE ATT&CK T1046)](#8-nmap-syn-scan-rule-mitre-attck-t1046)
9. [Key Learnings](#9-key-learnings)
10. [Tools Used](#10-tools-used)

---

## 1. Summary

This week I worked with endpoint data and network detection. I installed Sysmon on Windows and auditd on Linux to see how endpoint activity is logged, and I set up Snort on an Ubuntu VM to write and test intrusion detection rules, including a rule mapped to MITRE ATT&CK **T1046 (Network Service Discovery)**.

## 2. Lab Environment

| Machine | Role | Details |
|---|---|---|
| Windows VM | Sysmon | SwiftOnSecurity config |
| Ubuntu 64-bit VM (VMware) | auditd and Snort 2.9.20 | Interface `ens33`, IP `192.168.110.135/24` |
| Kali 12.x VM (VMware) | Attacker / traffic generator | IP `192.168.110.133`, same network |

## 3. Folder Structure

```text
DG Interns Hub
└── Week 3
    ├── Notes                      10 theory answers, one file per question
    ├── Writeups                   TryHackMe and LetsDefend writeups, one file per lab
    ├── Findings                   Screenshots: Sysmon, auditd, Snort setup, Snort alerts
    ├── Cheat Sheet                Event ID / Rule - What It Means - When to Use It (37 entries)
    ├── Snort Rules                local.rules (starter rules + T1046 rule)
    ├── Week3_Report.pdf           Weekly report
    ├── Week3_Presentation.pptx    Weekly presentation
    └── README.md                  This file
```

## 4. Tasks Completed

| # | Task | Status |
|---|---|---|
| 1 | Theory: 10 questions | Done |
| 2 | TryHackMe: Linux Logging for SOC, Intro to Logs, Intro to Log Analysis, Snort | Done |
| 3 | LetsDefend: How to Investigate a SIEM Alert, Security Solutions, Network Log Analysis, SIEM 101, Incident Management, Incident Response on Linux | Done |
| 4 | Hands-on 1: Install Sysmon with the SwiftOnSecurity config | Done |
| 5 | Hands-on 2: Generate events (PowerShell, new user, network connection, text file) and find them in Event Viewer | Done |
| 6 | Hands-on 3: Install auditd and find commands with `ausearch` | Done |
| 7 | Hands-on 4: Snort setup and starter rules | Done |
| 8 | Hands-on 5: Nmap SYN scan rule mapped to T1046 | Done |
| 9 | Hands-on 6: Cheat sheet | Done |
| 10 | LinkedIn post on endpoint logging | Done |

## 5. Sysmon (Windows)

- Extracted Sysmon to `C:\Sysmon` with `sysmonconfig-export.xml` from SwiftOnSecurity.
- Installed with:

  ```bat
  sysmon.exe -accepteula -i sysmonconfig-export.xml
  ```

- Checked events in Event Viewer: **Applications and Services Logs > Microsoft > Windows > Sysmon > Operational**.

| Action | Sysmon Event ID |
|---|---|
| Opened PowerShell | 1 (Process Create) |
| Created a new user account | 1 (Process Create) |
| Checked network connections | 3 (Network Connection) |
| Created a text file | 11 (File Create) |

## 6. auditd (Ubuntu)

```bash
sudo apt-get install -y auditd
sudo systemctl enable auditd --now
sudo systemctl status auditd
sudo apt install nano
sudo ausearch -k nano
sudo ausearch -m EXECVE -ts recent
```

Useful audit fields: `type`, `msg`, `exe`, `uid`, `gid` and the command arguments.

## 7. Snort Setup

```bash
ip a                                   # interface ens33, subnet 192.168.110.0/24
sudo apt-get update
sudo apt-get install -y snort snort-common snort-rules-default
snort -V                               # Snort 2.9.20
sudo nano /etc/snort/snort.conf        # HOME_NET 192.168.110.0/24, EXTERNAL_NET !$HOME_NET
sudo nano /etc/snort/rules/local.rules
sudo snort -T -i ens33 -c /etc/snort/snort.conf
sudo snort -A console -q -c /etc/snort/snort.conf -i ens33
```

### Starter rules

```text
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"SSH Connection Attempt"; sid:1000002; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"HTTP Traffic"; sid:1000003; rev:1;)
```

Tested from Kali with `ping -c 4`, `curl` and `nc -zv <ip> 22`. All three alerts fired.

## 8. Nmap SYN Scan Rule (MITRE ATT&CK T1046)

```text
alert tcp any any -> $HOME_NET any (msg:"MITRE T1046 - Nmap SYN Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 1; classtype:attempted-recon; metadata:mitre_technique T1046; reference:url,attack.mitre.org/techniques/T1046/; sid:1000004; rev:1;)
```

Test from Kali:

```bash
sudo nmap -sS -T5 -p 1-2000 192.168.110.135
```

Snort produced many T1046 alerts.

### Problems fixed

- Typo `trace by_src` instead of `track by_src` caused "unknown option: trace".
- Reference URL typo `T10146` corrected to `T1046`.
- `threshold` inside a rule gives a deprecation warning; `detection_filter` is the newer option.
- Kali is inside `HOME_NET`, so the rule source was changed from `$EXTERNAL_NET` to `any` for this single-subnet lab.

### Limitation

A slow scan (for example `nmap -T1`) stays below the threshold and would not trigger this rule.

## 9. Key Learnings

- Sysmon and auditd give much more detail than default OS logs.
- Sysmon Event IDs 1, 3, 11 and 22 cover process, network, file and DNS activity.
- A Snort rule has a header and options, and `snort -T` catches mistakes before going live.
- Mapping rules to MITRE ATT&CK gives alerts context.
- Detection depends on the network setup (`HOME_NET`, `EXTERNAL_NET`).

## 10. Tools Used

All free: VMware Workstation, Ubuntu, Kali Linux, Sysmon, auditd, Snort, Nmap, TryHackMe, LetsDefend.
