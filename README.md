# 🛡️ Home Lab SIEM Deployment – Wazuh + ELK Stack + Security Onion

This is a self-directed cybersecurity home lab project built to simulate a small-scale Security Operations Center (SOC) using open-source tools. The goal was to gain hands-on experience with threat detection, log analysis, alert triage, and security monitoring workflows typically used by Tier 1 SOC analysts.

> 📺 Project inspired by [John Hammond Wazuh ELK Stack Tutorial](https://www.youtube.com/watch?v=i68atPbB8uQ)

---

## 🎯 Objectives

- Deploy and configure a functioning SIEM environment from scratch
- Centralize security logs from Windows and Linux endpoints
- Create custom dashboards for monitoring security events
- Simulate attacker behavior (e.g., brute force, PowerShell abuse)
- Practice alert triage and log correlation techniques

---

## 🧰 Tools & Technologies

| Tool              | Purpose                               |
|-------------------|----------------------------------------|
| **Wazuh**         | Host-based intrusion detection (HIDS) |
| **ELK Stack**     | Log storage, analysis, visualization  |
| **Ubuntu Server** | SIEM host (Wazuh manager + Elastic)   |
| **Windows 10 VM** | Endpoint for log generation/testing   |
| **Linux VM**      | Additional endpoint and attacker box  |
| **VirtualBox**    | Hypervisor for running lab VMs        |

---

## 🏗️ Lab Architecture
+-----------------+ Sysmon Logs +--------------------+
| Windows 10 VM | ----------------> | || (Endpoint Host) | | Wazuh Manager |
+-----------------+
| (Ubuntu Server VM) |
| |
+-----------------+ Syslog | +----------------+ |
| Linux Client | ----------------> | | ELK Stack | |
| (Debian/Ubuntu) | | | Kibana + ES | |
+-----------------+ | +----------------+ |
+--------------------+


---

## 🔧 What I Did

- **Deployed Ubuntu Server** and installed Wazuh manager with ELK Stack (ElasticSearch, Logstash, Kibana)
- **Installed Wazuh agents** on Windows 10 and Linux VMs for log forwarding
- **Enabled Sysmon** on Windows endpoint to enhance event visibility (process creation, network connections, etc.)
- **Configured detection rules** in Wazuh for:
  - Brute-force login attempts
  - PowerShell abuse
  - Suspicious process spawning
- **Built custom Kibana dashboards** to visualize key log events like authentication failures, process execution, and user behavior
- **Tested alerts and triage process** by simulating attacker techniques (e.g., password spraying, failed RDP attempts)

---


---

## 📚 What I Learned

- How logs are collected, parsed, and visualized in a real SIEM pipeline
- How to identify abnormal behavior using Windows Event Logs + Sysmon
- Hands-on understanding of host-based detection and alert tuning
- Importance of correlation and context in threat detection

---

## 🚧 Future Improvements

- Add MITRE ATT&CK mapping for triggered rules
- Automate log parsing with custom decoders
- Simulate phishing, privilege escalation, or persistence techniques
- Deploy Security Onion as a complementary NSM stack
---

## 🧠 Why This Matters

This project bridges the gap between theory and practice by simulating a SOC environment using open-source tools. It helped me internalize the core responsibilities of a SOC analyst, from log ingestion to real-time alert triage and reinforced my understanding of how detection tools map to real-world attacks.

---

## 📎 Related Links

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Elastic Stack Documentation](https://www.elastic.co/guide/en/elastic-stack-get-started/current/get-started-elastic-stack.html)
- [John Hammond's YouTube Channel](https://www.youtube.com/@_JohnHammond)
