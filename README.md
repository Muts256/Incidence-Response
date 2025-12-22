## Introduction

This repository documents **practical Incident Response investigations** focused on detecting, analysing, and responding to real-world security threats commonly observed in enterprise and SOC environments.

The investigations in this repository follow the **NIST Incident Response Lifecycle**, ensuring a structured and repeatable approach to handling security incidents:

- **Preparation** – establishing visibility, logging, and readiness to detect malicious activity  
- **Detection and Analysis** – identifying suspicious behaviour, validating alerts, and determining incident scope and impact  
- **Containment, Eradication, and Recovery** – considering actions to limit impact, remove the threat, and restore affected systems safely  
- **Post-Incident Activity** – documenting findings, lessons learned, and opportunities for improvement  

Each investigation demonstrates how these phases are applied in practice, from initial alert triage through to analysis and response decision-making.

The scenarios included reflect **realistic attack techniques and suspicious activity patterns**, such as:
- [Brute Force Attempts Detection](https://github.com/Muts256/Incident-Response/blob/main/Brute-Force-Attempt-Detection.md) 
- [Suspicious PowerShell web requests]  
- [Potential Impossible Travel]  
- [Excessive Resource Creation/Deletion] 
  
Where applicable, investigations are mapped to **MITRE ATT&CK** techniques to provide additional context on adversary behaviour and to support threat-informed defence.

---

### Tools and Technologies

- **Microsoft Sentinel (SIEM)**
- **Microsoft Defender for Endpoint (MDE)**
- **Kusto Query Language (KQL)**

## Detection Coverage (MITRE ATT&CK Aligned)

As part of the **Detection and Analysis** phase of the  **NIST SP 800-61 Incident Response Lifecycle**, this is an example of how detections and investigations can be mapped to the **MITRE ATT&CK framework**.

MITRE ATT&CK helps to:
- Understand adversary behaviour
- Validate detection coverage
- Support alert triage and investigation
- Identify detection gaps for continuous improvement

| Tactic | Technique ID | Technique Name | Detection / Investigation |
|------|-------------|---------------|---------------------------|
| Credential Access | T1110 | Brute Force | Brute Force Sign-In Detection (Sentinel Scheduled Rule) |
| Execution | T1059.001 | PowerShell | Suspicious PowerShell Web Request |
| Credential Access | T1003 | OS Credential Dumping | Mimikatz Execution Investigation |
| Command and Control | T1071.001 | Web Protocols | Suspicious Outbound HTTP Traffic |
