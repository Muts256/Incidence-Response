## Brute Force Attempt

A **Brute Force attempt** is an attack technique in which an adversary repeatedly tries different username and password combinations to gain unauthorised access to a system, application, or service. This technique relies on weak passwords, reused credentials, default accounts, or the absence of effective account lockout and monitoring controls.

Brute force activity is commonly observed against:
- Remote access services (RDP, SSH, VPN)
- Web applications and portals
- Email and authentication services
- Administrative or privileged accounts

Such attempts are often characterised by a **high volume of failed authentication events**, sometimes followed by a successful login if valid credentials are discovered.

---

## MITRE ATT&CK Mapping

- **Framework:** MITRE ATT&CK (Enterprise)  
- **Technique ID:** **T1110 – Brute Force**  
- **Tactic:** **Credential Access**

> Adversaries attempt to guess passwords by systematically trying many possible combinations, often using automation or credential lists.

*(In ICS / OT environments, this activity maps to **T0806  Brute Force** under MITRE ATT&CK for ICS.)*

---

## Stage of the Attack

Brute force attempts typically occur during the **early stages of an attack**, most commonly associated with:

- **Initial Access** – attempting to gain entry into an environment  
- **Credential Access** – attempting to obtain valid authentication credentials  

While primarily classified under **Credential Access**, successful brute force attacks can directly enable **Initial Access**, allowing adversaries to proceed with lateral movement, privilege escalation, or persistence.

---

## Incident Response Relevance

If successful, brute force attacks can:
- Lead to unauthorized system access
- Enable account compromise
- Act as a precursor to broader intrusion activity

Early detections and investigations are critical to prevent escalation and limit impact.

---

# Scenario

An organisation needs to implement the NIST Special Publication 800-61 Revision 2: Computer Security Incident Handling Guide: Incident Response Lifecycle to prevent a repeat of a recent security breach.

Commonly referred to in practice as the **“NIST Incident Response Lifecycle”**, it covers the four main phases:

1. **Preparation**
2. **Detection and Analysis**
3. **Containment, Eradication, and Recovery**
4. **Post-Incident Activity**

---
### 1. Preparation

The **Preparation** phase focuses on establishing the capabilities, processes, and resources necessary to respond effectively to security incidents. Key activities include:

- Developing and documenting **incident response policies and procedures**  
- Establishing **roles and responsibilities** for the IR team and stakeholders  
- Implementing **security monitoring, logging, and alerting** systems (SIEM, EDR, etc.)  
- Creating **playbooks, runbooks, and detection rules** for common incidents  
- Conducting **training and awareness** exercises for staff  
- Ensuring **tools, access, and communication channels** are ready for incident handling  
- Performing **risk assessments and system hardening** to reduce potential impact  

The goal is to **ensure readiness** before an incident occurs, so detection and response can be swift and effective.

In this scenario, this will include designing a Sentinel Scheduled Query Rule within Log Analytics that will discover when the same remote IP address has failed to log in to the same local host (Azure VM) 10 times or more within the last 5 hours.

*Creating a Scheduled Rule in Sentinel:*

> An analytics rule that runs KQL queries at defined intervals to detect suspicious or malicious activity from log data and generate alerts and incidents.

Navigate to Sentinel in the Azure portal. Click on the Log Analytics Workspace.

Click on the Analytics tab to create a scheduled query rule

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In1.png)


