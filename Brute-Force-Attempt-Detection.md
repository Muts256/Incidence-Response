## Table of Contents

- [Brute Force Attempt](#brute-force-attempt)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Stage of the Attack](#stage-of-the-attack)
- [Incident Response Relevance](#incident-response-relevance)
- [Scenario](#scenario)
  - [1. Preparation](#1-preparation)
  - [2. Detection & Analysis](#2-detection--analysis)
  - [3. Containment, Eradication, and Recovery](#3-containment-eradication-and-recovery)
  - [4. Post-Incident Activity](#4-post-incident-activity)
- [Lessons Learned](#lessons-learned)

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

[Back to Top](#table-of-contents)

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

[Back to Top](#table-of-contents)

---
### 1. Preparation

The **Preparation** phase focuses on establishing the capabilities, processes, and resources necessary to respond effectively to security incidents. 

Key activities include:

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

On the Create a new Scheduled rule wizard page, Fill in the name of the rule, give a brief description select the severity, It may High, Medium or Low depending on the criticality, impact and risk to the business/asset. Company policy is another consideration when determinig the severity level.

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In4.png)

For the MITRE ATT&CK select the mapping. In this case Credential Access and Impair Process Control (for ICS/OT environments) 

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In5.png)

On the Set rule logic, Write the query that will be used for detection.

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In6.png)

Query used:

```
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```
In the Alert enhancement section select Hostname and DeviceName and IP Adress and RemoteIP to enable Sentinel to recognise and classify the data.

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In7.png)

In the Query scheduling section, fill in how often the query will be executed, set it to run automatically and the alert theshold set to zero

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In7a.png)

[Back to Top](#table-of-contents)

---

### 2. Detection & Analysis


The **Detection and Analysis** phase focuses on identifying potential security incidents, validating alerts, and understanding their scope and impact. 

Key activities include:

- Monitoring alerts from SIEM, EDR, IDS/IPS, and security tools
- Identifying indicators of compromise (IOCs) and suspicious behaviour
- Performing alert triage and prioritisation based on risk and business impact
- Determining whether activity represents a true incident or a false positive
- Analysing logs and telemetry to identify affected systems, users, and timelines
- Mapping observed activity to MITRE ATT&CK techniques
- Preserving evidence to support forensic analysis
- Escalating confirmed incidents according to incident response procedures

The objective of this phase is to ensure incidents are accurately identified and sufficient context is gathered to enable effective containment and remediation

In Sentinel, navigate to the Incident tab and select it. Search for the rule name created in the previous step. An incident will appear if the rule was violated.

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In8.png)

Select the incident.

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In9.png)

The incident can now be assigned to an analyst for investigation and the status set to active. Indicating to other team members that the indident is under investigation

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In10.png)

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In11.png)

Part of the investigation is to find out if any of the violating IP addresses was successful in it's attempt to gain access to any of the systems. To get this navigation to Sentinel and manual run the rule.

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In11a.png)

Create another query that will establish/confirm if any of the IP addesses gained access.

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In11b.png)

Query used:

```
DeviceLogonEvents
| where RemoteIP in ("212.200.34.189", "146.19.24.26", "174.138.116.10", "139.99.95.109", "174.138.7.124", "159.100.20.23", "51.178.174.31")
| where ActionType != "LogonFailed"
```
In this case none of the IP addresses was successful.

[Back to Top](#table-of-contents)

---

### 3. Containment, Eradication, and Recovery

The **Containment, Eradication, and Recovery** phase focuses on limiting the impact of a confirmed incident, removing the threat, and restoring systems to
normal operation.

**Containment** activities include:
- Isolating affected hosts or segments
- Disabling compromised user or service accounts
- Blocking malicious IPs, domains, or indicators
- Applying temporary controls to prevent lateral movement

If any of the IP addresses had a successful login. Isoloating the device would the next step the analyst would take. Using MDE search for the device under Assests > Device. Select the device

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In12.png)

This action is taken to contain ie stop the spread of the threat. User accounts can be disabled in the Active Directory/ Entra AD.

To block the IP addresses. a firewall rule can be configured specifing the addresses to block. In Azure, a rule in the Network Security Group (NSG) can be created specifing the IP address that are allowed to RDP into the device.

**Eradication** activities include:
- Removing malware or malicious artefacts
- Closing exploited vulnerabilities
- Applying security patches and configuration fixes
- Resetting credentials and rotating keys or certificates

If the threat is a malware, avirus scan can be started in MDE. Select the device, click on the 3 dots then select Run Antivirus Scan

![image alt](https://github.com/Muts256/SNC-Public/blob/2bdee97c08e8482a78020086ef3c927c0fa3d098/Images/Incident-Response/Brute-Force/In12a.png)

**Recovery** activities include:
- Restoring systems from clean backups if required
- Validating system integrity and functionality
- Monitoring systems for recurrence or residual activity
- Returning systems to production in a controlled manner

At this stage if any of the devices was compromised, consider re-imaging the device. Affected user account passwords need to be changed.

The objective of this phase is to fully eliminate the threat while ensuring business operations are restored securely and safely.

It is important to ensure that the threat has been remediated before moving forward. This means monitoring the affected devices and letting the scheduled rule run automatically. If remediation was successful no detections should be found.

[Back to Top](#table-of-contents)

---

### 4. Post-Incident Activity

The **Post-Incident Activity** phase focuses on learning from the incident and improving the organisation’s overall security posture.

Key activities include:

- Conducting lessons learned and post-incident reviews
- Analysing what worked well and what needs improvement
- Identifying gaps in detection, response, or security controls
- Updating incident response playbooks and procedures
- Improving detection rules, alerts, and monitoring coverage
- Updating documentation and providing training where required
- Reporting incident metrics and findings to stakeholders

The objective of this phase is continuous improvement, ensuring the organisation is better prepared to detect and respond to future incidents

Document the steps that were taken and include them in the Activity log. 

![image alt](https://github.com/Muts256/SNC-Public/blob/d1d0d6e6c04ae3fd523ffc194fb2a9d7c06f87c5/Images/Incident-Response/Brute-Force/In14.png)

After the review, recomendations applied, improvements made the incident can be closed

![image alt](https://github.com/Muts256/SNC-Public/blob/fbe051bc7f9e5c2f72c179c5f05bc085e91166b8/Images/Incident-Response/Brute-Force/In15.png)

[Back to Top](#table-of-contents)

---

# Lessons Learned

- Early detection of repeated failed authentication attempts was critical in preventing a successful compromise and limiting potential impact.  
- Alerting on failed logon thresholds is effective for detection; however, implementing preventative controls such as multi-factor authentication and account lockout policies would further reduce brute force risk.  
- Restricting RDP access at the network layer using NSG rules proved to be an effective containment measure and should be enforced proactively.  
- Post-incident monitoring and validation of scheduled analytics rules confirmed the effectiveness of remediation and that no further malicious activity occurred.


