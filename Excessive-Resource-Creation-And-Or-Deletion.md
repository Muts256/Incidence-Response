## Table of Contents

- [Excessive Resource Creation/Deletion](#excessive-resource-creationdeletion)
- [Use of NIST Incident Response](#use-of-nist-incident-response)
- [Preparation](#preparation)
- [Detection and Analysis](#detection-and-analysis)
- [Containment, Eradication, and Recovery](#containment-eradication-and-recovery)
- [Post-Incident Activity](#post-incident-activity)
- [Lessons Learned](#lessons-learned)


## Excessive Resource Creation/Deletion

Excessive resource creation/deletion refers to the abnormal or unexpected provisioning or destruction of a large number of infrastructure or cloud resources within a short period of time, exceeding normal operational activity.

This behaviour may indicate compromised credentials, malicious persistence, resource hijacking (such as cryptomining), misuse of automation, or insider threat activity. In cloud environments, rapid resource creation can lead to security exposure, service disruption, and significant financial impact if not detected and controlled promptly.


### Security Considerations

Excessive creation or deletion of cloud resources may indicate compromised credentials, malicious persistence, defence evasion, financial abuse, or intentional service disruption. Such activity can lead to data loss, service outages, increased operational costs, and reduced security visibility.

### MITRE ATT&CK Mapping

This activity maps to several MITRE ATT&CK techniques, depending on the  attacker's
intent:

| Tactic | Technique ID | Technique Name |
|------|-------------|---------------|
| Persistence | T1098 | Account Manipulation |
| Persistence | T1136 | Create Account |
| Defense Evasion | T1562.008 | Disable or Modify Cloud Logs |
| Impact | T1485 | Data Destruction |
| Impact | T1496 | Resource Hijacking |


## Use of NIST Incident Response

The **NIST SP 800-61 Incident Response Lifecycle** provides a structured approach to handling incidents involving excessive creation of cloud resources.

- **Preparation:** Logging, monitoring, IAM controls, and alerting are established to detect abnormal resource provisioning.
- **Detection and Analysis:** Alerts are analysed to determine whether the activity represents legitimate automation, misconfiguration, or malicious behaviour such as account compromise or resource hijacking.
- **Containment, Eradication, and Recovery:** Access is restricted, unauthorised resources are removed, credentials are rotated, and affected systems are restored to a secure state.
- **Post-Incident Activity:** Lessons learned are used to improve detection logic, tighten access controls, and enhance cloud governance.

Applying the NIST Incident Response framework ensures incidents are handled consistently, efficiently, and in alignment with industry best practices.

## Preparation

During the **Preparation** phase, the organisation ensures it is ready to detect, respond to, and mitigate abnormal cloud resource activity.

Key activities include:

- **Logging and monitoring:** Capture all resource creation and deletion events.
- **IAM and access controls:** Enforce least-privilege roles and separation of duties.
- **Alerting rules:** Configure SIEM or cloud-native monitoring to flag unusual activity.
- **Playbooks and runbooks:** Predefine response actions for rapid containment and remediation.
- **Incident response readiness:** Train SOC analysts to recognise abnormal provisioning or deletion patterns.
- **Baseline normal behaviour:** Understand typical operational activity to reduce false positives.

*Create a Scheduled rule* 
This rule will be used to detect excessive creation/deletion of resources

In Sentinel, Analytics workspace in the analytics tab, click Create a new scheduled rule

![image alt](https://github.com/Muts256/SNC-Public/blob/cb6eea585dd420bd0cb9ef8e89fd5367d9ff0413/Images/Incident-Response/Excessive-Resource-Creation-And-Or-Deletion/Er1.png)

Select the related MITRE ATT&CK

![image alt](https://github.com/Muts256/SNC-Public/blob/cb6eea585dd420bd0cb9ef8e89fd5367d9ff0413/Images/Incident-Response/Excessive-Resource-Creation-And-Or-Deletion/Er2.png)

Set rule logic

```
let ResourceCreations = AzureActivity
    | extend ClaimsJson = parse_json(Claims)
    | extend ObjectIdentifier = tostring(ClaimsJson["http://schemas.microsoft.com/identity/claims/objectidentifier"])
    | where OperationNameValue !startswith "MICROSOFT.SECURITYINSIGHTS/ALERTRULES" and OperationNameValue !startswith "MICROSOFT.SECURITYINSIGHTS/INCIDENTS"
    | where OperationNameValue endswith "WRITE" and ActivityStatusValue == "Success"
    | summarize NumberOfResourceCreations = count() by Caller, ObjectIdentifier, CallerIpAddress;
let ResourceDeletions = AzureActivity
    | extend ClaimsJson = parse_json(Claims)
    | extend ObjectIdentifier = tostring(ClaimsJson["http://schemas.microsoft.com/identity/claims/objectidentifier"])
    | where OperationNameValue !startswith "MICROSOFT.SECURITYINSIGHTS/ALERTRULES" and OperationNameValue !startswith "MICROSOFT.SECURITYINSIGHTS/INCIDENTS"
    | where OperationNameValue endswith "DELETE" and ActivityStatusValue == "Success" 
    | summarize NumberOfResourceDeletions = count() by Caller, ObjectIdentifier, CallerIpAddress;
ResourceCreations
| join kind=fullouter ResourceDeletions on ObjectIdentifier, Caller, CallerIpAddress
| project
    ObjectIdentifier,
    Caller,
    CallerIpAddress,
    NumberOfResourceCreations,
    NumberOfResourceDeletions
| where NumberOfResourceCreations >= 5 or NumberOfResourceDeletions >= 5
| order by NumberOfResourceCreations, NumberOfResourceDeletions
, NumberOfResourceDeletions

```
### Query Explanation 

- Parses Azure Activity logs to extract the user Object Identifier from the Claims field.
- Filters out operations related to Security Insights alerts and incidents, focusing only on successful `WRITE` (creation) and `DELETE` operations.
- Summarises the number of resource creations and deletions per user, Object Identifier, and IP address.
- Performs a full outer join of creations and deletions to correlate activity per user and device.
- Filters for users with 5 or more creations or deletions, and orders the results by number of actions for easy review.


Add Alert Enhancement to help identify the entity as unique

![Image alt](https://github.com/Muts256/SNC-Public/blob/cb6eea585dd420bd0cb9ef8e89fd5367d9ff0413/Images/Incident-Response/Excessive-Resource-Creation-And-Or-Deletion/Er3.png)

Save the query.

[Back to the Top](#table-of-contents)

---

## Detection and Analysis 

During the **Detection and Analysis** phase, the SOC investigates alerts related to abnormal resource creation or deletion activity.

Key steps include:

- **Alert monitoring:** Receive alerts from SIEM (e.g., Sentinel) when thresholds
  for excessive resource activity are exceeded.
- **Event correlation:** Aggregate creation/deletion events by user, IP, and
  object identifier to identify abnormal patterns.
- **Context enrichment:** Review IAM roles, recent changes, and user activity
  to determine if activity is legitimate (e.g., automation) or malicious.
- **Verification:** Confirm that resources affected were not part of normal
  operational processes.
  
This phase ensures that abnormal cloud activity is accurately detected and investigated before taking corrective actions.

After the rule detects a violation, an incident will be created.

![image alt](https://github.com/Muts256/SNC-Public/blob/cb6eea585dd420bd0cb9ef8e89fd5367d9ff0413/Images/Incident-Response/Excessive-Resource-Creation-And-Or-Deletion/Er4.png)

Set the incident status to Active

![image alt](https://github.com/Muts256/SNC-Public/blob/cb6eea585dd420bd0cb9ef8e89fd5367d9ff0413/Images/Incident-Response/Excessive-Resource-Creation-And-Or-Deletion/Er5.png)

Investigate the incident.

![image alt](https://github.com/Muts256/SNC-Public/blob/cb6eea585dd420bd0cb9ef8e89fd5367d9ff0413/Images/Incident-Response/Excessive-Resource-Creation-And-Or-Deletion/Er6.png)


Investigate the offending user

![image alt](https://github.com/Muts256/SNC-Public/blob/cb6eea585dd420bd0cb9ef8e89fd5367d9ff0413/Images/Incident-Response/Excessive-Resource-Creation-And-Or-Deletion/Er7.png)

[Back to the Top](#table-of-contents)

---

## Containment, Eradication, and Recovery 

Once abnormal resource activity is confirmed as malicious or unauthorized, the SOC initiates containment, eradication, and recovery actions.

**Containment actions:**
- Temporarily disable or restrict the affected account
- Apply conditional access or block suspicious IP addresses
- Stop ongoing automated or manual creation/deletion processes

**Eradication actions:**
- Remove unauthorized resources created by the attacker
- Rotate compromised credentials and enforce MFA
- Revoke malicious service principals, tokens, or API keys
- Correct misconfigurations that allowed the activity

**Recovery actions:**
- Restore systems and resources to a known-good state
- Re-enable the user account after verification
- Monitor activity to ensure no recurrence
- Verify normal operations and enforce cloud governance policies

This phase ensures threats are removed, normal operations are restored, and further abuse is prevented.

The incident indicates that over 4,000 resources were created or deleted. In a real-world scenario, such an incident would be escalated by the SOC fro tfuther investigation. The affected account would be temporarily disabled, and the associated device isolated using Microsoft Defender for Endpoint (MDE). Once the activities are thoroughly reviewed and the investigation determines that no malicious activity occurred, normal operations and access would be restored.

After the user has given a satifactory reason for the activities and no malicious intent is found the incident can be closed

[Back to the Top](#table-of-contents)

---

## Post-Incident Activity 

After the incident is resolved, a post-incident review is conducted to evaluate the response and identify improvements.

**Key activities:**

- **Lessons learned:** Analyze triggers, detection accuracy, and response effectiveness.
- **Playbook updates:** Refine alert thresholds, detection rules, and response procedures.
- **Access and IAM improvements:** Adjust roles, permissions, and policies to reduce risk.
- **Governance and monitoring enhancements:** Update cloud governance policies, logging, and alerting.
- **Stakeholder reporting:** Share findings with management and teams to inform risk mitigation.

The objective of this phase is continuous improvement to reduce the likelihood and impact of future excessive resource creation or deletion incidents.

---

## Lessons Learned 

- **Detection thresholds must be tuned carefully:** Setting thresholds too high may miss malicious activity, while too low may generate false positives.
- **Context and enrichment are critical:** Alerts are meaningful only when combined with IAM roles, automation patterns, and device information.
- **Automation can be both helpful and risky:** Legitimate scripts and DevOps pipelines can trigger alerts; clear baselines are essential to distinguish normal activity from malicious behaviour.
- **Rapid containment reduces impact:** Disabling compromised accounts and isolating devices immediately prevents further unauthorized resource modifications.
- **Post-incident review strengthens defenses:** Updating detection rules, playbooks, and IAM policies based on lessons learned improves resilience and reduces future risk.
- **Cloud governance is essential:** Policies on resource creation/deletion, least-privilege roles, and monitoring ensure abnormal activity is detected early.

[Back to the Top](#table-of-contents)
