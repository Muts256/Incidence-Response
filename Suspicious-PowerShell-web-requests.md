## Table of Contents

- [Suspicious PowerShell Web Requests](#suspicious-powershell-web-requests)
- [Scenario](#scenario)
- [Preparation](#preparation)
- [Detection and Analysis](#detection-and-analysis)
- [Containment, Eradication, and Recovery Phase](#containment-eradication-and-recovery-phase)
- [Post-Incident Activity Phase](#post-incident-activity-phase)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Lessons Learned](#lessons-learned)


## Suspicious PowerShell Web requests

In the real world, it is a common occurrence for a user to click on a link that has been designed to steal credentials, which a malicious actor can use to gain access to the user's device. In most cases, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity

## Scenario

By leveraging commands such as Invoke-WebRequest, bad actors can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

By implementing the NIST Incident Response Guidelines, these attacks can be detected early and limit the damage the bad actors could have done.

## NIST Special Publication 800-61 Revision 2: Incident Response Lifecycle

NIST Special Publication 800-61 Revision 2 is a widely used guide published by the National Institute of Standards and Technology (NIST) that provides best practices for handling computer security incidents. It defines an Incident Response (IR) lifecycle to help organizations prepare for, detect, respond to, and recover from security incidents in a structured and repeatable way.

The Incident Response Lifecycle consists of four main phases:

- **Preparation**
- **Detection and Analysis**
- **Containment, Eradication, and Recovery**
- **Post-Incident Activity**

---

## Preparation

The Preparation phase focuses on establishing the people, processes, and technical controls required to effectively detect and respond to suspicious PowerShell web requests before an incident occurs. This includes ensuring visibility into PowerShell activity, network communications, and endpoint behavior, as well as having documented procedures for investigation and response.

In this scenario, create a scheduled rule to detect suspicious PowerShell activity

In Sentinel, navigate to the Analytics in the Analytics workspace and select create a Scheduled rule.

On the Create Scheduled rule wizard page, give the rule a nmae and description.

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp20.png)

For the MITRE ATT&CK, select the associated categories, for example, T1059 Command and Scripting Interpreter

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp2.png)

On the Set rule logic page. Set the query that will be used to query the logs and detect the PowerShell script execution

```
let TargetHostname = "Inc-Response-VM"; 
DeviceProcessEvents
| where DeviceName == TargetHostname 
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp3.png)

Fill in the Alert enhancement fields with host devicename, Name AccountName and Commandline ProcessCommandline

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp4.png)

For the Query Scheduling follow the company policy. In this scenario, run THE query every 4 hrs, lookup data from the last 24 hours

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp5.png)

Create the rule.

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp6.png)

[Back to the Top](#table-of-contents)

---

## Detection and Analysis

The Detection and Analysis phase focuses on identifying suspicious PowerShell activity and determining whether it represents a true security incident. This phase begins with alerts or detections generated from endpoint, network, or SIEM telemetry indicating PowerShell processes making outbound web requests to external or untrusted destinations.

Analysis involves reviewing PowerShell command-line arguments, script block logs, and parent-child process relationships to identify common abuse patterns such as download cradles, encoded commands, or execution from unusual locations. Network indicators, including destination domains, IP addresses, and request frequency, are examined to assess potential command-and-control or payload retrieval activity.

During this phase, analysts assess the scope and impact of the activity by identifying affected hosts, users, and timelines, and by determining whether the behavior is malicious, suspicious, or benign administrative activity. The outcome of this phase is a validated incident classification and a clear understanding of the threat, enabling appropriate containment actions to be taken.

An incident is created after a PowerShell is executed on the device.
Its is assgned to an anlyst for further investigation

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp8.png)

And status changed to active

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp9.png).

Inspect the command that was executed. taking care to to run it by mistake. 

From the logs, in the ProcessCommandline looks like the Powershell script downloads another script on the the device then executes that script.

![image alt](https://github.com/Muts256/SNC-Public/blob/71c35a279478c64bcb8d4962a0786d0a36ceeeea/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp13.png)

This initial indication might require Tthe device to be isolated or for a scan to be initiated.

If there scripts were downdloaded to the device, invesitigate that they were executed 

```
let TargetHostname = "inc-response-vm";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); 
DeviceProcessEvents
| where DeviceName == TargetHostname 
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine

```
The query reveals that the scripts were downloaded and exceuted on the device.

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp12.png).

[Back to the Top](#table-of-contents)

---

## Containment, Eradication, and Recovery Phase

The Containment, Eradication, and Recovery phase focuses on limiting the impact of the suspicious PowerShell activity, removing the root cause, and restoring affected systems to a secure operational state. Containment actions are taken immediately to prevent further execution or communication, such as isolating affected endpoints, blocking malicious domains or IP addresses, and disabling compromised user accounts if required.

Eradication involves identifying and removing the source of the malicious PowerShell activity. This may include deleting malicious scripts, removing persistence mechanisms such as scheduled tasks or registry run keys, terminating unauthorized processes, and cleaning up any downloaded payloads. Endpoint and system configurations are reviewed to ensure no residual indicators remain.

Recovery ensures that systems are safely returned to normal operation. This includes re-enabling network access for isolated hosts, validating system integrity, applying security patches, and monitoring for any recurrence of suspicious PowerShell behavior. Successful recovery is confirmed through continued telemetry review and the absence of new alerts related to PowerShell web requests.

Isolate the device.

![image alt](https://github.com/Muts256/SNC-Public/blob/6893b76659cb75b04b50c372533b90496199f999/Images/Incident-Response/Suspicious-PowerShell-Web-Request/Sp10.png).

Manualy start an Antivirus full scan to ensure that no malware was installed on the device.

Ensure that the user accounts on the device have their password changed, and there may be a need for the device to be re-imaged if malware was found on the device. In some case it does not matter; re-imagining ensures the device is clean

The device can be removed from Isolation once all tests have been confirmed clean
---

## Post-Incident Activity Phase 

The Post-Incident Activity phase focuses on capturing lessons learned and improving the organization’s ability to prevent and respond to similar incidents in the future. This includes documenting the incident timeline, investigation findings, actions taken, and outcome to ensure accurate reporting and knowledge retention.

An extra policy restricting PowerShell execution was implemented, and the user underwent user education on clicking links

Following the incident, detection rules and analytics are reviewed and refined to improve visibility into suspicious PowerShell web requests, such as enhancing alerts for download cradles, encoded commands, or unusual outbound connections. Gaps identified in logging, monitoring, or response procedures are addressed, and playbooks are updated accordingly. Include the findings of the scripts that were downloaded in the report 

This phase also supports continuous improvement by feeding insights back into security awareness, analyst training, and control implementation, ensuring that future PowerShell-based threats can be detected and handled more efficiently.

[Back to the Top](#table-of-contents)

---

## MITRE ATT&CK Mapping

| Tactic                | Technique ID | Technique Name                    | Relevance to Scenario                                                                 |
|-----------------------|--------------|-----------------------------------|---------------------------------------------------------------------------------------|
| Execution             | T1059.001    | PowerShell                        | PowerShell scripts were executed on the device, indicating potential malicious command execution. |
| Command and Control   | T1071.001    | Web Protocols                    | PowerShell was used to make outbound web requests to external destinations.            |
| Command and Control   | T1105        | Ingress Tool Transfer            | Web requests may have been used to download additional scripts or payloads.            |
| Defense Evasion       | T1027        | Obfuscated/Encrypted Files or Info | PowerShell commands may be encoded or obfuscated to evade detection.                  |
| Discovery             | T1082        | System Information Discovery     | Executed scripts may collect host information prior to further actions.               |

---
## Lessons Learned

- Adequate preparation, including enhanced PowerShell logging and endpoint visibility, is essential for detecting suspicious PowerShell web requests at an early stage.

- Correlating PowerShell execution data with network telemetry significantly improves the accuracy of incident detection and reduces false positives during analysis.

- Timely containment actions, such as isolating affected endpoints and blocking malicious destinations, are effective in preventing further execution and potential lateral movement.

- Continuous improvement of detection rules, playbooks, and analyst awareness is necessary to maintain resilience against PowerShell-based attack techniques.

