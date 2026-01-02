### Scenario

“Script execution attacks” occur when a bad actor infects your endpoint with malware that uses a “script interpreter” (in this case, AutoIt.exe) to automatically launch malicious programs within the target machine, silently. This typically happens when you download this malware from a website or click a malicious link.

This lab involves creating MDE detection rules to detect the attack, setting up a VM to be vulnerable to it, using some tools to monitor the VM, and finally executing the malicious script. Finally, conduct a basic incident response based on what was detected using NIST 800-61.

### Technology:
  - Microsoft Defender for Endpoint (MDE)
  - Virtual Machine (VM)
  - Sentinel
  - AtomicRedTeam Scripts

### Setup

Spin up a VM, disable the firewall, and the Network Security Group (NSG) to allow download of the scripts. 

Onboard your VM to Microsoft Defender for Endpoint (EDR) to enable detection. Download the script from this site

```
https://sacyberrange00.blob.core.windows.net/mde-agents/Windows-10-and-11-GatewayWindowsDefenderATPOnboardingPackage.zip
```
Install Git.

```

```

