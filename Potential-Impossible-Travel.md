## What is Impossible Travel?

**Impossible Travel** is a security detection technique used to identify potentially compromised user accounts based on **geographic inconsistency in authentication events**.

### How it works
An alert is triggered when:

- A user logs in from **Location A**
- Then logs in again from **Location B**
- Within a time window that is **physically impossible** to travel between  
  *(e.g. Ireland → Singapore in 20 minutes)*

### What this may indicate:
 Impossible Travel detections often point to:

- **Stolen credentials**
- **Session hijacking**
- **Token theft**
- Use of **VPNs, proxies, or anonymization services** by an attacker

## Why Impossible Travel Matters

### Common attacker behaviors
Attackers frequently:

- Use credentials stolen via **phishing**
- Authenticate from **cloud infrastructure** or **foreign IP ranges**
- Bypass MFA using **token replay** or **MFA fatigue attacks**

### Why this detection is effective
Impossible Travel is effective because:

- It focuses on **behavior**, not malware
- It detects **valid logins** being used maliciously
- It works especially well in **cloud-first and identity-focused attack scenarios**
