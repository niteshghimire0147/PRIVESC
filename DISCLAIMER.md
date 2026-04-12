# Disclaimer — Linux Privilege Escalation Automation Toolkit

> **Read this document before using the tool.**  
> By running this software you confirm that you have read, understood, and agreed to the terms below.

---

## Table of Contents

- [Authorised Use Only](#authorised-use-only)
- [Detection Only — No Exploitation Code](#detection-only--no-exploitation-code)
- [No Warranty](#no-warranty)
- [Responsible Use](#responsible-use)
- [Academic and Educational Context](#academic-and-educational-context)
- [Applicable Law](#applicable-law)

---

## Authorised Use Only

This tool is designed **exclusively** for the following purposes:

| Permitted Use | Description |
|---------------|-------------|
| Authorised penetration testing | Systems you own, or systems where you hold explicit **written** permission from the owner |
| Security education and coursework | Controlled lab environments, intentionally vulnerable VMs, course assignments |
| CTF competitions | Designated challenge systems within the competition scope |
| System hardening audits | Conducted by or on behalf of the system owner |

**Using this tool on any system without explicit authorisation is illegal** regardless of intent.

Unauthorised use may violate laws including but not limited to:

- **Computer Fraud and Abuse Act (CFAA)** — United States
- **Computer Misuse Act 1990** — United Kingdom
- **Cybercrime Convention (Budapest Convention)** — EU and signatories
- Equivalent cybercrime legislation in your jurisdiction

Penalties for unauthorised computer access vary by jurisdiction but can include significant fines and imprisonment.

---

## Detection Only — No Exploitation Code

This toolkit is **detection-only**. It identifies potential privilege escalation vectors and reports them with contextual information. It does **not**:

- Automatically exploit any vulnerability
- Modify system configuration or files
- Create backdoors, persistence, or reverse shells
- Escalate privileges on your behalf
- Exfiltrate data off the system

Exploit examples included in reports are **for educational reference only** — they help administrators understand the real-world impact of a finding and verify that mitigations are effective. They are not automated and require deliberate manual execution by a human operator in an authorised context.

---

## No Warranty

This software is provided **"as is"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.

The authors accept **no responsibility or liability** for:

| Scenario | Example |
|----------|---------|
| Damage from use or misuse | System instability caused by running scans |
| Inaccurate findings | False positives flagging benign configurations |
| Missed vulnerabilities | False negatives leaving real risks unreported |
| Unauthorised use | Consequences of running the tool without permission |
| Actions taken on output | Decisions made based on the tool's report |

Security scanning tools can interact unexpectedly with monitoring systems, intrusion detection, or rate-limiting software. Always notify relevant parties before running scans in production environments.

---

## Responsible Use

### If you are scanning a system you administer

1. **Document and track** findings using your organisation's vulnerability management process
2. **Remediate** in order of severity — CRITICAL findings first
3. **Do not share** raw scan output containing system details publicly or with unauthorised parties
4. **Re-scan** after remediation to confirm findings are resolved
5. Follow your organisation's **vulnerability disclosure policy** for any issues that affect third-party software

### If you are conducting an authorised engagement

1. Keep a copy of your **written authorisation** accessible throughout the engagement
2. **Report findings** only to the authorising party or parties named in the scope of work
3. Handle all scan output as **confidential client data**
4. **Do not retain** data beyond what is required by the terms of the engagement
5. Comply with any **data handling agreements** (NDA, DPA, etc.) in place

---

## Academic and Educational Context

If you are using this tool as part of a university course, security bootcamp, or personal learning:

- **Run it only** on virtual machines or lab systems set up explicitly for security practice
- **Do not run** it on shared university or college infrastructure without explicit written approval from IT
- **Appropriate targets** include intentionally vulnerable platforms such as:
  - Metasploitable 2 / 3
  - VulnHub machines
  - HackTheBox / TryHackMe lab environments
  - Your own locally provisioned VMs
- **Do not submit** raw scan output of real production systems as coursework

If you are unsure whether a target system is in scope, **ask your instructor or supervisor** before scanning.

---

## Applicable Law

This tool is intended for lawful use only. Security research and penetration testing are legal activities when properly authorised. Performing the same activities without authorisation is a criminal offence in virtually every jurisdiction.

If you are conducting security research and believe you have found a vulnerability in a third-party system:

1. **Do not exploit** the vulnerability beyond what is necessary to confirm it exists
2. **Disclose responsibly** — contact the vendor or system owner through their responsible disclosure or bug bounty programme
3. Refer to frameworks such as the [disclose.io safe harbour](https://disclose.io/) for guidance on protected research

---

*Last updated: 2025*  
*This disclaimer is provided for informational purposes and does not constitute legal advice.*  
*Consult a qualified legal professional if you have questions about the legality of specific activities in your jurisdiction.*
