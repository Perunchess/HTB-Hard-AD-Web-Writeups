# HTB-Hard-AD-Web-Writeups | Conquering Hard Machines

---

### **Mastering the Toughest Challenges in Active Directory & Web Exploitation**

---

Welcome, fellow digital warrior, to my personal **arsenal of in-depth write-ups** for **Hack The Box (HTB)** machines!

This repository isn't just a collection of solutions; it's a **deep dive into the strategic methodologies** required to break through the most formidable **'Hard' difficulty boxes**. My focus? Unraveling the complexities of **Active Directory (AD)** and executing intricate **Web Exploitation** techniques.

---

###  Why This Repository Rocks 

Forget superficial walkthroughs. Each write-up here is a **meticulous breakdown** of the entire penetration testing journey:

*  Initial Reconnaissance: From port scans to service enumeration.
*  Foothold Establishment: Uncovering critical web vulnerabilities and leveraging them for initial access.
*  Credential Decoding: Cracking obscure encodings to reveal hidden secrets.
*  Privilege Escalation: Elevating access to achieve ultimate system or domain control.
*  Remediation Insights: Actionable recommendations to fortify defenses against similar attacks.

My goal is to provide **unfiltered, step-by-step explanations** of complex attack chains, showcasing the exact tools, commands, and critical thought processes that lead to success. Whether you're aiming to learn, refine your skills, or just appreciate a well-executed hack, these analyses are designed to be your ultimate guide.

---

###  Featured Conquests 

Explore the detailed breakdown of my latest victories:

#### [1. Mantis](Mantis.md)
* **Difficulty:** Hard
* **Tags:** Active Directory, Web, IIS, OrchardCMS, MS14-068, Kerberos
* **Description:** A pivotal machine demanding prowess in web enumeration, creative binary and Base64 decoding, and the precise execution of a critical Active Directory vulnerability (MS14-068). Discover how a seemingly innocuous web note led to **full Domain Dominance**.
#### [2. Blackfield](blackfield.md)
* **Difficulty:** Hard
* **Tags:** Active Directory, Kerberos, AS-REP Roasting, SeBackupPrivilege, LSASS Dump, Pass-the-Hash
* **Description:** This intense Active Directory challenge tested my ability to navigate a complex domain environment. From uncovering vulnerable user accounts via AS-REP Roasting and BloodHound analysis, to leveraging the SeBackupPrivilege to dump the NTDS.dit file, this write-up details the full path to Domain Administrator control.
#### [3. Oouch](Oouch.md)
* **Difficulty:** Hard
* **Tags:** Web, IIS, OAuth, Nmap, FFuf, UNC, Flask, Django
* **Description:** This machine presents a complex web application environment, where an initial information leak from an FTP server points to a misconfigured OAuth implementation. The path to a shell involves a clever **token theft** via an HTTP redirect, a vulnerable API endpoint for user data, and the discovery of SSH credentials, leading to a full system compromise. The attack chain highlights the dangers of insecure API design and unvalidated redirects.
#### [4. Office](Office.md)
* **Difficulty:** Hard
* **Tags:** Active Directory, Joomla, CVE-2023-23752, Kerbrute, Password Spraying, PCAP Analysis, AS-REP Roasting, Pass-the-Hash
* **Description:** A challenging Active Directory scenario that begins with a vulnerable Joomla web server. An unauthenticated API endpoint discloses credentials for a user who, while not privileged on the web server, holds a domain account. The foothold is leveraged through a password spraying attack on the domain, leading to the discovery of a valid user account. The final phase involves analyzing network traffic to perform an **AS-REP Roast** and a Pass-the-Hash attack to gain a Domain Admin shell.
#### [5. Object](Object.md)
* **Difficulty:** Hard
* **Tags:** Jenkins, Web, Command Injection, Active Directory, Credential Theft, RPC
* **Description:** This intricate path to domain administrator control starts with a Jenkins instance on an unusual port. A simple **command injection** vulnerability in the build system allows for initial code execution as a low-privileged user, leading to the recovery of encrypted secrets. The attack pivots to Active Directory where a critical misconfiguration allows for the hijacking of user objects via RPC, ultimately leading to a full domain takeover.
#### [6. Flight](Flight.md)
* **Difficulty:** Hard
* **Tags:** Active Directory, Web, Virtual Host, LFI, UNC Injection, NTLM Hash Capture, Responder, SweetPotato, EfsRpc
* **Description:** This machine's initial access is gained through a Local File Inclusion (LFI) vulnerability discovered on a hidden virtual host. The LFI is leveraged to perform a UNC path injection, forcing the server to authenticate to a malicious listener and capturing an NTLM hash. After cracking the hash, the attack chain progresses with a privilege escalation using the **SweetPotato** tool, exploiting the EfsRpc abuse vector to escalate to a SYSTEM shell, thus gaining a full compromise.
#### [7. Analysis](Analysis.md)
* **Difficulty:** Hard
* **Tags:** Active Directory, LDAP Injection, Nmap, FFuf, DLL Hijacking, Impacket
* **Description:** This write-up documents a complex red team engagement centered on an Active Directory environment with a vulnerable internal web application. The initial foothold is a **blind LDAP injection** vulnerability on a user listing page, used to enumerate users and groups without direct output. The path to privilege escalation involves exploiting a software with a misconfigured DLL path, leading to DLL hijacking and code execution. The final attack highlights the critical importance of secure software configurations and the dangers of misconfigured group policies in an AD environment.
#### [8. Acute](Acute.md)
* **Difficulty:** Hard
* **Tags:** Active Directory, PowerShell, Web, Credential Disclosure, Windows PowerShell Web Access (PSWA), Scheduled Task Hijack, Group Policy Abuse
* **Description:** A sophisticated Active Directory challenge that begins with an open-source intelligence (OSINT) discovery of a publicly available document. This document contains an unpatched vulnerability and discloses a **default password** used by multiple employees. This single piece of information provides initial access to a Windows PowerShell Web Access (PSWA) portal. The subsequent privilege escalation involves leveraging a misconfigured scheduled task to execute a malicious script as a privileged user, ultimately leading to a full domain compromise.


###  What's Next?

I'm relentlessly pursuing new challenges! Expect more high-quality write-ups covering diverse and advanced AD and Web exploitation scenarios in the near future.

---

###  Connect & Contribute

Found a typo? Have a different approach? Or just want to share your own HTB experiences?
Feel free to **open an issue**, **submit a pull request**, or simply **star this repository** to show your support!

---
