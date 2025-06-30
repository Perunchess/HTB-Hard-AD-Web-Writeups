### **Mantis (HTB) Write-Up: From Web Enumeration to Domain Dominance**

This report details the penetration testing process for the "Mantis" machine on the Hack The Box platform. Rated as a "Hard" difficulty machine, Mantis provides a challenging and realistic journey through Active Directory enumeration, web application vulnerability discovery, creative credential decoding, and classic Kerberos exploitation to achieve full system compromise.

-----

### **Phase 1: Initial Reconnaissance and Enumeration**

The first step in any engagement is a thorough reconnaissance of the target system.

#### **Port Scanning**

A full TCP port scan was initiated to identify all open services on the target IP address. This provides a complete map of the potential attack surface.

**Commands:**

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.133.141 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.133.141
```

**Key Findings:**
The `nmap` scan revealed a Windows Server 2008 R2 machine acting as a Domain Controller for the `htb.local` domain. The following critical ports were identified:

  * **53, 88, 135, 139, 389, 445, 636:** Standard Active Directory services (DNS, Kerberos, RPC, NetBIOS, LDAP, SMB, LDAPS).
  * **1337 (HTTP):** A non-standard web server running Microsoft IIS httpd 7.5.
  * **3389 (RDP):** Remote Desktop Protocol, indicating a possible graphical login point.

Based on these findings, the domain names were added to the local `/etc/hosts` file to ensure proper name resolution for subsequent steps.

```bash
echo "10.129.133.141 mantis.htb.local htb.local" | sudo tee -a /etc/hosts
```
![nmap results](images\browser_NK1BbB0yCT.png)

![nmap results](images\browser_Pt03SBCRu2.png)

![nmap results](images\browser_f3CEhzAl9W.png)

#### **Service Enumeration**

Initial enumeration of SMB and LDAP with `enum4linux` confirmed the OS details and that anonymous access was permitted, but yielded no users or shares. However, a more targeted approach against Kerberos using `kerbrute` proved successful in identifying a list of valid domain usernames. This step was crucial as it provided the first piece of the puzzle: a valid username.

![enum4linux results](images\browser_XF4xRqDByM.png)

![enum4linux results](images\browser_A6NJmuZgMg.png)

![kerbute results](images\browser_I2nc2aaF9r.png)

-----

### **Phase 2: Initial Foothold via Web Application**

With Active Directory enumeration temporarily exhausted, the focus shifted to the web application running on port 1337.

#### **Directory Fuzzing and Discovery**

The web application's root page was sparse. A directory fuzzing tool was used to discover hidden content, which quickly uncovered a directory named `/secure_notes`.

![fuzz results](images\browser_jHm4HyLGSn.png)


Navigating to this directory revealed two files:

  * `dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt`
  * `web.config` (Access Denied)

The `dev_notes` file contained instructions for setting up an OrchardCMS instance and, more importantly, a binary string presented as "OrchardCMS admin creadentials."

1. Download OrchardCMS
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
3. Launch IIS and add new website and point to Orchard CMS folder location.
4. Launch browser and navigate to http://localhost:8080
5. Set admin password and configure sQL server connection string.
6. Add blog pages with admin user.

Credentials stored in secure format
OrchardCMS admin creadentials 010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001
SQL Server sa credentials file namez

#### **Credential Decoding: Part 1 (OrchardCMS)**

The binary string was:
`010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001`

A simple Python script was used to convert this binary string to its ASCII equivalent, revealing the password for the OrchardCMS administrator.

```python
binary_string = "010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001"

if len(binary_string) % 8 != 0:
    print("Warning: Binary string length is not a multiple of 8. It might be truncated or malformed.")

decoded_chars = []
for i in range(0, len(binary_string), 8):
    byte = binary_string[i:i+8]
    try:
        decimal_val = int(byte, 2)
        decoded_chars.append(chr(decimal_val))
    except ValueError:
        print(f"Error decoding byte: {byte}. This might indicate invalid binary or a non-ASCII character in a different encoding.")
        decoded_chars.append("[ERROR]")

decoded_password = "".join(decoded_chars)
print(f"Decoded potential password: {decoded_password}")
```

**Decoded Password:** `@dm!n_P@ssW0rd!`

Logging into the OrchardCMS dashboard with the credentials `admin` / `@dm!n_P@ssW0rd!` did not immediately provide further access. However, the filename of the notes file itself was a clue.

#### **Credential Decoding: Part 2 (SQL Server)**

The long string in the filename, `NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx`, appeared to be Base64 encoded. Decoding it revealed a hexadecimal string.

1.  **Base64 Decode:**
    ```bash
    echo "NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx" | base64 -d
    # Output: 6d2424716c5f53405f504073735730726421
    ```
2.  **Hex to ASCII Conversion:**
    ```bash
    echo "6d2424716c5f53405f504073735730726421" | xxd -p -r
    # Output: m$$ql_S@_P@ssW0rd!
    ```


This revealed a password for what was likely the SQL Server `sa` account: `m$$ql_S@_P@ssW0rd!`but ended up being for admin.

![logged_in results](images\browser_zoT3oS4U8Z.png)

#### **Database Pivot**

Using these credentials (presumably through a database administration feature within OrchardCMS), it was possible to query the backend database. An inspection of the database schema revealed the `Orchard_Users_UserPartRecord` table, which contained user information. Querying this table exposed the credentials for the user `james`.

![table results](images\browser_EVPDMCoWzT.png)

**Discovered Credentials:** `james` / `J@m3s_P@ssW0rd!`

-----

### **Phase 3: Privilege Escalation with MS14-068**

With valid domain user credentials, the final phase was to escalate privileges to Domain Administrator.

#### **Identifying the Vulnerability**

The target's operating system, **Windows Server 2008 R2**, is notoriously vulnerable to **MS14-068**. This critical vulnerability allows a user to forge a Kerberos ticket with a specially crafted Privilege Attribute Certificate (PAC), tricking the Domain Controller into granting them Domain Admin-level privileges.

#### **Exploitation**

The exploitation process required configuring the local Kerberos client and then using an exploit script.

1.  **Kerberos Configuration (`/etc/krb5.conf`):** The client was configured to recognize the `htb.local` realm.

    ```ini
    [libdefaults]
        default_realm = HTB.LOCAL

    [realms]
        HTB.LOCAL = {
            kdc = mantis.htb.local:88
            admin_server = mantis.htb.local
        }
    ```

2.  **Obtain a Ticket-Granting Ticket (TGT):** Using the credentials for `james`, a valid TGT was requested from the KDC.

    ```bash
    kinit james
    # Password: J@m3s_P@ssW0rd!
    ```

3.  **Forge Privileged Ticket and Execute:** Impacket's `goldenPAC.py` script was used to leverage MS14-068. The script uses the valid TGT for `james`, injects a forged PAC, and requests a service ticket that grants administrator access. This was then used to launch a command shell on the target.

The script successfully executed, providing an interactive shell with the highest privileges: `NT AUTHORITY\SYSTEM`.

![root proof](images\browser_KvpDLLQlAd.png)

-----

### **Remediation and Recommendations**

The compromise of this machine was possible due to a chain of vulnerabilities. The following remediation steps are recommended:

1.  **Patch Critical Vulnerabilities:** The highest priority is to apply the security patch for MS14-068. All systems running Windows Server 2008 R2 should be audited and updated immediately.
2.  **Remove Sensitive Information:** Developer notes, credentials, or any sensitive data should never be stored in a web-accessible directory. The `secure_notes` directory and its contents must be removed.
3.  **Enforce Least Privilege:** The SQL Server account used by the web application should have the minimum permissions necessary, not the all-powerful `sa` role.
4.  **Credential Security:** Passwords should never be stored in easily decodable formats. The binary and Base64/Hex encoding provided trivial security.

### **Conclusion**

Mantis was a well-designed machine that mirrored real-world attack paths. The logical progression from reconnaissance to enumeration, credential discovery, and finally, privilege escalation via a known but critical vulnerability, made for an engaging and educational experience. It highlights how a single oversight, like leaving developer notes on a web server, can unravel an entire domain's security.