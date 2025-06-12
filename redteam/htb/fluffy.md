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


## 🧩 Enumeration and Initial Access

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


## 🪪 SMB Enumeration

