const markdown =
'# CRTA-Lab — Red-Team Walk-through\n\
\n\
> End-to-end compromise of the CyberWarFare CRTA lab: external foothold, internal pivot, AD takeover and NTDS extraction.\n\
>\n\
> **Difficulty :** Advanced   |   **Platform :** Windows / Linux hybrid\n\
\n\
---\n\
\n\
## ☑️ Lab Badge\n\
\n\
![CRTA Lab Logo](/img/writeups/cwl/crta-lab/logo.png)\n\
\n\
[🔗 Go to Lab Portal](https://academy.cyberwarfare.live/)\n\
\n\
---\n\
\n\
## 🧩 Initial Foothold\n\
\n\
*(Coloque aqui toda a sua seção de enumeração: nmap, credenciais iniciais, etc.)*\n\
\n\
```bash\n\
$ nmap -sS -Pn -T4 -p- <IP>\n\
...\n\
```\n\
\n\
---\n\
\n\
## 📂 SMB & Internal Pivot\n\
\n\
*(Detalhe a exploração SMB, pivot interno, descobertas BloodHound, etc.)*\n\
\n\
---\n\
\n\
## 🔑 DPAPI e Dump de Hash NTDS\n\
\n\
*(Descreva a extração de masterkeys / credential blobs, cracking, elevação a DA, DRSUAPI dump, etc.)*\n\
\n\
---\n\
\n\
## 🏁 Flags & Lessons Learned\n\
\n\
* **user.txt :** `<hash>`\n\
* **root.txt :** `<hash>`\n\
\n\
> **Key take-aways** : abuse de ACL (GenericWrite / GenericAll), DPAPI offline, Pass-the-Hash em WinRM e riscos de senhas armazenadas em backup XML.\n\
';

document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('markdown-content');
  if (!container) return;

  container.innerHTML = marked.parse(markdown);

  container.querySelectorAll('pre code').forEach(block => {
    block.innerHTML = block.innerHTML
      .split('\n')
      .map(line =>
        line.trimStart().startsWith('~$')
          ? `<span style="color:#FFD700;font-weight:bold;">${line}</span>`
          : line
      )
      .join('\n');
  });
});