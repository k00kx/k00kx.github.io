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
Reconnaissance began by identifying the external and internal IP ranges provided in the lab scope: <code>192.168.80.0/24</code> and <code>192.168.98.0/24</code><span class="codefix">.</span> These subnets typically host infrastructure components such as perimeter services, internal servers, and domain resources. Notably, <code>192.168.80.1</code> and <code>192.168.98.1</code> were explicitly excluded from testing, as they fall outside the authorized engagement scope. With these constraints in place, enumeration efforts proceeded by scanning only the permitted ranges to identify reachable hosts and map the initial attack surface.
</p>

```
~$ nmap -sn 192.168.80.2-254

Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-17 14:14 MDT
Nmap scan report for 192.168.80.10
Host is up (0.17s latency).
Nmap done: 253 IP addresses (1 host up) scanned in 12.42 seconds
```

<p class="indent-paragraph">
After identifying <code>192.168.80.10</code> as the only live host in the external network, I proceeded with a service enumeration scan to identify running applications and gather version information. The scan utilized the flags <code>-sC</code> for default NSE scripts, <code>-sV</code> for service and version detection, <code>-p-</code> to cover all 65535 TCP ports, and <code>-T4</code> to increase speed without being overly aggressive.
</p>
<p class="indent-paragraph">
This enumeration phase lays the groundwork for deeper analysis. The next steps involve interacting with the HTTP service to inspect its structure, discover hidden paths, and potentially identify input vectors for exploitation.
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
To simplify interaction and avoid typing the raw IP address each time, I mapped the target IP address <code>192.168.80.10</code> to a hostname using the local resolver configuration.
</p>

```
~$ sudo nano /etc/hosts

192.168.80.10 ecommerce.lab
```

<p class="indent-paragraph">
Navigating to <code>ecommerce.lab</code> revealed a login portal for a platform titled <code>Cyberwarops E-commerce</code><span class="codefix">.</span> This login page appears to be part of a custom-developed web application branded as CyberWarFare Labs, which aligns with the http-title identified during the Nmap scan. While analyzing the login page I noticed a link labeled “Sign Up”, located below the login form. Clicking on this link led to the user registration endpoint<code>
http://ecommerce.lab/registration.php</code><span class="codefix">.</span>
</p>
<p class="indent-paragraph">
  <img src="/img/RedTeam/cwl/crta-http-login.png" alt="login page cyberwarcops" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

<p class="indent-paragraph">
While navigating through the authenticated area of the application <code>http://ecommerce.lab/dashboard1.php</code><span class="codefix">,</span> I discovered a newsletter subscription field that accepted an email address as input. Submitting the form triggered the following behavior: <code>alert("Thanks for subcribing ..!")</code><span class="codefix">.</span>
</p>
<p class="indent-paragraph">
  <img src="/img/RedTeam/cwl/crta-newsletter-email.png" alt="Thanks for subcribing" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

### 🧨 Command Injection via Email Parameter

<p class="indent-paragraph">
The presence of raw <code>&lt;script&gt;</code> output indicates that the server is dynamically generating JavaScript based on user interaction. This strongly indicates that the value of the <code>EMAIL</code> parameter is being executed by the underlying system shell, without proper input validation or sanitization. To validate the injection point, a crafted POST request was sent with <code>EMAIL=cat /etc/passwd</code>, resulting in the disclosure of the system's <code>/etc/passwd</code> file. This confirms the presence of unauthenticated command injection.
</p>
<p class="indent-paragraph">
  <img src="/img/RedTeam/cwl/crta-command-injection-email.png" alt="Command Injection via Email Parameter" style="width:100%; border-radius:6px; margin-top: 1em;" />
</p>

### 🔐 Remote Shell Access via SSH

</div>