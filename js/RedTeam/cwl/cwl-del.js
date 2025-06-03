const markdown =
'\
> **Objective**  \n\
> Assess the security posture of the CyberWarFare CRTA enterprise environment, identify AD mis-configurations and provide remediation paths.  [oai_citation:0‡CRTA-lab_progress.pdf](file-service://file-WAsEi67fC3Qsc2WbeNXGPS)\n\
\n\
---\n\
\n\
##  🛰  Initial Access\n\
\n\
### Identifying Assigned IP Addresses and Network Context\n\
```bash\n\
ip -4 a | grep inet\n\
```\n\
Output shows:\n\
* `10.10.200.106/24` on **tun0** (VPN)  \n\
* `172.16.11.128/24` on **eth0** (NAT)  \n\
* loopback `127.0.0.1`  [oai_citation:1‡CRTA-lab_progress.pdf](file-service://file-WAsEi67fC3Qsc2WbeNXGPS)\n\
\n\
The **10.10.200.0/24** range is reachable and will be our primary target segment.\n\
\n\
### Scanning the External Range `192.168.80.0/24`\n\
```bash\n\
nmap -sn 192.168.80.2-254\n\
```\n\
*One live host discovered: **192.168.80.10***  [oai_citation:2‡CRTA-lab_progress.pdf](file-service://file-WAsEi67fC3Qsc2WbeNXGPS)\n\
\n\
#### Full TCP scan\n\
```bash\n\
nmap -sC -sV -p- -T4 192.168.80.10\n\
```\n\
Service banners reveal **Apache/2.4.54** hosting the *CyberWarOps – E-commerce* portal.\n\
\n\
![login](/img/RedTeam/cwl/crta-lab/login.png)\n\
\n\
---\n\
\n\
##  🌐  Web-Application Discovery\n\
\n\
Visiting <http://192.168.80.10> presents a login page titled **CyberWarOps – E-commerce**.\n\
\n\
[…MORE…  (paste the rest of your markdown here, keeping indentation & code blocks intact) …]\n\
';

(() => {
  const shuffle = a => { for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]];} return a; };

  const card = itm => {
    const el = document.createElement('a');
    el.href = itm.url;
    el.className = 'tool-card';
    el.innerHTML = `
      <span class="badge-src">CyberWarFare</span>
      <div class="thumb" style="background-image:url('${itm.thumbnail}')"></div>
      <div class="card-body">
        <h3>${itm.title}</h3>
        <p>${itm.description}</p>
        <div class="tag-list">${itm.tags.map(t=>`<span class="tag">${t}</span>`).join('')}</div>
      </div>`;
    return el;
  };

  const meta = async url => {
    const html = await fetch(url).then(r=>r.text());
    const doc  = new DOMParser().parseFromString(html,'text/html');
    const get  = n => doc.querySelector(`meta[name="${n}"]`)?.content || '';
    return {
      url,
      title:       get('portfolio-title')       || url,
      description: get('portfolio-description') || '',
      tags:        get('portfolio-tags').split(',').map(t=>t.trim()).filter(Boolean),
      thumbnail:   get('portfolio-thumb')        || '/assets/walking.gif'
    };
  };

  document.addEventListener('DOMContentLoaded', async () => {
    const links = Array
      .from(document.querySelectorAll('.submenu-label'))
      .find(l=>l.textContent.trim()==='CyberWarFare')       
      .parentElement.querySelectorAll('.links a');

    const urls  = Array.from(links).map(a=>a.getAttribute('href'));
    const items = await Promise.all(urls.map(meta));

    const grid  = document.getElementById('cardGrid');
    const render = list => {
      grid.innerHTML='';
      list.forEach(i=>grid.appendChild(card(i)));
    };

    const all = shuffle(items);
    render(all);

    /* busca */
    const searchWrap = document.getElementById('search-box-wrapper');
    searchWrap.style.display='block';
    document.getElementById('searchBox').addEventListener('input',e=>{
      const q=e.target.value.trim().toLowerCase();
      render(all.filter(itm=>
        itm.title.toLowerCase().includes(q) ||
        itm.description.toLowerCase().includes(q) ||
        itm.tags.some(t=>t.toLowerCase().includes(q))
      ));
    });
  });
})();