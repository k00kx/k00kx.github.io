(() => {
  const $    = sel => document.querySelector(sel);
  const rnd  = max => Math.floor(Math.random() * max);
  const shuffle = arr => {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = rnd(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  };

  const cardHTML = itm => `
    <a href="${itm.url}" class="tool-card">
      <span class="badge-src">${itm.source}</span>
      <div class="thumb" style="background-image:url('${itm.thumbnail}')"></div>
      <div class="card-body">
        <h3>${itm.title}</h3>
        <p>${itm.description}</p>
        <div class="tag-list">
          ${itm.tags.map(t => `<span class="tag">${t}</span>`).join('')}
        </div>
      </div>
    </a>`;

  async function readMeta(url){
    const html = await fetch(url).then(r => r.text());
    const doc  = new DOMParser().parseFromString(html, 'text/html');
    const get  = n => doc.querySelector(`meta[name="${n}"]`)?.content || '';

    return {
      url,
      source      : get('portfolio-source')      || 'Write-up',
      title       : get('portfolio-title')       || url,
      description : get('portfolio-description') || '',
      tags        : get('portfolio-tags').split(',').map(t=>t.trim()).filter(Boolean),
      thumbnail   : get('portfolio-thumb')       || '/img/ui/walking.gif'
    };
  }

  const render = list => {
    const grid = $('#cardGrid');
    grid.innerHTML = list.map(cardHTML).join('');
  };

  document.addEventListener('DOMContentLoaded', async () => {
    const parts = location.pathname.split('/').filter(Boolean);
    const lastPart = parts.length ? parts[parts.length - 1].toLowerCase() : '';
    const isIndex = lastPart === '' || lastPart === 'index.html';

    // Sempre pegamos os links visíveis no menu para compor “links”
    let links = Array.from(
      document.querySelectorAll('.nav-links .dropdown-content .links a[href$=".html"]')
    ).map(a => a.getAttribute('href'));

    // Se estivermos em labs.html (body class="labs-page"), substituímos pelos links fixos
    if (parts.length >= 2 && parts[1].toLowerCase() === 'labs') {
      links = [
        '/RedTeam/htb/puppy.html',
        '/RedTeam/htb/fluffy.html',
        '/RedTeam/cwl/crta-lab.html'
      ];
    }

    const itemsRaw = await Promise.all(links.map(readMeta));
    const items = itemsRaw.filter(it => it !== null);

    let slice = items;
    if (!isIndex && !(parts.length >= 2 && parts[1].toLowerCase() === 'labs')) {
      const catDir = lastPart.endsWith('.html') ? lastPart.replace('.html', '') : lastPart;
      const srcMap = { htb: 'hackthebox', thm: 'tryhackme', cwl: 'cyberwarfare' };
      const expectedSource = srcMap[catDir] || '';
      if (expectedSource) {
        const norm = s => s.toLowerCase().replace(/\s+/g,'');
        slice = items.filter(it => norm(it.source) === expectedSource);
      }
    }

    $('#search-box-wrapper').style.display = 'block';

    const fullList = slice.slice();
    let initialList;
    if (isIndex) {
      const shuffled = shuffle(fullList.slice());
      initialList = shuffled.slice(0, Math.min(4, shuffled.length));
    } else {
      initialList = shuffle(slice.slice());
    }

    render(initialList);

    $('#searchBox').addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();
      if (isIndex) {
        if (!q) {
          const shuffled = shuffle(fullList.slice());
          initialList = shuffled.slice(0, Math.min(4, shuffled.length));
          render(initialList);
          return;
        }
        const filtered = fullList.filter(it =>
          it.title.toLowerCase().includes(q)       ||
          it.description.toLowerCase().includes(q) ||
          it.tags.some(t => t.toLowerCase().includes(q)) ||
          it.source.toLowerCase().includes(q)
        );
        render(filtered);
      } else {
        const filtered = slice.filter(it =>
          it.title.toLowerCase().includes(q)       ||
          it.description.toLowerCase().includes(q) ||
          it.tags.some(t => t.toLowerCase().includes(q)) ||
          it.source.toLowerCase().includes(q)
        );
        render(filtered);
      }
    });
  });
})();