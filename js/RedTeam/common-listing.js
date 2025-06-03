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
      thumbnail   : get('portfolio-thumb')       || '/assets/walking.gif'
    };
  }

  const render = list => {
    const grid = $('#cardGrid');
    grid.innerHTML = list.map(cardHTML).join('');
  };

  document.addEventListener('DOMContentLoaded', async () => {

    const parts  = location.pathname.split('/').filter(Boolean);  
    const catDir = (parts.length >= 2 ? parts[1] : '').toLowerCase();

    const srcMap = { htb: 'hackthebox', thm: 'tryhackme', cwl: 'cyberwarfare' };
    const expectedSource = srcMap[catDir] || '';

    const links = Array.from(
      document.querySelectorAll('.nav-links .dropdown-content a[href$=".html"]')
    ).map(a => a.getAttribute('href'));

    const items = await Promise.all(links.map(readMeta));

    const norm = s => s.toLowerCase().replace(/\s+/g,'');
    const slice = expectedSource
      ? items.filter(it => norm(it.source) === expectedSource)
      : items;                      

    $('#search-box-wrapper').style.display = 'block';
    const initialList = shuffle(slice);
    render(initialList);

    $('#searchBox').addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();
      const match = initialList.filter(it =>
        it.title.toLowerCase().includes(q)       ||
        it.description.toLowerCase().includes(q) ||
        it.tags.some(t => t.toLowerCase().includes(q)) ||
        it.source.toLowerCase().includes(q)
      );
      render(match);
    });
  });

})();