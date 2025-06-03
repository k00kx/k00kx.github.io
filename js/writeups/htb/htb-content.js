(() => {
  const shuffle = a => {                             
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  };
  const $ = sel => document.querySelector(sel);

  function cardHTML(item) {
    return `
      <a href="${item.url}" class="tool-card">
        <span class="badge">${item.source}</span>
        <div class="thumb" style="background-image:url('${item.thumbnail}')"></div>
        <div class="card-body">
          <h3>${item.title}</h3>
          <p>${item.description}</p>
          <div class="tag-list">
            ${item.tags.map(t => `<span class="tag">${t}</span>`).join('')}
          </div>
        </div>
      </a>`;
  }

  async function readMeta(url) {
    const html = await fetch(url).then(r => r.text());
    const doc  = new DOMParser().parseFromString(html, 'text/html');
    const get  = n => doc.querySelector(`meta[name="${n}"]`)?.content || '';

    return {
      url,
      title       : get('portfolio-title')       || url,
      description : get('portfolio-description') || '',
      tags        : get('portfolio-tags').split(',').map(t => t.trim()).filter(Boolean),
      thumbnail   : get('portfolio-thumb')       || '/assets/walking.gif',
      source      : get('portfolio-source')      || 'Write-up'
    };
  }

  function render(list) {
    const grid = $('#cardGrid');
    grid.innerHTML = list.map(cardHTML).join('');
  }

  document.addEventListener('DOMContentLoaded', async () => {
    const links = Array.from(
      document.querySelectorAll('.nav-links .dropdown-content a[href$=".html"]')
    ).map(a => a.getAttribute('href'));

    const items = await Promise.all(links.map(readMeta));

    const htb = shuffle(items.filter(i => i.source.toLowerCase() === 'hackthebox'));

    $('#search-box-wrapper').style.display = 'block';
    render(htb);

    $('#searchBox').addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();
      const filt = htb.filter(i =>
        i.title.toLowerCase().includes(q) ||
        i.description.toLowerCase().includes(q) ||
        i.tags.some(t => t.toLowerCase().includes(q))
      );
      render(filt);
    });
  });
})();