(() => {

  const DEFAULT_THUMB = '/img/ui/walking.gif';

  const shuffle = arr => {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  };

  const createCard = item => {
    const a = document.createElement('a');
    a.href      = item.url;
    a.className = 'tool-card';
    a.innerHTML = `
      ${item.source ? `<span class="badge-src">${item.source}</span>` : ''}
      <div class="thumb"
           style="background-image:url('${item.thumbnail}')"></div>
      <div class="card-body">
        <h3>${item.title}</h3>
        <p>${item.description}</p>
        <div class="tag-list">
          ${item.tags.map(t => `<span class="tag">${t}</span>`).join('')}
        </div>
      </div>`;
    return a;
  };

  const fetchMeta = async url => {
    try {
      const res = await fetch(url, { cache: 'no-store' });
      if (!res.ok) return null;

      const html = await res.text();
      const doc  = new DOMParser().parseFromString(html, 'text/html');
      const get  = n => doc.querySelector(`meta[name="${n}"]`)
                            ?.content.trim() || '';

      const title = get('portfolio-title');
      if (!title) return null;

      let source = get('portfolio-source');
      if (!source) {
        const seg  = url.split('/').filter(Boolean)[1] || '';
        const map  = { htb:'HackTheBox', thm:'TryHackMe',
                       pg:'PortSwigger', cwl:'CyberWarFare' };
        source = map[seg] || '';
      }

      return {
        url,
        source,
        title,
        description : get('portfolio-description'),
        tags        : get('portfolio-tags')
                        .split(',')
                        .map(t => t.trim())
                        .filter(Boolean),
        thumbnail   : get('portfolio-thumb') || DEFAULT_THUMB
      };

    } catch (err) {
      console.warn('Skipped', url, err.message);
      return null;
    }
  };

  const render = list => {
    const grid = document.getElementById('cardGrid');
    grid.innerHTML = '';
    list.forEach(item => grid.appendChild(createCard(item)));
  };

  document.addEventListener('DOMContentLoaded', async () => {

    const links = Array.from(
      document.querySelectorAll('.nav-links .links a[href$=".html"]')
    ).map(a => a.getAttribute('href'));

    const raw   = await Promise.all(links.map(fetchMeta));
    const items = raw.filter(Boolean);

    // Embaralha todos os itens
    const data = shuffle(items);

    // Mostra apenas 4 cards na home
    const initialFour = data.slice(0, Math.min(4, data.length));
    render(initialFour);

    const search = document.getElementById('searchBox');
    search.addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();
      const filtered = data.filter(itm =>
        itm.title.toLowerCase().includes(q)       ||
        itm.description.toLowerCase().includes(q) ||
        itm.tags.some(t => t.toLowerCase().includes(q)) ||
        itm.source.toLowerCase().includes(q)
      );

      // Ao buscar, exibe no máximo 4 resultados
      render(filtered.slice(0, Math.min(4, filtered.length)));
    });
  });

})();