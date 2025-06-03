(() => {
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
      <div class="thumb" style="background-image:url('${item.thumbnail}')"></div>
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
    const html = await fetch(url).then(r => r.text());
    const doc  = new DOMParser().parseFromString(html, 'text/html');
    const get  = name => doc.querySelector(`meta[name="${name}"]`)?.content || '';

    let source = get('portfolio-source');
    if (!source) {
      const seg = url.split('/').filter(Boolean)[1] || '';
      const map = { htb: 'HackTheBox', thm: 'TryHackMe', pg: 'PortSwigger', pg: 'CyberWarFare' };
      source = map[seg] || '';          
    }

    return {
      url,
      source,
      title:       get('portfolio-title')       || url,
      description: get('portfolio-description') || '',
      tags:        get('portfolio-tags').split(',').map(t => t.trim()).filter(Boolean),
      thumbnail:   get('portfolio-thumb')       || '/assets/walking.gif'
    };
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

    const items = await Promise.all(links.map(fetchMeta));

    const allItems = shuffle(items);
    render(allItems);

    const search = document.getElementById('searchBox');
    search.addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();
      const filtered = allItems.filter(itm =>
        itm.title.toLowerCase().includes(q)       ||
        itm.description.toLowerCase().includes(q) ||
        itm.tags.some(t => t.toLowerCase().includes(q)) ||
        itm.source.toLowerCase().includes(q)
      );
      render(filtered);
    });
  });
})();
