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
    const parts   = location.pathname.split('/').filter(Boolean);
    const lastPart = parts.length ? parts[parts.length - 1].toLowerCase() : '';
    const isIndex  = lastPart === '' || lastPart === 'index.html';

    // 1) Coleta todos os links das dropdowns
    let links = Array.from(
      document.querySelectorAll('.nav-links .dropdown-content .links a[href$=".html"]')
    ).map(a => a.getAttribute('href'));

    // 2) Se não houver nada em “.links” (menu fechado), pega qualquer <a> em .dropdown-content
    if (links.length === 0) {
      links = Array.from(
        document.querySelectorAll('.nav-links .dropdown-content a[href$=".html"]')
      ).map(a => a.getAttribute('href'));
    }

    // 3) Se estivermos em labs.html, sobrescreve com os links fixos de laboratório
    if (!isIndex && lastPart === 'labs.html') {
      links = [
        '/RedTeam/htb/puppy.html',
        '/RedTeam/htb/fluffy.html',
        '/RedTeam/cwl/crta-lab.html',
        '/RedTeam/thm/overpass.html',
        '/RedTeam/thm/blue.html',
        '/RedTeam/thm/kenobi.html',
        '/RedTeam/thm/vulnversity.html'
      ];
    }

    // 4) Faz fetch de cada página para extrair os <meta name="portfolio-*">
    const itemsRaw = await Promise.all(links.map(readMeta));
    const items    = itemsRaw.filter(it => it !== null);

    // 5) Se não for index e não for labs.html, filtra por fonte (htb/thm/cwl)
    let slice = items;
    if (!isIndex && lastPart !== 'labs.html') {
      const catDir = lastPart.replace('.html', '');
      const srcMap = { htb: 'hackthebox', thm: 'tryhackme', cwl: 'cyberwarfare' };
      const expectedSource = srcMap[catDir] || '';
      if (expectedSource) {
        const norm = s => s.toLowerCase().replace(/\s+/g,'');
        slice = items.filter(it => norm(it.source) === expectedSource);
      }
    }

    // 6) Exibe o campo de busca
    $('#search-box-wrapper').style.display = 'block';

    // 7) Prepara a “fullList” (todos) e “initialList” (o que aparece de início)
    const fullList = slice.slice();
    let initialList;
    if (isIndex) {
      // Home: embaralha e exibe os 4 primeiros (ou menos, se tiver menos de 4 itens)
      const shuffled = shuffle(fullList.slice());
      initialList = shuffled.slice(0, Math.min(4, shuffled.length));
    } else {
      // Qualquer outra página: exibe todos (embalhado)
      initialList = shuffle(slice.slice());
    }

    // 8) Renderiza a lista inicial
    render(initialList);

    // 9) Ao digitar na busca:
    $('#searchBox').addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();

      if (isIndex) {
        // Home: se limpar o campo, volta aos 4 aleatórios
        if (!q) {
          const shuffled = shuffle(fullList.slice());
          initialList = shuffled.slice(0, Math.min(4, shuffled.length));
          render(initialList);
          return;
        }
        // Home: filtra fullList e exibe apenas 4 correspondências
        const filtered = fullList.filter(it =>
          it.title.toLowerCase().includes(q)       ||
          it.description.toLowerCase().includes(q) ||
          it.tags.some(t => t.toLowerCase().includes(q)) ||
          it.source.toLowerCase().includes(q)
        );
        render(filtered.slice(0, Math.min(4, filtered.length)));

      } else {
        // Subpáginas: filtra slice inteiro e exibe todos os correspondentes
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