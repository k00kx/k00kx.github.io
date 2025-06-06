(() => {
  const $       = sel => document.querySelector(sel);
  const rnd     = max => Math.floor(Math.random() * max);
  const shuffle = arr => {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = rnd(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  };

  const createCard = itm => {
    const a = document.createElement('a');
    a.href      = itm.url;
    a.className = 'tool-card';
    a.innerHTML = `
      ${itm.source ? `<span class="badge-src">${itm.source}</span>` : ''}
      <div class="thumb" style="background-image:url('${itm.thumbnail}')"></div>
      <div class="card-body">
        <h3>${itm.title}</h3>
        <p>${itm.description}</p>
        <div class="tag-list">
          ${itm.tags.map(t => `<span class="tag">${t}</span>`).join('')}
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
      const get  = n => doc.querySelector(`meta[name="${n}"]`)?.content.trim() || '';

      const title = get('portfolio-title');
      if (!title) return null;

      let source = get('portfolio-source');
      if (!source) {
        const seg = url.split('/').filter(Boolean)[1] || '';
        const map = {
          htb: 'HackTheBox',
          thm: 'TryHackMe',
          pg:  'PortSwigger',
          cwl: 'CyberWarFare'
        };
        source = map[seg] || '';
      }

      return {
        url,
        source,
        title,
        description: get('portfolio-description'),
        tags: get('portfolio-tags')
               .split(',')
               .map(t => t.trim())
               .filter(Boolean),
        thumbnail: get('portfolio-thumb') || '/img/ui/walking.gif'
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
    const parts    = location.pathname.split('/').filter(Boolean);
    const lastPart = parts.length ? parts[parts.length - 1].toLowerCase() : '';
    const isIndex  = lastPart === '' || lastPart === 'home.html';
    const isLabs   = lastPart === 'labs.html';

    // 1) BUSCA TODOS os <a> dentro de ".nav-links" cujo href:
    //    - comece com "/RedTeam/"
    //    - termine com ".html"
    let links = Array.from(
      document.querySelectorAll('.nav-links a[href^="/RedTeam/"][href$=".html"]')
    ).map(a => a.getAttribute('href'));

    // 2) Caso o menu esteja fechado (nenhum ".links a" visível), captura
    //    qualquer <a> em ".dropdown-content" com o mesmo critério:
    if (links.length === 0) {
      links = Array.from(
        document.querySelectorAll('.nav-links .dropdown-content a[href^="/RedTeam/"][href$=".html"]')
      ).map(a => a.getAttribute('href'));
    }

    // 3) Em labs.html, filtramos para garantir que só fiquem URLs dentro de "/RedTeam/"
    //    (na prática já capturamos assim, mas deixamos por garantia):
    if (!isIndex && isLabs) {
      links = links.filter(url => url.startsWith('/RedTeam/'));
    }

    // 4) Se ainda não encontrou nada, aborta (não renderiza cards)
    if (links.length === 0) {
      return;
    }

    // 5) Faz fetch/meta de cada URL
    const itemsRaw = await Promise.all(links.map(fetchMeta));
    const items    = itemsRaw.filter(it => it !== null);

    // 6) Se não é índice e não é labs.html, fazemos filtragem por “source”:
    let slice = items;
    if (!isIndex && !isLabs) {
      const catDir = lastPart.replace('.html', '');
      const srcMap = { htb: 'hackthebox', thm: 'tryhackme', cwl: 'cyberwarfare' };
      const expectedSource = srcMap[catDir] || '';
      if (expectedSource) {
        const norm = s => s.toLowerCase().replace(/\s+/g, '');
        slice = items.filter(it => norm(it.source) === expectedSource);
      }
    }

    // 7) Exibe o search box
    document.getElementById('search-box-wrapper').style.display = 'block';

    // 8) Prepara a lista final
    const fullList = slice.slice();
    let initialList;
    if (isIndex) {
      // Home: exibe 4 aleatórios
      const shuffled   = shuffle(fullList.slice());
      initialList = shuffled.slice(0, Math.min(4, shuffled.length));
    } else {
      // labs.html e subpáginas: exibe todos embaralhados
      initialList = shuffle(slice.slice());
    }

    // 9) Renderiza a lista inicial
    render(initialList);

    // 10) Listener de busca
    document.getElementById('searchBox').addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();

      if (isIndex) {
        // Home: se campo vazio, volta aos 4 aleatórios
        if (!q) {
          const again     = shuffle(fullList.slice());
          const firstFour = again.slice(0, Math.min(4, again.length));
          render(firstFour);
          return;
        }
        // Home: filtra fullList e mostra até 4 resultados
        const filtered = fullList.filter(it =>
          it.title.toLowerCase().includes(q)       ||
          it.description.toLowerCase().includes(q) ||
          it.tags.some(t => t.toLowerCase().includes(q)) ||
          it.source.toLowerCase().includes(q)
        );
        render(filtered.slice(0, Math.min(4, filtered.length)));

      } else {
        // labs.html / htb.html / thm.html / cwl.html: filtra slice completo e exibe tudo filtrado
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