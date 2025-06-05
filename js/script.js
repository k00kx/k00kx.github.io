const usernames = ["cybersec","pentest","gh0st","redteam","kali","root"];
const skullSymbol = "㉿";
const switchUserInterval = 5000;
let animationTimeouts = [];

const r = (min, max) => Math.floor(Math.random() * (max - min)) + min;
const getRandomUsername = () => usernames[r(0, usernames.length)];

function getCurrentDirectory() {
  const parts = location.pathname.split("/").filter(Boolean);
  const idx = parts.indexOf("RedTeam");
  if (idx !== -1) {
    return parts
      .slice(idx)
      .map(p => p.replace(".html", ""))
      .join("/");
  }
  const file = parts.pop() || "index.html";
  const name = file.replace(".html", "");
  return name === "index" || name === "" ? "Home" : name;
}

function clearAnims() {
  animationTimeouts.forEach(clearTimeout);
  animationTimeouts = [];
}

function animateUsername(newName) {
  const el = document.getElementById("username");
  if (!el) return;
  clearAnims();
  let i = 0;
  const cur = el.textContent;

  const back = () => {
    if (i < cur.length) {
      el.textContent = cur.slice(0, -++i);
      animationTimeouts.push(setTimeout(back, 60));
    } else {
      i = 0;
      type();
    }
  };

  const type = () => {
    if (i < newName.length) {
      el.textContent += newName[i++];
      animationTimeouts.push(setTimeout(type, 100));
    }
  };

  back();
}

function renderHeader() {
  const user     = getRandomUsername();
  const lastDir  = getCurrentDirectory().split("/").pop();
  const prompt   = `[~/${lastDir}]`;

  document.getElementById("header-container").innerHTML = `
    <div class="terminal-header">
      <div class="terminal-line">
        <span class="red">root</span><span class="skull">${skullSymbol}</span><span id="username" class="blue">${user}</span><span id="directory-path">${prompt}</span>
      </div>

      <nav class="nav-links">
        <button class="dropbtn" onclick="location.href='/index.html'">Home</button>

        <button class="dropbtn" onclick="location.href='/whoami.html'">Whoami</button>

        <!-- 3) RedTeam (continuamos usando dropdown normal) -->
        <div class="dropdown">
          <button class="dropbtn">RedTeam</button>
          <div class="dropdown-content">
            <div class="submenu">
              <a href="/RedTeam/labs/labs.html" class="submenu-label">Labs</a>
              <div class="links">
                <a href="/RedTeam/htb/puppy.html">Puppy</a>
                <a href="/RedTeam/htb/fluffy.html">Fluffy</a>
                <a href="/RedTeam/cwl/crta-lab.html">CRTA-Lab</a>
              </div>
            </div>
          </div>
        </div>

        <!-- <button class="dropbtn" onclick="location.href='/forensic.html'">Forensic</button> -->
        <!-- <button class="dropbtn" onclick="location.href='/intelligence.html'">Intelligence</button> -->
      </nav>

      <hr class="separator">
    </div>`;

  document.querySelectorAll(".dropdown").forEach(dropdown => {
    const dropBtn = dropdown.querySelector(".dropbtn");
    dropBtn.addEventListener("click", e => {
      e.stopPropagation();
      dropdown.classList.toggle("open");
    });
    document.addEventListener("click", e => {
      if (!dropdown.contains(e.target)) dropdown.classList.remove("open");
    });
    dropdown.querySelectorAll(".submenu").forEach(sub => {
      const links = sub.querySelector(".links");
      sub.addEventListener("click", e => {
        if (e.target.classList.contains("submenu-label")) return;
        links.style.display = (links.style.display === "block") ? "none" : "block";
      });
    });
  });

  animateUsername(user);
  setInterval(() => animateUsername(getRandomUsername()), switchUserInterval);
}

function loadParticles() {
  if (!document.getElementById("tsparticles") || window.tsLoaded) return;
  const s = document.createElement("script");
  s.src = "https://cdn.jsdelivr.net/npm/tsparticles@2/tsparticles.bundle.min.js";
  s.onload = () => {
    window.tsLoaded = true;
    tsParticles.load("tsparticles", {
      background: { color: { value: "#0000" } },
      fpsLimit: 60,
      particles: {
        color: { value: "#66ccff" },
        links: { color: "#66ccff", distance: 130, enable: true, opacity: .25, width: 1 },
        move: { enable: true, speed: .4, outModes: "bounce" },
        number: { value: 80, density: { enable: true, area: 800 } },
        opacity: { value: .4 },
        shape: { type: "circle" },
        size: { value: { min: 1, max: 3 } }
      },
      detectRetina: true
    });
  };
  document.head.appendChild(s);
}

document.addEventListener("DOMContentLoaded", () => {
  renderHeader();
  loadParticles();
});