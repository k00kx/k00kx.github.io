const usernames = [
  "cybersec", "pentest", "gh0st", "redteam", "kali", "root"
];
const skullSymbol = "㉿";
const switchUserInterval = 5000;

let animationTimeouts = [];

function getRandomUsername() {
  return usernames[Math.floor(Math.random() * usernames.length)];
}

function getCurrentDirectory() {
  const path = window.location.pathname;
  const parts = path.split("/").filter(Boolean);
  const writeupsIndex = parts.indexOf("writeups");

  if (writeupsIndex !== -1) {
    const relevantPath = parts.slice(writeupsIndex).map(p => p.replace(".html", ""));
    return relevantPath.join("/");
  }

  const file = parts.pop() || "Desktop.html";
  return file.replace(".html", "") || "Desktop";
}

function clearAnimationTimeouts() {
  animationTimeouts.forEach(clearTimeout);
  animationTimeouts = [];
}

function animateUsernameChange(username) {
  const el = document.getElementById("username");
  if (!el) return;

  clearAnimationTimeouts();
  let current = el.textContent;
  let step = 0;

  function backspace() {
    if (step < current.length) {
      el.textContent = current.slice(0, current.length - step - 1);
      step++;
      animationTimeouts.push(setTimeout(backspace, 60));
    } else {
      step = 0;
      el.textContent = "";
      typeNew(username);
    }
  }

  function typeNew(newText) {
    if (step < newText.length) {
      el.textContent += newText.charAt(step);
      step++;
      animationTimeouts.push(setTimeout(() => typeNew(newText), 100));
    }
  }

  backspace();
}

function toggleSubmenu(id) {
  const submenu = document.getElementById(id);
  submenu.style.display = submenu.style.display === "block" ? "none" : "block";
}

function renderHeader() {
  const username = getRandomUsername();
  const currentDir = getCurrentDirectory();

  const headerHTML = `
    <div class="terminal-header">
      <div class="terminal-line">
        <span class="red">root</span><span class="skull">${skullSymbol}</span><span id="username" class="blue">${username}</span>:~$
        <span id="directory-path">/home/k00kx/${currentDir}</span>
      </div>
      <div class="cursor-line"><span class="cursor"></span></div>

      <nav class="nav-links">
        <div class="dropdown">
          <button class="dropbtn">Writeups</button>
          <div class="dropdown-content">
            <div class="submenu">
              <span onclick="toggleSubmenu('htb-links')">HackTheBox</span>
              <div class="links" id="htb-links" style="display: none;">
              <a href="/writeups/htb/puppy.html">Puppy</a>
              </div>
            </div>
            <div class="submenu">
              <span onclick="toggleSubmenu('thm-links')">TryHackMe</span>
              <div class="links" id="thm-links" style="display: none;">
              </div>
            </div>
          </div>
        </div>
      </nav>

      <hr class="separator" />
    </div>
  `;

  document.getElementById("header-container").innerHTML = headerHTML;
  animateUsernameChange(username);
  setInterval(() => {
    const next = getRandomUsername();
    animateUsernameChange(next);
  }, switchUserInterval);
}

window.onload = () => {
  renderHeader();
};

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("tsparticles")) {
    const script = document.createElement("script");
    script.src = "https://cdn.jsdelivr.net/npm/tsparticles@2/tsparticles.bundle.min.js";
    script.onload = () => {
      tsParticles.load("tsparticles", {
        background: { color: { value: "#00000000" } },
        fpsLimit: 60,
        particles: {
          color: { value: "#66ccff" },
          links: {
            color: "#66ccff",
            distance: 130,
            enable: true,
            opacity: 0.25,
            width: 1
          },
          move: {
            enable: true,
            speed: 0.4,
            direction: "none",
            outModes: "bounce"
          },
          number: {
            value: 80,
            density: {
              enable: true,
              area: 800
            }
          },
          opacity: { value: 0.4 },
          shape: { type: "circle" },
          size: { value: { min: 1, max: 3 } }
        },
        detectRetina: true
      });
    };
    document.head.appendChild(script);
  }
});