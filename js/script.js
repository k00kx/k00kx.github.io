const usernames=["cybersec","pentest","gh0st","redteam","kali","root"];
const skullSymbol="㉿";
const switchUserInterval=5000;
let animationTimeouts=[];

/* util ---------------------------------------------------*/
const r=(min,max)=>Math.floor(Math.random()*(max-min))+min;
const getRandomUsername=()=>usernames[r(0,usernames.length)];
function getCurrentDirectory(){
  const parts=location.pathname.split("/").filter(Boolean);
  const idx=parts.indexOf("writeups");
  if(idx!==-1) return parts.slice(idx).map(p=>p.replace(".html","")).join("/");
  const file=parts.pop()||"Desktop.html";
  return file.replace(".html","")||"Desktop";
}

/* header -------------------------------------------------*/
function clearAnims(){animationTimeouts.forEach(clearTimeout);animationTimeouts=[];}
function animateUsername(newName){
  const el=document.getElementById("username"); if(!el) return;
  clearAnims(); let i=0,cur=el.textContent;
  const back=()=>{ if(i<cur.length){el.textContent=cur.slice(0,cur.length-i-1);i++;animationTimeouts.push(setTimeout(back,60));}else{ i=0; type();}};
  const type=()=>{ if(i<newName.length){el.textContent+=newName[i++];animationTimeouts.push(setTimeout(type,100));}};
  back();
}
function toggleSubmenu(id){
  const box=document.getElementById(id);
  box.style.display=box.style.display==="block"?"none":"block";
}
function renderHeader(){
  const user=getRandomUsername();
  document.getElementById("header-container").innerHTML=`
    <div class="terminal-header">
      <div class="terminal-line">
        <span class="red">root</span><span class="skull">${skullSymbol}</span>
        <span id="username" class="blue">${user}</span>:~$
        <span id="directory-path">/home/k00kx/${getCurrentDirectory()}</span>
      </div>
      <div class="cursor-line"><span class="cursor"></span></div>

      <nav class="nav-links">
        <div class="dropdown">
          <button class="dropbtn">Writeups</button>
          <div class="dropdown-content">
            <div class="submenu">
              <span onclick="toggleSubmenu('htb-links')">HackTheBox</span>
              <div class="links" id="htb-links">
                <a href="/writeups/htb/puppy.html">Puppy</a>
              </div>
            </div>
            <div class="submenu">
              <span onclick="toggleSubmenu('thm-links')">TryHackMe</span>
              <div class="links" id="thm-links"></div>
            </div>
          </div>
        </div>
      </nav>
      <hr class="separator">
    </div>`;
  animateUsername(user);
  setInterval(()=>animateUsername(getRandomUsername()),switchUserInterval);
}

/* particles ----------------------------------------------*/
function loadParticles(){
  if(!document.getElementById("tsparticles")||window.tsLoaded) return;
  const s=document.createElement("script");
  s.src="https://cdn.jsdelivr.net/npm/tsparticles@2/tsparticles.bundle.min.js";
  s.onload=()=>{
    window.tsLoaded=true;
    tsParticles.load("tsparticles",{
      background:{color:{value:"#0000"}},
      fpsLimit:60,
      particles:{
        color:{value:"#66ccff"},
        links:{color:"#66ccff",distance:130,enable:true,opacity:.25,width:1},
        move:{enable:true,speed:.4,outModes:"bounce"},
        number:{value:80,density:{enable:true,area:800}},
        opacity:{value:.4},
        shape:{type:"circle"},
        size:{value:{min:1,max:3}}
      },
      detectRetina:true
    });
  };
  document.head.appendChild(s);
}

/* init ----------------------------------------------------*/
document.addEventListener("DOMContentLoaded",()=>{
  renderHeader();
  loadParticles();
});