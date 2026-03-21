/* ── canvas bg ── */
(function(){
  const c=document.getElementById('bg'),x=c.getContext('2d');
  let W,H,pts;
  function resize(){W=c.width=window.innerWidth;H=c.height=window.innerHeight}
  function init(){pts=Array.from({length:40},()=>({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.15,vy:(Math.random()-.5)*.15,r:Math.random()*.8+.3}))}
  function draw(){
    x.clearRect(0,0,W,H);
    pts.forEach(p=>{
      x.beginPath();x.arc(p.x,p.y,p.r,0,Math.PI*2);
      x.fillStyle='rgba(74,222,128,.5)';x.fill();
      p.x+=p.vx;p.y+=p.vy;
      if(p.x<0)p.x=W;if(p.x>W)p.x=0;
      if(p.y<0)p.y=H;if(p.y>H)p.y=0;
    });
    for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){
      const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);
      if(d<120){x.beginPath();x.moveTo(pts[i].x,pts[i].y);x.lineTo(pts[j].x,pts[j].y);
        x.strokeStyle=`rgba(74,222,128,${.04*(1-d/120)})`;x.lineWidth=.5;x.stroke();}
    }
    requestAnimationFrame(draw);
  }
  window.addEventListener('resize',()=>{resize();init()});
  resize();init();draw();
})();

/* ── state ── */
let ws = null;
let currentResult = null;
let history = JSON.parse(localStorage.getItem('nmapx_history') || '[]');
let activeProfile = 'fast';

const PROFILE_TAGS = {
  fast:'T4 -F', full:'T4 -A -p-', stealth:'sS -T2',
  udp:'sU', vuln:'vuln', ping:'sn', version:'sV', custom:'...'
};

/* ── profiles ── */
fetch('/profiles').then(r=>r.json()).then(profiles=>{
  const grid = document.getElementById('profile-grid');
  Object.entries(profiles).forEach(([key, label]) => {
    const btn = document.createElement('button');
    btn.className = 'profile-btn' + (key === activeProfile ? ' active' : '');
    btn.innerHTML = `<span>${label}</span><span class="profile-tag">${PROFILE_TAGS[key]||''}</span>`;
    btn.dataset.key = key;
    btn.addEventListener('click', () => {
      document.querySelectorAll('.profile-btn').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      activeProfile = key;
      document.getElementById('custom-section').classList.toggle('hidden', key !== 'custom');
    });
    grid.appendChild(btn);
  });
});

/* ── terminal ── */
const term = document.getElementById('terminal');

function termLine(text, cls='') {
  const line = document.createElement('div');
  line.className = 'term-line' + (cls ? ' '+cls : '');
  line.textContent = text;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function termClear() { term.innerHTML = ''; }

document.getElementById('btn-clear').addEventListener('click', termClear);

function classifyLine(line) {
  const l = line.toLowerCase();
  if (l.includes('open') || l.startsWith('nmap scan report')) return 'info';
  if (l.includes('filtered') || l.includes('warn')) return 'warn';
  if (l.includes('error') || l.includes('failed')) return 'err';
  return '';
}

/* ── scan ── */
document.getElementById('btn-scan').addEventListener('click', startScan);
document.getElementById('target').addEventListener('keydown', e => { if(e.key==='Enter') startScan(); });

function startScan() {
  const target = document.getElementById('target').value.trim();
  if (!target) { termLine('No target specified.', 'err'); return; }
  if (ws) ws.close();

  termClear();
  document.getElementById('results').classList.add('hidden');
  document.getElementById('analysis-panel').classList.add('hidden');
  document.getElementById('sidebar-stats').classList.remove('hidden');
  document.getElementById('btn-scan').disabled = true;
  document.getElementById('btn-stop').classList.remove('hidden');
  resetStats();

  ws = new WebSocket(`ws://${location.host}/ws/scan`);

  ws.onopen = () => ws.send(JSON.stringify({
    target, profile: activeProfile,
    custom_flags: document.getElementById('custom-flags').value.trim(),
  }));

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'start') {
      document.getElementById('terminal-title').textContent = msg.cmd;
      termLine('$ ' + msg.cmd, 'cmd');
      termLine('');
    } else if (msg.type === 'output') {
      termLine(msg.line, classifyLine(msg.line));
    } else if (msg.type === 'done') {
      currentResult = msg.result;
      renderResults(msg.result);
      updateStats(msg.result);
      saveHistory(target, activeProfile, msg.result);
      termLine('\n✓ Scan complete.', 'info');
      scanDone();
    } else if (msg.type === 'error') {
      termLine('Error: ' + msg.msg, 'err');
      scanDone();
    }
  };

  ws.onerror = () => { termLine('Connection error.', 'err'); scanDone(); };
  ws.onclose = () => scanDone();
}

document.getElementById('btn-stop').addEventListener('click', () => {
  if (ws) ws.close();
  termLine('Scan stopped.', 'warn');
  scanDone();
});

function scanDone() {
  document.getElementById('btn-scan').disabled = false;
  document.getElementById('btn-stop').classList.add('hidden');
  ws = null;
}

function resetStats() {
  ['stat-up','stat-ports','stat-time'].forEach(id => document.getElementById(id).textContent = '—');
}

function updateStats(result) {
  const hosts = result.hosts || [];
  document.getElementById('stat-up').textContent    = hosts.length;
  document.getElementById('stat-ports').textContent = hosts.reduce((s,h)=>s+h.open_count,0);
  document.getElementById('stat-time').textContent  = result.stats?.elapsed || '—';
}

/* ── render results ── */
function renderResults(result) {
  const hosts = result.hosts || [];
  const grid  = document.getElementById('hosts-grid');
  grid.innerHTML = '';

  if (!hosts.length) {
    grid.innerHTML = `<div class="empty-state"><span>◌</span><span>No hosts found in this scan</span></div>`;
    document.getElementById('results').classList.remove('hidden');
    return;
  }

  hosts.forEach(host => {
    const card = document.createElement('div');
    card.className = 'host-card';

    const names = host.hostnames.join(', ');
    const badges = [
      host.open_count     ? `<span class="badge open">${host.open_count} open</span>` : '',
      host.filtered_count ? `<span class="badge filtered">${host.filtered_count} filtered</span>` : '',
      host.rtt            ? `<span class="badge rtt">${host.rtt}</span>` : '',
    ].join('');

    card.innerHTML = `
      <div class="host-header">
        <div class="host-status-dot"></div>
        <div>
          <div class="host-ip">${host.ip}</div>
          ${names ? `<div class="host-name">${names}</div>` : ''}
        </div>
        ${host.os ? `<span class="host-os">${host.os}</span>` : ''}
        <div class="host-right">
          ${badges}
          <span class="chevron">▾</span>
        </div>
      </div>
      <div class="host-body">
        ${renderPortsTable(host.ports)}
      </div>
    `;

    card.querySelector('.host-header').addEventListener('click', () => {
      card.classList.toggle('collapsed');
      card.querySelector('.host-body').style.display =
        card.classList.contains('collapsed') ? 'none' : '';
    });

    grid.appendChild(card);
  });

  document.getElementById('results').classList.remove('hidden');
}

function renderPortsTable(ports) {
  if (!ports.length) return `<div class="empty-state" style="height:80px"><span style="font-size:1rem">—</span><span>No ports found</span></div>`;

  const rows = ports.map(p => {
    const stateCls = p.state === 'open' ? 'state-open' : p.state === 'filtered' ? 'state-filtered' : 'state-closed';
    const version  = [p.product, p.version, p.extra].filter(Boolean).join(' ');
    const scripts  = p.scripts.map(s =>
      `<div class="script-output"><span class="script-id">[${s.id}]</span>${s.output}</div>`
    ).join('');

    return `<tr>
      <td class="port-num">${p.port}<span style="color:var(--text3);font-weight:400">/${p.proto}</span></td>
      <td><span class="state-pill ${stateCls}">${p.state}</span></td>
      <td>
        <div class="svc-row">
          <span class="svc-dot" style="background:${p.color}"></span>
          <span class="svc-name">${p.service || '—'}</span>
        </div>
        ${version ? `<div class="svc-detail">${version}</div>` : ''}
        ${scripts}
      </td>
    </tr>`;
  }).join('');

  return `<table class="ports-table">
    <thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

/* ── AI analysis ── */
document.getElementById('btn-analyze').addEventListener('click', async () => {
  if (!currentResult) return;
  const panel  = document.getElementById('analysis-panel');
  const loader = document.getElementById('analysis-loader');
  const body   = document.getElementById('analysis-body');

  panel.classList.remove('hidden');
  loader.classList.remove('hidden');
  body.innerHTML = '';

  try {
    const r = await fetch('/analyze', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({scan_result: currentResult}),
    });
    const d = await r.json();
    loader.classList.add('hidden');
    body.innerHTML = markdownToHtml(d.analysis);
  } catch(e) {
    loader.classList.add('hidden');
    body.innerHTML = `<span style="color:var(--red)">Error: ${e.message}</span>`;
  }
});

document.getElementById('btn-close-analysis').addEventListener('click', () =>
  document.getElementById('analysis-panel').classList.add('hidden'));

/* ── export ── */
document.getElementById('btn-export').addEventListener('click', () => {
  if (!currentResult) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(currentResult,null,2)],{type:'application/json'}));
  a.download = `nmapx_${Date.now()}.json`;
  a.click();
});

/* ── history ── */
function saveHistory(target, profile, result) {
  history.unshift({target, profile, time: new Date().toLocaleTimeString(), hosts: result.hosts?.length||0, result});
  if (history.length > 8) history.pop();
  localStorage.setItem('nmapx_history', JSON.stringify(history));
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById('history-list');
  list.innerHTML = '';
  if (!history.length) return;
  document.getElementById('history-section').style.display = '';

  history.forEach(h => {
    const el = document.createElement('div');
    el.className = 'history-item';
    el.innerHTML = `
      <div class="history-target">${h.target}</div>
      <div class="history-meta">${h.time} · ${h.profile} · ${h.hosts} host${h.hosts!==1?'s':''}</div>
    `;
    el.addEventListener('click', () => {
      currentResult = h.result;
      renderResults(h.result);
      updateStats(h.result);
      document.getElementById('sidebar-stats').classList.remove('hidden');
      document.getElementById('target').value = h.target;
    });
    list.appendChild(el);
  });
}

renderHistory();

/* ── markdown ── */
function markdownToHtml(md) {
  return md
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/^### (.+)$/gm,'<h3>$1</h3>')
    .replace(/^## (.+)$/gm,'<h2>$1</h2>')
    .replace(/^# (.+)$/gm,'<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/`([^`]+)`/g,'<code>$1</code>')
    .replace(/^- (.+)$/gm,'<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g,'<ul>$&</ul>')
    .replace(/\n\n/g,'<br><br>')
    .replace(/\n/g,'<br>');
}
