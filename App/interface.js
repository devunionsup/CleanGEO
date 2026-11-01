/* CleanGEO — ინტერფეისი (ქართული). ყველა მონაცემი Swift-ის ბრიჯიდან მოდის. */
"use strict";
const $=q=>document.querySelector(q);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const P={
shield:'<path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/><path d="M9 12l2 2 4-4"/>',
check:'<path d="M5 12.5l4.5 4.5L19 7.5"/>',home:'<path d="M4 11l8-7 8 7v8a1 1 0 0 1-1 1h-4v-6h-6v6H5a1 1 0 0 1-1-1z"/>',
chart:'<path d="M5 20V10M12 20V4M19 20v-7"/>',
globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
filter:'<path d="M4 6h16M7 12h10M10 18h4"/>',dots:'<circle cx="6" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="18" cy="12" r="1.2"/>',
back:'<path d="M15 5l-7 7 7 7"/>',chev:'<path d="M9 5l7 7-7 7"/>',
ban:'<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
eye:'<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/>',
warn:'<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17.5v.1"/>',
compass:'<circle cx="12" cy="12" r="9"/><path d="M15.5 8.5l-2 5-5 2 2-5z"/>',
lock:'<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
trash:'<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',plus:'<path d="M12 5v14M5 12h14"/>',
refresh:'<path d="M20 11a8 8 0 0 0-14-4L4 9M4 4v5h5M4 13a8 8 0 0 0 14 4l2-2M20 20v-5h-5"/>',
clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
list:'<path d="M8 6h12M8 12h12M8 18h12M4 6h.1M4 12h.1M4 18h.1"/>',
info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.1"/>',
bell:'<path d="M6 17V11a6 6 0 0 1 12 0v6l2 2H4zM10 21h4"/>',
srv:'<rect x="4" y="4" width="16" height="6" rx="2"/><rect x="4" y="14" width="16" height="6" rx="2"/><path d="M8 7h.1M8 17h.1"/>',
moon:'<path d="M20 14A8 8 0 0 1 10 4a8 8 0 1 0 10 10z"/>',
user:'<circle cx="12" cy="8" r="4"/><path d="M4 20c1-4 4-6 8-6s7 2 8 6"/>',
bug:'<rect x="8" y="7" width="8" height="12" rx="4"/><path d="M12 7V4M4 12h4M16 12h4M5 18l3-2M19 18l-3-2"/>'};
const ic=(n,c)=>`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" ${c?`class="${c}"`:""}>${P[n]||""}</svg>`;

/* ---------- ბრიჯი ---------- */
const S={vpn:{power:false,mode:"dns",dnsOnly:true,status:"idle",statusText:"",node:null,connectedSince:null,bytesUp:0,bytesDown:0,lastError:null},
safari:{enabled:false,rules:0,lastUpdate:null,updating:false},
stats:{adsBlocked:0,trackersBlocked:0,queries:0,week:[0,0,0,0,0,0,0],topBlocked:[]},
dns:{doh:"",dot:"",dnssec:true,validating:false,lastLatency:null,ok:null},
filters:[],activity:[],schedule:{mode:"interval",hours:12,last:null,next:null,wifiOnly:true},
settings:{dark:"auto",updateAutomatically:true,icloudSync:false,notifications:false}};
let seq=0;const pend=new Map();
function post(name,payload={},cb){const id="r"+(++seq);pend.set(id,cb||(()=>{}));
  try{window.webkit.messageHandlers.interface.postMessage({id,name,payload});}
  catch(e){/* WebView-გარე ხედი */ pend.delete(id);}}
window.__reply=(id,ok,data)=>{const cb=pend.get(id);pend.delete(id);cb&&cb(ok,data);};
window.__state=s=>{Object.assign(S.vpn,s.vpn||{});Object.assign(S.safari,s.safari||{});Object.assign(S.stats,s.stats||{});Object.assign(S.dns,s.dns||{});Object.assign(S.schedule,s.schedule||{});Object.assign(S.settings,s.settings||{});
  if(s.filters)S.filters=s.filters;if(s.activity)S.activity=s.activity;refresh();};
window.__toast=m=>toast(m);

/* ---------- UI ბირთვი ---------- */
let route="home";
function toast(m){const t=$("#toast");t.textContent=m;t.classList.add("s");clearTimeout(t._h);t._h=setTimeout(()=>t.classList.remove("s"),2400);}
function sheet(html){$("#sc").innerHTML='<div class="gr"></div>'+html;$("#sh").classList.add("o");$("#dock").classList.add("h");}
function closeSheet(){$("#sh").classList.remove("o");$("#dock").classList.remove("h");}
document.addEventListener("click",e=>{
  const a=e.target.closest("[data-a]"),g=e.target.closest("[data-go]");
  if(g){const[,r]=g.dataset.go.split(":");nav(r);return;}
  if(!a)return;const act=a.dataset.a;
  const act2=act.split(":");const fn=ACTIONS[act2[0]];fn&&fn(act2[1],a);});
const ACTIONS={
  cs:closeSheet,
  togglePower(){post("togglePower",{},(ok,d)=>{if(!ok&&d&&d.msg)toast(d.msg);});},
  setMode(m){S.vpn.mode=m;render();post("setMode",{mode:m});},
  toggleSafari(){post("toggleSafari",{},(ok,d)=>{if(!ok&&d&&d.msg)toast(d.msg);});},
  updateNow(){S.safari.updating=true;render();post("updateFilters",{},()=>{S.safari.updating=false;refresh();});},
  ftoggle(id){const f=S.filters.find(x=>x.id===id);if(!f)return;f.enabled=!f.enabled;render();post("setFilter",{id:id,enabled:f.enabled});},
  fopen(id){openFilter(id);},
  fsync(){toast("ფილტრების განახლება…");post("updateFilters",{},(ok,d)=>toast(ok?"ფილტრები განახლდა":(d&&d.msg||"ვერ განახლდა")));},
  refreshStats(){post("refreshStats",{},()=>toast("სტატისტიკა განახლდა"));},
  day(n){sheetDay(n);},
  clearStats(){sheetClearStats();},
  dnsSave(){const d=$("#doh").value.trim(),t=$("#dot").value.trim();post("setDNS",{doh:d,dot:t},(ok,d2)=>toast(ok?"DNS შენახულია":(d2&&d2.msg||"არასწორი მისამართი")));},
  dnsTest(){post("testDNS",{},()=>{});},
  dnssec(){S.dns.dnssec=!S.dns.dnssec;render();post("setDNSSEC",{on:S.dns.dnssec});},
  schMode(m){S.schedule.mode=m;render();post("setSchedule",{mode:m,hours:S.schedule.hours,wifiOnly:S.schedule.wifiOnly});},
  schHours(h){S.schedule.hours=+h;render();post("setSchedule",{mode:S.schedule.mode,hours:+h,wifiOnly:S.schedule.wifiOnly});},
  schWifi(){S.schedule.wifiOnly=!S.schedule.wifiOnly;render();post("setSchedule",{mode:S.schedule.mode,hours:S.schedule.hours,wifiOnly:S.schedule.wifiOnly});},
  theme(v){S.settings.dark=v;applyTheme();render();post("setTheme",{dark:v});},
  autoUp(){S.settings.updateAutomatically=!S.settings.updateAutomatically;render();post("setSetting",{key:"updateAutomatically",value:S.settings.updateAutomatically});},
  icloud(){S.settings.icloudSync=!S.settings.icloudSync;render();post("setSetting",{key:"icloudSync",value:S.settings.icloudSync});},
  notif(){S.settings.notifications=!S.settings.notifications;render();post("setSetting",{key:"notifications",value:S.settings.notifications});},
  howto(){sheetHowto();},
  log(){sheetLog();},
  nodePick(){sheetNodes();},
  nodeUse(id){S.vpn.node=id;render();post("setNode",{id:id});closeSheet();toast("სერვერი არჩეულია");},
  fdel(id){post("removeFilter",{id:id},()=>{});S.filters=S.filters.filter(f=>f.id!==id);closeSheet();render();},
  faddOpen(){sheet(`<h3 style="margin-top:0">ფილტრის დამატება</h3>
  <div class="pd" style="padding:0 0 12px"><div class="lb" style="margin-bottom:6px">URL</div>
  <input id="furl" placeholder="https://example.ge/list.txt" autocapitalize="off" autocorrect="off" spellcheck="false">
  <div class="lb" style="margin:12px 0 6px">სახელი (არასავალდებულო)</div>
  <input id="fname" placeholder="ჩემი ფილტრი"></div>
  <div class="ar"><button class="btn" data-a="fadd">დამატება</button><button class="btn s" data-a="cs">გაუქმება</button></div>`);
    setTimeout(()=>{const el=$("#furl");el&&el.focus();},60);},
  fadd(){const u=$("#furl").value.trim();if(!u)return toast("მიუთითე URL");post("addFilter",{url:u,name:$("#fname").value.trim()||u.split("/").pop()},(ok,d)=>{if(ok){closeSheet();toast("დაემატა");}else toast(d&&d.msg||"ვერ დაემატა");});}
};

/* ---------- ნავიგაცია ---------- */
const TABS=[["home","home","მთავარი"],["vpn","globe","VPN"],["filters","filter","ფილტრები"],["dns","compass","DNS"],["stats","chart","სტატისტიკა"],["settings","user","პარამეტრები"]];
function renderDock(){const act=["home","vpn","dns","stats","settings"];
  $("#dock").innerHTML=act.map(t=>{const[x,i,l]=TABS.find(z=>z[0]===t);
    if(x==="stats")return `<button class="tab ${route===x?"on":""}" data-go="tab:${x}">${ic(i)}<span>${l}</span></button>`
      +`<button class="cb ${route==="filters"?"on":""}" data-go="tab:filters" aria-label="ფილტრები">${ic("filter")}</button>`;
    return `<button class="tab ${route===x?"on":""}" data-go="tab:${x}">${ic(i)}<span>${l}</span></button>`;}).join("");
  $("#dock").classList.toggle("h",route==="filters");}
function nav(r){if(!TABS.some(t=>t[0]===r))return;route=r;render();}
function refresh(){render();}

/* ---------- ფორმატი ---------- */
const nf=new Intl.NumberFormat("ka-GE");
const fmtN=n=>nf.format(n||0);
function fmtBytes(b){b=b||0;if(b<1024)return b+" B";const u=["KB","MB","GB","TB"];let i=-1;do{b/=1024;i++}while(b>=1024&&i<3);return b.toFixed(1)+" "+u[i];}
function fmtTime(t){if(!t)return "—";try{return new Date(t).toLocaleString("ka-GE",{day:"numeric",month:"short",hour:"2-digit",minute:"2-digit"})}catch(e){return t}}
function fmtSince(t){if(!t)return "—";const s=(Date.now()-new Date(t).getTime())/1e3;if(s<60)return Math.floor(s)+" წმ";if(s<3600)return Math.floor(s/60)+" წთ";if(s<86400)return Math.floor(s/3600)+" სთ";return Math.floor(s/86400)+" დღე";}
const DAYS=["ორშ","სამ","ოთხ","ხუთ","პარ","შაბ","კვ"];

/* ---------- გვერდები ---------- */
function render(){
  const st={connecting:"დაკავშირება…",connected:"დაკავშირებულია",disconnecting:"აუცილებელია…",disconnected:"გათიშულია",idle:"გამორთული",invalid:"მიუწვდომელია"}[S.vpn.status]||"გამორთული";
  const on=["connected","connecting"].includes(S.vpn.status);
  renderDock();
  const M=$("#main");
  if(route==="home")M.innerHTML=pgHome(st,on);
  else if(route==="vpn")M.innerHTML=pgVPN(st,on);
  else if(route==="filters")M.innerHTML=pgFilters();
  else if(route==="dns")M.innerHTML=pgDNS();
  else if(route==="stats")M.innerHTML=pgStats();
  else M.innerHTML=pgSettings();
  M.scrollTop=0;
}
function pgHome(st,on){const s=S.stats;const max=Math.max(1,...s.week);
  return `<div class="pg">
  <div class="nb"><h1>მთავარი</h1><button class="bk" data-a="howto" style="display:grid;width:40px;height:40px">${ic("info")}</button></div>
  <div class="top"><div class="brand"><i>${ic("shield")}</i>CleanGEO</div><span class="bg ${on?"ok":"off"}">${on?"აქტიურია":"პასიური"}</span></div>
  <div class="gw"><button class="gl" data-a="togglePower" aria-label="ჩართვა/გამორთვა">
    <span class="w" style="top:${on?"15%":"110%"}"></span><span class="w" style="top:${on?"45%":"140%"}"></span>
    <div>${ic("shield")}${on?`<b>${s.adsBlocked>=1000?(s.adsBlocked/1000).toFixed(1)+"k":fmtN(s.adsBlocked)}</b><small>დაიბლოკა</small>`:`<b>${on?"":"—"}</b><small>დააჭირე ჩასართავად</small>`}</div></button></div>
  <div class="st">${st}</div><p>${S.vpn.dnsOnly?"DNS-დაცვა":"სრული ტუნელი"} · ${S.vpn.lastError?esc(S.vpn.lastError):(S.dns.ok===false?"DNS ვერ შემოწმდა":"ყველაფერი მუშაობს")}</p>
  <div class="pw"><button class="${S.vpn.mode==="dns"?"on":""}" data-a="setMode:dns">მხოლოდ DNS</button><button class="${S.vpn.mode==="tunnel"?"on o":""}" data-a="setMode:tunnel">სრული ტუნელი</button></div>
  <h3>დაცვის სტატუსი</h3>
  <div class="cd">
    <div class="row" data-go="tab:filters"><span class="ic">${ic("filter")}</span><span class="rt"><b>Safari-ს ფილტრები</b><small>${S.safari.updating?"განახლება…":fmtN(S.safari.rules)+" წესი აქტიურია"}</small></span>
      <span class="bg ${S.safari.enabled?"ok":"off"}">${S.safari.enabled?"ჩართული":"გამორთული"}</span>${ic("chev","")}</div>
    <div class="row" data-go="tab:dns"><span class="ic ${S.dns.ok===false?"r":"g"}">${ic(S.dns.ok===false?"warn":"compass")}</span><span class="rt"><b>DNS რეზოლვერი</b><small>${esc(S.dns.doh||"მისამართი მითითებული არაა")}</small></span>
      <span class="bg ${S.dns.ok===false?"bd":(S.dns.ok?"ok":"off")}">${S.dns.ok===false?"ვერ პასუხობს":S.dns.ok?"მუშაობს":"—"}</span>${ic("chev","")}</div>
    <div class="row" data-go="tab:vpn"><span class="ic ${on?"g":""}">${ic("globe")}</span><span class="rt"><b>VPN ტუნელი</b><small>${esc(S.vpn.node?S.vpn.node.name:"სერვერი არჩეული არაა")}</small></span>
      <span class="bg ${on?"ok":"off"}">${st}</span>${ic("chev","")}</div>
  </div>
  <h3>აქტივობა</h3>
  <div class="cd"><div class="pd">
    <div class="g2" style="margin:0">
      <div><div class="nm">${fmtN(s.adsBlocked)}</div><div class="lb">რეკლამა დაიბლოკა</div></div>
      <div><div class="nm">${fmtN(s.trackersBlocked)}</div><div class="lb">თრექერი დაიბლოკა</div></div>
    </div>
    <div class="bars">${s.week.map((v,i)=>`<div><i style="height:${Math.max(4,v/max*100)}%"></i>${DAYS[i]}</div>`).join("")}</div>
  </div></div>
  ${S.activity.length?`<h3>უახლესი მოქმედებები</h3><div class="cd">${S.activity.slice(0,4).map(a=>`<div class="row"><span class="ic ${a.kind==="blocked"?"r":""}">${ic(a.kind==="blocked"?"ban":a.kind==="update"?"refresh":"check")}</span><span class="rt"><b>${esc(a.title)}</b><small>${fmtTime(a.at)}</small></span></div>`).join("")}</div>`:""}
  </div>`;}
function pgVPN(st,on){const up=S.vpn.bytesUp,dn=S.vpn.bytesDown;
  return `<div class="pg">
  <div class="nb"><button class="bk" data-go="tab:home">${ic("back")}</button><h1>VPN ტუნელი</h1></div>
  <div class="gw"><button class="gl" data-a="togglePower"><span class="w" style="top:${on?"15%":"110%"}"></span><span class="w" style="top:${on?"45%":"140%"}"></span>
    <div>${ic("globe")}<b>${up+dn>0?fmtBytes(up+dn):"VPN"}</b><small>${on?"ტუნელი აქტიურია":"გამორთულია"}</small></div></button></div>
  <div class="st">${st}</div><p>${on?("უკავშირდება "+esc(S.vpn.node?S.vpn.node.name:"")):"დააჭირე ღილაკს დასაკავშირებლად"}</p>
  ${S.vpn.lastError?`<div class="dm">${ic("warn")}<span>${esc(S.vpn.lastError)}</span></div>`:""}
  <div class="cd"><div class="pd">
    <div style="display:flex;justify-content:space-between;margin-bottom:6px"><b>ტრაფიკი</b><span class="lb">${fmtBytes(dn)} ↓ / ${fmtBytes(up)} ↑</span></div>
    <div class="stk"><i style="width:62%;background:var(--ac)"></i><i style="width:22%;background:var(--a2)"></i><i style="width:16%;background:var(--sp)"></i></div>
    <div class="lb" style="display:flex;gap:14px;margin-top:6px"><span><span class="dt" style="background:var(--ac);display:inline-block"></span> ჩამოტვირთვა</span><span><span class="dt" style="background:var(--a2);display:inline-block"></span> ატვირთვა</span></div>
  </div></div>
  <div class="cd">
    <div class="row" data-a="nodePick"><span class="ic">${ic("srv")}</span><span class="rt"><b>სერვერი</b><small>${esc(S.vpn.node?S.vpn.node.name+" — "+S.vpn.node.flag:"აირჩიე")}</small></span><span class="r2">${ic("chev")}</span></div>
    <div class="row"><span class="ic">${ic("clock")}</span><span class="rt"><b>კავშირის ხანგრძლივობა</b><small>${fmtSince(S.vpn.connectedSince)}</small></span></div>
    <div class="row"><span class="ic">${ic("lock")}</span><span class="rt"><b>დაშიფვრა</b><small>${S.vpn.dnsOnly?"DNS-over-TLS ტუნელში":"ChaCha20-Poly1305"}</small></span><span class="bg ok">${S.vpn.dnsOnly?"DNS":"AES/ChaCha"}</span></div>
  </div>
  <div class="pd" style="padding:0 2px"><button class="btn ${on?"d":""}" data-a="togglePower">${on?"გათიშვა":"დაკავშირება"}</button></div>
  </div>`;}
function pgFilters(){const total=S.filters.length,en=S.filters.filter(f=>f.enabled).length;
  return `<div class="pg">
  <div class="nb"><button class="bk" data-go="tab:home">${ic("back")}</button><h1>ფილტრები</h1></div>
  <div class="cd"><div class="row" style="padding:16px"><span class="ic">${ic("eye")}</span><span class="rt"><b>Safari-ს კონტენტ-ბლოკერი</b><small>${S.safari.enabled?"აქტიურია სისტემაში":"ჩართე პარამეტრებში"}</small></span>
    <button class="tg ${S.safari.enabled?"on":""}" data-a="toggleSafari" aria-label="Safari"></button></div>
    <div class="row"><span class="ic">${ic("list")}</span><span class="rt"><b>წესები</b><small>${fmtN(S.safari.rules)} ჩატვირთული</small></span></div></div>
  <div class="ar"><button class="btn" data-a="updateNow">${S.safari.updating?'<span class="sp" style="display:inline-block">'+ic("refresh")+"</span> განახლება…":"განახლება ახლავე"}</button><button class="btn s" data-a="faddOpen">${ic("plus","")}</button></div>
  <div class="cd">${S.filters.length?S.filters.map(f=>`<div class="row" data-a="fopen:${esc(f.id)}"><span class="ic ${f.enabled?"":"r"}">${ic(f.enabled?"check":"ban")}</span>
    <span class="rt"><b>${esc(f.name)}</b><small>${f.ok===false?"ვერ ჩაიტვირთა":fmtTime(f.updated)}</small></span>
    <button class="tg ${f.enabled?"on":""}" data-a="ftoggle:${esc(f.id)}"></button></div>`).join(""):
    '<div class="em">ფილტრები არ არის — დააჭირე „განახლებას“</div>'}</div>
  <div class="pd" style="padding:0 2px"><button class="btn s" data-a="fsync">${ic("refresh","")} ფილტრების სრული სინქრონი</button></div>
  </div>`;}
function pgDNS(){const d=S.dns;
  return `<div class="pg">
  <div class="nb"><button class="bk" data-go="tab:home">${ic("back")}</button><h1>DNS</h1></div>
  <div class="cd"><div class="pd">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px"><span class="ic ${d.ok===false?"r":"g"}">${ic(d.ok===false?"warn":"shield")}</span>
    <div><b>${d.ok===false?"სერვერი არ პასუხობს":d.ok?"დაცვა აქტიურია":"სტატუსი უცნობია"}</b><div class="lb">${d.lastLatency!=null?d.lastLatency+" მწმ":"გაშვება სცადე ტესტით"}</div></div></div>
    <button class="btn s" data-a="dnsTest">${ic("refresh","")} ტესტი</button>
  </div></div>
  <div class="cd"><div class="pd">
    <div class="lb" style="margin-bottom:6px">DoH მისამართი (DNS-over-HTTPS)</div>
    <input id="doh" value="${esc(d.doh)}" placeholder="https://dns.cleangeo.ge/dns-query" autocapitalize="off" autocorrect="off" spellcheck="false">
    <div class="lb" style="margin:12px 0 6px">DoT მისამართი (DNS-over-TLS)</div>
    <input id="dot" value="${esc(d.dot||"")}" placeholder="dns.cleangeo.ge" autocapitalize="off" autocorrect="off" spellcheck="false">
    <div class="ar" style="margin-top:14px"><button class="btn" data-a="dnsSave">შენახვა</button></div>
  </div></div>
  <div class="cd"><div class="row"><span class="ic">${ic("lock")}</span><span class="rt"><b>DNSSEC ვალიდაცია</b><small>ხელმოწერების შემოწმება ყველა პასუხზე</small></span>
    <button class="tg ${d.dnssec?"on":""}" data-a="dnssec"></button></div>
    <div class="row"><span class="ic">${ic("eye")}</span><span class="rt"><b>პროვაიდერის ჩარევა</b><small>DNS-ჰაიჯეკის ავტო-შემოწმება</small></span><span class="bg ${S.vpn.status==="connected"?"ok":"off"}">${S.vpn.status==="connected"?"ტუნელით დაცული":"—"}</span></div></div>
  <div class="pd" style="padding:0 2px;color:var(--t2);font-size:12.5px;text-align:center">Google-ის, Cloudflare-ის და AdGuard-ის DNS არ გამოიყენება.</div>
  </div>`;}
function pgStats(){const s=S.stats;
  return `<div class="pg">
  <div class="nb"><button class="bk" data-go="tab:home">${ic("back")}</button><h1>სტატისტიკა</h1></div>
  <div class="sg"><button class="on">კვირა</button><button>თვე</button><button>ყველა დრო</button></div>
  <div class="g2">
    <div class="cd"><div class="nm">${fmtN(s.adsBlocked)}</div><div class="lb">რეკლამა</div><div class="mt"><i style="width:${Math.min(100,s.adsBlocked/10)}%"></i></div></div>
    <div class="cd"><div class="nm">${fmtN(s.trackersBlocked)}</div><div class="lb">თრექერი</div><div class="mt"><i style="width:${Math.min(100,s.trackersBlocked/10)}%"></i></div></div>
    <div class="cd"><div class="nm">${fmtN(s.queries)}</div><div class="lb">DNS მოთხოვნა</div><div class="mt"><i style="width:${Math.min(100,s.queries/10)}%"></i></div></div>
    <div class="cd"><div class="nm">${fmtN(s.week.reduce((a,b)=>a+b,0))}</div><div class="lb">ამ კვირაში</div><div class="mt"><i style="width:${Math.min(100,s.week.reduce((a,b)=>a+b,0)/10)}%"></i></div></div>
  </div>
  <h3>ტოპ დაბლოკილი</h3>
  <div class="cd">${s.topBlocked.length?s.topBlocked.map(t=>`<div class="row"><span class="ic r">${ic("ban")}</span><span class="rt"><b>${esc(t.host)}</b><small>${fmtN(t.count)} შემთხვევა</small></span><span class="bg bd">${t.pct||""}%</span></div>`).join(""):'<div class="em">ჯერ მონაცემები არ არის</div>'}</div>
  <div class="pd" style="padding:0 2px"><button class="btn d" data-a="clearStats">სტატისტიკის გასუფთავება</button></div>
  </div>`;}
function pgSettings(){const t=S.settings;
  return `<div class="pg">
  <div class="nb"><button class="bk" data-go="tab:home">${ic("back")}</button><h1>პარამეტრები</h1></div>
  <h3>გარეგნობა</h3>
  <div class="cd"><div class="row"><span class="ic">${ic("moon")}</span><span class="rt"><b>თემა</b><small>${t.dark==="auto"?"სისტემური":t.dark==="dark"?"მუქი":"ნათელი"}</small></span>
    <div class="sg" style="margin:0;min-width:150px"><button class="${t.dark==="light"?"on":""}" data-a="theme:light">ნათელი</button><button class="${t.dark==="auto"?"on":""}" data-a="theme:auto">ავტო</button><button class="${t.dark==="dark"?"on":""}" data-a="theme:dark">მუქი</button></div></div></div>
  <h3>განახლებები</h3>
  <div class="cd">
    <div class="row"><span class="ic">${ic("refresh")}</span><span class="rt"><b>ავტომატური განახლება</b><small>ფილტრები განრიგით</small></span><button class="tg ${t.updateAutomatically?"on":""}" data-a="autoUp"></button></div>
  </div>
  <h3>სხვა</h3>
  <div class="cd">
    <div class="row" data-a="howto"><span class="ic">${ic("info")}</span><span class="rt"><b>ინსტრუქცია</b><small>Safari-ს ჩართვის ნაბიჯები</small></span><span class="r2">${ic("chev")}</span></div>
    <div class="row" data-a="log"><span class="ic">${ic("list")}</span><span class="rt"><b>აქტივობის ჟურნალი</b><small>${S.activity.length} ჩანაწერი</small></span><span class="r2">${ic("chev")}</span></div>
  </div>
  <div class="pd" style="padding:0 2px;text-align:center;color:var(--t2);font-size:12px">ლოკალური აღრიცხვა — მონაცემები მოწყობილობიდან არ გადის · CleanGEO 1.0</div>
  </div>`;}

/* ---------- ქვე-ფანჯრები ---------- */
function sheetHowto(){sheet(`<h3 style="margin-top:0">Safari-ს დაცვის ჩართვა</h3>
  <div class="cd"><div class="stp"><b>1</b><span>გახსენი <b>პარამეტრები → Safari → გაფართოებები</b></span></div>
  <div class="stp"><b>2</b><span>აირჩიე <b>CleanGEO</b> და ჩართე ნებართვა</span></div>
  <div class="stp"><b>3</b><span>დაბრუნდი აქ და დააჭირე <b>„განახლება“</b> — ფილტრები ავტომატურად დაყენდება</span></div></div>
  <button class="btn" data-a="cs">გასაგებია</button>`);}
function sheetDay(n){const s=S.stats.week;sheet(`<h3 style="margin-top:0">${DAYS[n]}</h3>
  <div class="cd pd"><div class="nm">${fmtN(s[n])}</div><div class="lb">დაბლოკილი ობიექტი</div>
  <div class="mt"><i style="width:${Math.max(4,s[n]/Math.max(1,...s)*100)}%"></i></div></div>
  <button class="btn s" data-a="cs">დახურვა</button>`);}
function sheetClearStats(){sheet(`<h3 style="margin-top:0">სტატისტიკის გასუფთავება</h3>
  <div class="cd pd"><span>წაიშლება ყველა დათვლა და გრაფიკი. ფილტრები არ შეიცვლება.</span></div>
  <div class="ar"><button class="btn d" id="csYes">წაშლა</button><button class="btn s" data-a="cs">გაუქმება</button></div>`);
  $("#csYes").onclick=()=>{post("clearStats",{},()=>{});S.stats={adsBlocked:0,trackersBlocked:0,queries:0,week:[0,0,0,0,0,0,0],topBlocked:[]};closeSheet();render();toast("გასუფთავებულია");};}
function openFilter(id){const f=S.filters.find(x=>x.id===id);if(!f)return;
  sheet(`<h3 style="margin-top:0">${esc(f.name)}</h3>
  <div class="cd">
    <div class="row"><span class="ic">${ic("list")}</span><span class="rt"><b>წესები</b><small>${fmtN(f.rules)}</small></span></div>
    <div class="row"><span class="ic">${ic("clock")}</span><span class="rt"><b>ბოლო განახლება</b><small>${fmtTime(f.updated)}</small></span></div>
    <div class="row"><span class="ic">${ic("globe")}</span><span class="rt"><b>წყარო</b><small>${esc(f.url||"—")}</small></span></div>
  </div>
  <div class="ar"><button class="btn s" data-a="fsync">განახლება</button><button class="btn d" data-a="fdel:${esc(id)}">წაშლა</button></div>
  <button class="btn" data-a="cs">დახურვა</button>`);}
function sheetLog(){sheet(`<h3 style="margin-top:0">აქტივობის ჟურნალი</h3>
  <div class="tl">${S.activity.length?S.activity.slice(0,20).map(a=>`<div class="it"><div class="cd"><div class="row"><span class="ic ${a.kind==="blocked"?"r":"g"}">${ic(a.kind==="blocked"?"ban":"check")}</span><span class="rt"><b>${esc(a.title)}</b><small>${fmtTime(a.at)}</small></span></div></div></div>`).join(""):'<div class="em">ცარიელია</div>'}</div>
  <button class="btn" data-a="cs">დახურვა</button>`);}
function sheetNodes(){const nodes=S.vpn.nodes||[
    {id:"tbilisi",name:"თბილისი",flag:"🇬🇪",ping:12,load:32},
    {id:"fra",name:"ფრანკფურტი",flag:"🇩🇪",ping:48,load:51},
    {id:"ams",name:"ამსტერდამი",flag:"🇳🇱",ping:57,load:44}];
  sheet(`<h3 style="margin-top:0">სერვერის არჩევა</h3>
  <div class="cd">${nodes.map(n=>`<div class="row" data-a="nodeUse:${n.id}"><span class="ic ${S.vpn.node&&S.vpn.node.id===n.id?"g":""}">${ic("srv")}</span>
    <span class="rt"><b>${n.flag} ${esc(n.name)}</b><small>პინგი ${n.ping} მწმ · დატვირთვა ${n.load}%</small></span>
    ${S.vpn.node&&S.vpn.node.id===n.id?'<span class="sel on">'+ic("check")+"</span>":'<span class="sel"></span>'}</div>`).join("")}</div>
  <button class="btn" data-a="cs">გაუქმება</button>`);}

/* ---------- თემა ---------- */
function applyTheme(){const t=S.settings.dark;
  if(t==="auto")document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme",t);}
applyTheme();
window.addEventListener("resize",()=>{renderDock();});
render();
