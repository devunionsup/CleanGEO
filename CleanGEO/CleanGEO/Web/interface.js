// Bridge: every call goes to a real Swift service; no mock data anywhere.
const $ = id => document.getElementById(id);
let seq = 0; const pending = {};
window.__bridgeReply = (id, data) => { pending[id]?.(data); delete pending[id]; };
function call(cmd, args = {}) {
  return new Promise(res => {
    const id = ++seq; pending[id] = res;
    window.webkit.messageHandlers.bridge.postMessage({ id, cmd, args });
  });
}
const fmtBytes = n => n < 1024 ? n + " B" : n < 1048576 ? (n/1024).toFixed(1) + " KB" : (n/1048576).toFixed(1) + " MB";

let lastSig = "";
function render(s) {
  if (!s || s.error && !s.total && s.total !== 0) { $("error").textContent = s?.error || ""; return; }
  const sig = JSON.stringify(s); if (sig === lastSig) return; lastSig = sig;   // no flicker
  $("error").textContent = s.error || "";
  $("tunnelStatus").textContent = s.tunnel;
  $("orb").classList.toggle("on", s.tunnelOn);
  $("toggle").textContent = s.tunnelOn ? "გამორთვა" : "ჩართვა";
  $("blocked").textContent = s.blocked;
  $("total").textContent = s.total; $("ads").textContent = s.ads; $("trackers").textContent = s.trackers;
  $("bytes").textContent = s.bytes ? fmtBytes(s.bytes) : "—";
  $("rules").textContent = s.rules;
  $("updated").textContent = s.lastUpdate ? new Date(s.lastUpdate).toLocaleString("ka") : "—";
  const max = Math.max(1, ...s.days.map(d => d.total));
  $("chart").innerHTML = s.days.map(d => `<i title="${d.day}" style="height:${d.total/max*100}%"></i>`).join("");
  $("top").innerHTML = s.top.length ? s.top.map(t => `<li>${t.domain} — ${t.count}</li>`).join("") : "<li>—</li>";
  $("lists").innerHTML = s.lists.map(u => `<li>${u} <a href="#" data-rm="${u}">✕</a></li>`).join("");
}
window.__push = render;
const act = async (cmd, args) => render(await call(cmd, args));

$("toggle").onclick = () => act("toggleTunnel", { on: $("orb").classList.contains("on") ? false : true });
$("update").onclick = () => act("updateFilters");
$("clear").onclick = () => act("clearStats");
$("addList").onclick = () => { const u = $("listUrl").value.trim(); if (u) act("addList", { url: u }); $("listUrl").value = ""; };
$("lists").onclick = e => { const u = e.target.dataset.rm; if (u) act("removeList", { url: u }); };
$("probe").onclick = async () => {
  const r = await call("probeDoH");
  $("latency").textContent = r.latency == null ? "მიუწვდომელია" : r.latency + " ms";
};
document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  document.querySelectorAll(".screen").forEach(s => s.classList.toggle("active", s.id === b.dataset.s));
  document.querySelectorAll("nav button").forEach(x => x.classList.toggle("on", x === b));
});
act("getState");
