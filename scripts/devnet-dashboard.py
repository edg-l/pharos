#!/usr/bin/env python3
"""Pharos devnet dashboard — a tiny, standalone local-devnet monitor.

Scope is pharos-only: every datum is sourced from pharos's own Beacon API (the
axum server shipped in M7). It does NOT query Lighthouse or ethrex directly; the
execution-layer panel reflects pharos's *view* of the EL (the head block's
execution payload + the optimistic/VALID-SYNCING status it carries).

Form factor: one stdlib file. A background thread polls the Beacon API and
caches an aggregated snapshot; the HTTP server hands the browser the cached
snapshot at `/data` and the dashboard HTML at `/`. The browser only ever talks
to this server (same origin), so Beacon API CORS never enters the picture.

Usage:
    scripts/devnet-dashboard.py                       # defaults below
    scripts/devnet-dashboard.py --beacon http://127.0.0.1:5053 --port 8080

Then open http://127.0.0.1:8080 in a browser. Pairs with the devnet launcher
~/.cache/pharos-devnet/run-blockprod.sh (pharos BN on :5053).
"""

import argparse
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Beacon API client ────────────────────────────────────────────────────────


class Beacon:
    """Thin Beacon API client. Returns parsed JSON or None on any failure."""

    def __init__(self, base, timeout=3.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def get(self, path):
        url = f"{self.base}{path}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                if r.status != 200:
                    return None
                return json.loads(r.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                ValueError, TimeoutError):
            return None


# ── Aggregation ────────────────────────────────────────────────────────────--


class Poller:
    """Background poller: refreshes a cached snapshot every `interval` seconds."""

    def __init__(self, beacon, interval, recent_window):
        self.beacon = beacon
        self.interval = interval
        self.recent_window = recent_window
        self.lock = threading.Lock()
        self.snapshot = {"online": False, "ts": 0}
        # Genesis + spec are immutable; fetch once and memoize.
        self._genesis_time = None
        self._seconds_per_slot = None
        self._slots_per_epoch = None

    def _ensure_constants(self):
        if self._genesis_time is None:
            g = self.beacon.get("/eth/v1/beacon/genesis")
            if g:
                self._genesis_time = int(g["data"]["genesis_time"])
        if self._seconds_per_slot is None:
            s = self.beacon.get("/eth/v1/config/spec")
            if s:
                d = s.get("data", {})
                if "SECONDS_PER_SLOT" in d:
                    self._seconds_per_slot = int(d["SECONDS_PER_SLOT"])
                if "SLOTS_PER_EPOCH" in d:
                    self._slots_per_epoch = int(d["SLOTS_PER_EPOCH"])

    def _wall_slot(self):
        if self._genesis_time is None or not self._seconds_per_slot:
            return None
        now = int(time.time())
        if now < self._genesis_time:
            return 0
        return (now - self._genesis_time) // self._seconds_per_slot

    def _slot_into(self):
        """Seconds elapsed into the current wall-clock slot (slot timing)."""
        if self._genesis_time is None or not self._seconds_per_slot:
            return None
        return (int(time.time()) - self._genesis_time) % self._seconds_per_slot

    def _recent_blocks(self, head_slot):
        """Last `recent_window` slots: which had a block, who proposed it."""
        out = []
        if head_slot is None:
            return out
        lo = max(0, head_slot - self.recent_window + 1)
        for slot in range(head_slot, lo - 1, -1):
            h = self.beacon.get(f"/eth/v1/beacon/headers?slot={slot}")
            if h and h.get("data"):
                item = h["data"][0]
                msg = item["header"]["message"]
                out.append({
                    "slot": slot,
                    "proposer_index": int(msg["proposer_index"]),
                    "root": item["root"],
                    "missed": False,
                })
            else:
                out.append({"slot": slot, "proposer_index": None,
                            "root": None, "missed": True})
        return out

    def poll_once(self):
        b = self.beacon
        self._ensure_constants()

        head = b.get("/eth/v1/beacon/headers/head")
        syncing = b.get("/eth/v1/node/syncing")
        finality = b.get("/eth/v1/beacon/states/head/finality_checkpoints")
        peer_count = b.get("/eth/v1/node/peer_count")
        peers = b.get("/eth/v1/node/peers")
        head_block = b.get("/eth/v2/beacon/blocks/head")
        version = b.get("/eth/v1/node/version")

        online = head is not None or syncing is not None
        snap = {"online": online, "ts": int(time.time())}

        if version:
            snap["node_version"] = version["data"]["version"]

        head_slot = None
        if head and head.get("data"):
            hm = head["data"]["header"]["message"]
            head_slot = int(hm["slot"])
            snap["head"] = {
                "slot": head_slot,
                "root": head["data"]["root"],
                "proposer_index": int(hm["proposer_index"]),
                "parent_root": hm["parent_root"],
                "state_root": hm["state_root"],
            }

        wall = self._wall_slot()
        snap["wall_slot"] = wall
        snap["slot_into"] = self._slot_into()
        snap["seconds_per_slot"] = self._seconds_per_slot
        snap["slots_per_epoch"] = self._slots_per_epoch
        if wall is not None and head_slot is not None:
            snap["wall_lag"] = wall - head_slot
        if head_slot is not None and self._slots_per_epoch:
            snap["epoch"] = head_slot // self._slots_per_epoch

        if finality and finality.get("data"):
            d = finality["data"]
            snap["finality"] = {
                "finalized": d["finalized"],
                "current_justified": d["current_justified"],
                "previous_justified": d["previous_justified"],
            }

        if syncing and syncing.get("data"):
            snap["syncing"] = syncing["data"]

        if peer_count and peer_count.get("data"):
            snap["peer_count"] = peer_count["data"]

        if peers and peers.get("data") is not None:
            snap["peers"] = peers["data"]

        # Fork name + execution-layer view from the head block (v2, fork-tagged).
        if head_block:
            snap["fork"] = head_block.get("version")
            snap["execution_optimistic"] = head_block.get("execution_optimistic")
            snap["finalized_head"] = head_block.get("finalized")
            body = (head_block.get("data", {})
                    .get("message", {})
                    .get("body", {}))
            payload = body.get("execution_payload")
            if payload:
                el = {
                    "block_number": payload.get("block_number"),
                    "block_hash": payload.get("block_hash"),
                    "timestamp": payload.get("timestamp"),
                    "gas_used": payload.get("gas_used"),
                    "gas_limit": payload.get("gas_limit"),
                    "fee_recipient": payload.get("fee_recipient"),
                }
                # Deneb+ blob/gas fields (present once the Deneb fork lands).
                if "blob_gas_used" in payload:
                    el["blob_gas_used"] = payload["blob_gas_used"]
                if "excess_blob_gas" in payload:
                    el["excess_blob_gas"] = payload["excess_blob_gas"]
                kzg = body.get("blob_kzg_commitments")
                if kzg is not None:
                    el["blob_count"] = len(kzg)
                snap["execution"] = el

        snap["recent_blocks"] = self._recent_blocks(head_slot)
        return snap

    def run(self):
        while True:
            try:
                snap = self.poll_once()
            except Exception as e:  # never let the poll thread die
                snap = {"online": False, "ts": int(time.time()),
                        "error": str(e)}
            with self.lock:
                self.snapshot = snap
            time.sleep(self.interval)

    def latest(self):
        with self.lock:
            return dict(self.snapshot)


# ── HTTP server ────────────────────────────────────────────────────────────--

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pharos devnet</title>
<style>
  :root {
    --bg:#070b12; --bg2:#0b1119; --panel:#10172180; --panel-solid:#101721;
    --border:#1e2937; --border2:#2a3a4d; --fg:#e6edf6; --muted:#7d8da3;
    --dim:#56657c; --accent:#4aa8ff; --accent2:#7c5cff;
    --ok:#34d399; --warn:#fbbf24; --err:#f87171;
    --mono:ui-monospace,'SF Mono','JetBrains Mono',Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  }
  * { box-sizing:border-box; }
  html,body { margin:0; }
  body {
    background:
      radial-gradient(1200px 600px at 12% -10%, #12305522, transparent 60%),
      radial-gradient(1000px 500px at 100% 0%, #2a1a5522, transparent 55%),
      var(--bg);
    color:var(--fg); font:16px/1.55 var(--sans);
    -webkit-font-smoothing:antialiased; min-height:100vh;
    padding-bottom:32px;
  }
  /* ── header ── */
  header {
    display:flex; align-items:center; gap:18px;
    padding:20px 30px; border-bottom:1px solid var(--border);
    background:linear-gradient(180deg,#0b111b 0%, #070b1200 100%);
    position:sticky; top:0; z-index:5; backdrop-filter:blur(8px);
  }
  .brand { display:flex; align-items:baseline; gap:12px; }
  .brand h1 {
    margin:0; font-size:26px; font-weight:800; letter-spacing:-.02em;
    background:linear-gradient(90deg,#fff,#9fc7ff 60%,#b9a6ff);
    -webkit-background-clip:text; background-clip:text; color:transparent;
  }
  .brand .tag { font-size:14px; color:var(--muted); font-weight:600;
                text-transform:uppercase; letter-spacing:.18em; }
  .nv { font-family:var(--mono); font-size:12.5px; color:var(--dim);
        padding:3px 10px; border:1px solid var(--border); border-radius:8px; }
  .right { margin-left:auto; display:flex; align-items:center; gap:18px; }
  .clock { font-family:var(--mono); font-size:15px; color:var(--muted);
           font-variant-numeric:tabular-nums; }
  #status { display:flex; align-items:center; gap:9px; font-size:14px;
            color:var(--muted); font-weight:600; }
  .dot { width:11px; height:11px; border-radius:50%; }
  .dot.on  { background:var(--ok);  box-shadow:0 0 0 0 #34d39966;
             animation:pulse 1.8s infinite; }
  .dot.off { background:var(--err); box-shadow:0 0 8px #f8717188; }
  @keyframes pulse { 70%{box-shadow:0 0 0 9px #34d39900;} 100%{box-shadow:0 0 0 0 #34d39900;} }

  /* ── hero metrics ── */
  .hero { display:grid; gap:16px; padding:26px 30px 6px;
          grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); }
  .stat {
    background:linear-gradient(180deg,#121b28cc,#0c121bcc);
    border:1px solid var(--border); border-radius:16px; padding:18px 20px;
    position:relative; overflow:hidden;
  }
  .stat::before { content:""; position:absolute; inset:0 auto 0 0; width:4px;
                  background:var(--accent); opacity:.85; }
  .stat.accent2::before { background:var(--accent2); }
  .stat.ok::before { background:var(--ok); }
  .stat.warn::before { background:var(--warn); }
  .stat.err::before { background:var(--err); }
  .stat .label { font-size:12px; letter-spacing:.14em; text-transform:uppercase;
                 color:var(--dim); font-weight:700; }
  .stat .val { font-size:42px; font-weight:800; line-height:1.05; margin-top:8px;
               font-variant-numeric:tabular-nums; letter-spacing:-.02em; }
  .stat .val.mono { font-family:var(--mono); font-size:30px; }
  .stat .sub { font-size:13px; color:var(--muted); margin-top:5px;
               font-family:var(--mono); }
  .stat .val.ok{color:var(--ok);} .stat .val.warn{color:var(--warn);}
  .stat .val.err{color:var(--err);} .stat .val.accent{color:var(--accent);}

  /* ── panels ── */
  .grid { display:grid; gap:18px; padding:18px 30px;
          grid-template-columns:repeat(auto-fit,minmax(360px,1fr)); }
  .panel {
    background:linear-gradient(180deg,#0e1622cc,#0a0f17cc);
    border:1px solid var(--border); border-radius:16px; padding:20px 22px;
    box-shadow:0 8px 30px #00000040;
  }
  .panel h2 { margin:0 0 16px; font-size:13px; text-transform:uppercase;
              letter-spacing:.16em; color:var(--accent); font-weight:700;
              display:flex; align-items:center; gap:9px; }
  .panel h2::before { content:""; width:7px; height:7px; border-radius:2px;
                      background:var(--accent); box-shadow:0 0 8px var(--accent); }
  .kv { display:grid; grid-template-columns:auto 1fr; gap:11px 18px;
        font-size:15px; align-items:baseline; }
  .kv dt { color:var(--muted); white-space:nowrap; font-weight:500; }
  .kv dd { margin:0; font-family:var(--mono); word-break:break-all;
           text-align:right; }
  .pill { display:inline-block; padding:3px 11px; border-radius:999px;
          font-size:12.5px; font-family:var(--mono); font-weight:600;
          border:1px solid transparent; }
  .pill.ok   { background:#34d39920; color:var(--ok);   border-color:#34d39940; }
  .pill.warn { background:#fbbf2420; color:var(--warn); border-color:#fbbf2440; }
  .pill.err  { background:#f8717120; color:var(--err);  border-color:#f8717140; }
  .pill.neutral { background:#4aa8ff18; color:var(--accent); border-color:#4aa8ff35; }
  .muted { color:var(--muted); }

  table { width:100%; border-collapse:collapse; font-size:13.5px;
          font-family:var(--mono); }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--border); }
  th { color:var(--dim); font-weight:600; text-transform:uppercase;
       font-size:11px; letter-spacing:.08em; }
  tbody tr:last-child td { border-bottom:none; }
  tr.missed td { color:var(--warn); opacity:.85; }
  td.r, th.r { text-align:right; }
  .scroll { max-height:230px; overflow:auto; margin:-2px; padding:2px; }
  .scroll::-webkit-scrollbar { width:8px; }
  .scroll::-webkit-scrollbar-thumb { background:var(--border2); border-radius:4px; }

  /* slot-timing bar */
  .timing { margin-bottom:18px; }
  .timing .row { display:flex; justify-content:space-between; font-size:13px;
                 color:var(--muted); margin-bottom:7px; font-family:var(--mono); }
  .bar { height:12px; background:#0a1019; border:1px solid var(--border);
         border-radius:7px; overflow:hidden; }
  .bar > span { display:block; height:100%;
                background:linear-gradient(90deg,var(--accent),var(--accent2));
                transition:width .4s ease; box-shadow:0 0 12px #4aa8ff66; }
</style>
</head>
<body>
<header>
  <div class="brand"><h1>Pharos</h1><span class="tag">devnet</span></div>
  <span class="nv" id="node-version"></span>
  <div class="right">
    <span class="clock" id="clock"></span>
    <span id="status"><span class="dot off"></span>connecting…</span>
  </div>
</header>

<div class="hero" id="hero"></div>

<div class="grid">
  <section class="panel"><h2>Chain</h2><div id="chain"></div></section>
  <section class="panel"><h2>Sync &amp; peers</h2><div id="sync"></div></section>
  <section class="panel"><h2>Validator activity</h2><div id="validator"></div></section>
  <section class="panel"><h2>Execution layer</h2><div id="execution"></div></section>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const short = h => !h ? '—' : (h.length>16 ? h.slice(0,10)+'…'+h.slice(-6) : h);
const pill = (t,c) => `<span class="pill ${c}">${esc(t)}</span>`;
const cp = c => c ? `<span class="muted">ep</span> ${esc(c.epoch)} · ${short(c.root)}` : '—';
const num = n => (n===undefined||n===null) ? '—'
                 : Number(n).toLocaleString('en-US');
const kv = rows => '<dl class="kv">'+rows.map(([k,v])=>`<dt>${k}</dt><dd>${v}</dd>`).join('')+'</dl>';
function stat(label,val,cls,sub){
  return `<div class="stat ${cls||''}"><div class="label">${label}</div>`+
         `<div class="val ${cls||''}">${val}</div>`+
         (sub?`<div class="sub">${sub}</div>`:'')+`</div>`;
}

function render(s){
  if(!s.online){
    $('status').innerHTML = '<span class="dot off"></span>node offline';
    $('hero').innerHTML = '';
    for(const id of ['chain','sync','validator','execution'])
      $(id).innerHTML = '<span class="muted">waiting for pharos Beacon API…</span>';
    return;
  }
  const age = Math.max(0, Math.floor(Date.now()/1000) - s.ts);
  $('status').innerHTML = `<span class="dot on"></span>live · ${age}s ago`;
  $('node-version').textContent = s.node_version || '';

  const head = s.head || {}, fin = s.finality || {}, sy = s.syncing || {};
  const lag = s.wall_lag;
  const lagCls = lag===undefined ? '' : (lag<=0?'ok':(lag<=2?'warn':'err'));
  const lagTxt = lag===undefined ? '—' : ((lag<=0?'':'+')+lag);

  // ── hero metrics ──
  $('hero').innerHTML =
    stat('Fork', s.fork? esc(s.fork.toUpperCase()):'—', 'accent') +
    stat('Head slot', num(head.slot), '', `wall ${num(s.wall_slot)}`) +
    stat('Epoch', num(s.epoch), 'accent2') +
    stat('Wall lag', lagTxt, lagCls, lag===undefined?'':'slots behind tip') +
    stat('Peers', num((s.peer_count||{}).connected), '',
         (s.peers&&s.peers.length)?`${s.peers.length} listed`:'as reported');

  // ── Chain ──
  $('chain').innerHTML = kv([
    ['fork', s.fork ? pill(s.fork,'neutral') : '—'],
    ['head slot', num(head.slot)],
    ['head root', `<span class="muted">${short(head.root)}</span>`],
    ['parent root', `<span class="muted">${short(head.parent_root)}</span>`],
    ['epoch', num(s.epoch)],
    ['wall slot', num(s.wall_slot)],
    ['wall lag', pill(lagTxt+' slots', lagCls||'neutral')],
    ['justified', cp(fin.current_justified)],
    ['finalized', cp(fin.finalized)],
  ]);

  // ── Sync & peers ──
  const b2 = v => pill(v?'true':'false', v?'warn':'ok');
  let html = kv([
    ['syncing', b2(sy.is_syncing)],
    ['optimistic', b2(sy.is_optimistic)],
    ['el offline', pill(sy.el_offline?'true':'false', sy.el_offline?'err':'ok')],
    ['sync distance', num(sy.sync_distance)],
    ['connected', num((s.peer_count||{}).connected)],
  ]);
  const peers = s.peers || [];
  if(peers.length){
    html += '<div class="scroll" style="margin-top:14px"><table><thead><tr>'+
            '<th>peer</th><th>state</th><th>dir</th></tr></thead><tbody>';
    for(const p of peers)
      html += `<tr><td>${short(p.peer_id)}</td><td>${esc(p.state||'?')}</td>`+
              `<td>${esc(p.direction||'?')}</td></tr>`;
    html += '</tbody></table></div>';
  } else {
    html += '<p class="muted" style="margin:14px 0 0;font-size:13.5px">'+
            'no peers listed by pharos API</p>';
  }
  $('sync').innerHTML = html;

  // ── Validator activity ──
  let v = '';
  if(s.slot_into!=null && s.seconds_per_slot){
    const pct = Math.min(100, Math.round(100*s.slot_into/s.seconds_per_slot));
    v += `<div class="timing"><div class="row"><span>slot timing</span>`+
         `<span>t+${s.slot_into}s / ${s.seconds_per_slot}s</span></div>`+
         `<div class="bar"><span style="width:${pct}%"></span></div></div>`;
  }
  const rb = s.recent_blocks || [];
  v += '<div class="scroll"><table><thead><tr><th>slot</th><th>proposer</th>'+
       '<th class="r">root</th></tr></thead><tbody>';
  for(const b of rb){
    v += b.missed
      ? `<tr class="missed"><td>${b.slot}</td><td colspan="2">— missed —</td></tr>`
      : `<tr><td>${b.slot}</td><td>#${b.proposer_index}</td>`+
        `<td class="r muted">${short(b.root)}</td></tr>`;
  }
  v += '</tbody></table></div>';
  $('validator').innerHTML = v;

  // ── Execution layer (pharos's view) ──
  const el = s.execution;
  if(!el){
    $('execution').innerHTML =
      '<p class="muted">pre-merge head — no execution payload</p>';
  } else {
    const rows = [
      ['payload', s.execution_optimistic
        ? pill('OPTIMISTIC','warn') : pill('VALID','ok')],
      ['block #', num(el.block_number)],
      ['block hash', `<span class="muted">${short(el.block_hash)}</span>`],
      ['gas used', num(el.gas_used)],
      ['gas limit', num(el.gas_limit)],
      ['fee recipient', `<span class="muted">${short(el.fee_recipient)}</span>`],
    ];
    if(el.blob_count!==undefined)    rows.push(['blobs', el.blob_count]);
    if(el.blob_gas_used!==undefined) rows.push(['blob gas used', num(el.blob_gas_used)]);
    if(el.excess_blob_gas!==undefined) rows.push(['excess blob gas', num(el.excess_blob_gas)]);
    $('execution').innerHTML = kv(rows);
  }
}

function clock(){
  const d = new Date();
  $('clock').textContent = d.toLocaleTimeString('en-GB');
}
async function tick(){
  try { render(await (await fetch('/data',{cache:'no-store'})).json()); }
  catch(e){ $('status').innerHTML = '<span class="dot off"></span>fetch error'; }
}
clock(); setInterval(clock, 1000);
tick();  setInterval(tick, 1000);
</script>
</body>
</html>
"""


def make_handler(poller):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):  # silence per-request stderr noise
            pass

        def _send(self, code, body, ctype):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/index"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif self.path.startswith("/data"):
                body = json.dumps(poller.latest())
                self._send(200, body, "application/json")
            else:
                self._send(404, "not found", "text/plain")

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Pharos devnet dashboard")
    ap.add_argument("--beacon", default="http://127.0.0.1:5053",
                    help="pharos Beacon API base URL (default: %(default)s)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address; pass 0.0.0.0 for LAN access (default: %(default)s)")
    ap.add_argument("--port", type=int, default=8080,
                    help="dashboard HTTP port (default: %(default)s)")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="Beacon API poll interval, seconds (default: %(default)s)")
    ap.add_argument("--recent-window", type=int, default=12,
                    help="recent-blocks slot window (default: %(default)s)")
    args = ap.parse_args()

    poller = Poller(Beacon(args.beacon), args.interval, args.recent_window)
    t = threading.Thread(target=poller.run, daemon=True)
    t.start()

    server = ThreadingHTTPServer((args.host, args.port), make_handler(poller))
    print(f"pharos devnet dashboard → http://{args.host}:{args.port}")
    print(f"  polling Beacon API at {args.beacon} every {args.interval}s")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
