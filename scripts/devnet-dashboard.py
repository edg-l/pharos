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
<title>Pharos devnet dashboard</title>
<style>
  :root {
    --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#c9d1d9;
    --muted:#8b949e; --accent:#58a6ff; --ok:#3fb950; --warn:#d29922;
    --err:#f85149; --mono:'SF Mono',ui-monospace,Menlo,Consolas,monospace;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif; }
  header { display:flex; align-items:baseline; gap:16px; padding:12px 20px;
           border-bottom:1px solid var(--border); background:var(--panel); }
  header h1 { font-size:16px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:12px; }
  #status { margin-left:auto; font-size:12px; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%;
         margin-right:6px; vertical-align:middle; }
  .dot.on { background:var(--ok); } .dot.off { background:var(--err); }
  .grid { display:grid; gap:14px; padding:18px;
          grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); }
  .panel { background:var(--panel); border:1px solid var(--border);
           border-radius:8px; padding:14px 16px; }
  .panel h2 { margin:0 0 10px; font-size:13px; text-transform:uppercase;
              letter-spacing:.05em; color:var(--accent); }
  .kv { display:grid; grid-template-columns:auto 1fr; gap:4px 14px;
        font-size:13px; }
  .kv dt { color:var(--muted); white-space:nowrap; }
  .kv dd { margin:0; font-family:var(--mono); word-break:break-all; }
  .pill { display:inline-block; padding:1px 8px; border-radius:10px;
          font-size:11px; font-family:var(--mono); }
  .pill.ok { background:rgba(63,185,80,.15); color:var(--ok); }
  .pill.warn { background:rgba(210,153,34,.15); color:var(--warn); }
  .pill.err { background:rgba(248,81,73,.15); color:var(--err); }
  .mono { font-family:var(--mono); }
  .muted { color:var(--muted); }
  table { width:100%; border-collapse:collapse; font-size:12px;
          font-family:var(--mono); }
  th,td { text-align:left; padding:3px 6px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:500; }
  tr.missed td { color:var(--warn); }
  .peers { max-height:180px; overflow:auto; }
  .bar { height:6px; background:var(--border); border-radius:3px;
         overflow:hidden; margin-top:4px; }
  .bar > span { display:block; height:100%; background:var(--accent); }
</style>
</head>
<body>
<header>
  <h1>Pharos devnet</h1>
  <span class="sub" id="node-version"></span>
  <span id="status"></span>
</header>
<div class="grid">
  <section class="panel"><h2>Chain status</h2><div id="chain"></div></section>
  <section class="panel"><h2>Sync &amp; peers</h2><div id="sync"></div></section>
  <section class="panel"><h2>Validator activity</h2><div id="validator"></div></section>
  <section class="panel"><h2>Execution layer</h2><div id="execution"></div></section>
</div>
<script>
const $ = id => document.getElementById(id);
function esc(s){ return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function short(h){ if(!h) return '—'; return h.length>14 ? h.slice(0,10)+'…'+h.slice(-6) : h; }
function cp(c){ return c ? `epoch ${esc(c.epoch)} · <span class="muted">${short(c.root)}</span>` : '—'; }
function kv(rows){
  return '<dl class="kv">'+rows.map(([k,v])=>`<dt>${k}</dt><dd>${v}</dd>`).join('')+'</dl>';
}
function pill(text,cls){ return `<span class="pill ${cls}">${esc(text)}</span>`; }

function render(s){
  // status line
  if(!s.online){
    $('status').innerHTML = '<span class="dot off"></span>offline';
    $('chain').innerHTML = $('sync').innerHTML = $('validator').innerHTML =
      $('execution').innerHTML = '<span class="muted">node unreachable…</span>';
    return;
  }
  const age = Math.max(0, Math.floor(Date.now()/1000) - s.ts);
  $('status').innerHTML = `<span class="dot on"></span>live · updated ${age}s ago`;
  $('node-version').textContent = s.node_version || '';

  // ── Chain status ──
  const head = s.head || {};
  const lag = s.wall_lag;
  let lagPill = '—';
  if(lag !== undefined){
    const cls = lag<=0 ? 'ok' : (lag<=2 ? 'warn' : 'err');
    lagPill = pill((lag<=0?'':'+')+lag+' slots', cls);
  }
  const fin = s.finality || {};
  $('chain').innerHTML = kv([
    ['fork', s.fork ? pill(s.fork, 'ok') : '—'],
    ['head slot', head.slot ?? '—'],
    ['head root', `<span class="muted">${short(head.root)}</span>`],
    ['epoch', s.epoch ?? '—'],
    ['wall slot', s.wall_slot ?? '—'],
    ['wall lag', lagPill],
    ['justified', cp(fin.current_justified)],
    ['finalized', cp(fin.finalized)],
  ]);

  // ── Sync & peers ──
  const sy = s.syncing || {};
  const pc = s.peer_count || {};
  const optCls = sy.is_optimistic ? 'warn' : 'ok';
  const syncCls = sy.is_syncing ? 'warn' : 'ok';
  let html = kv([
    ['syncing', pill(sy.is_syncing?'true':'false', syncCls)],
    ['optimistic', pill(sy.is_optimistic?'true':'false', optCls)],
    ['el_offline', pill(sy.el_offline?'true':'false', sy.el_offline?'err':'ok')],
    ['sync distance', sy.sync_distance ?? '—'],
    ['peers', `${pc.connected ?? 0} connected`],
  ]);
  const peers = s.peers || [];
  if(peers.length){
    html += '<div class="peers"><table><tr><th>peer</th><th>state</th><th>dir</th></tr>';
    for(const p of peers){
      html += `<tr><td>${short(p.peer_id)}</td><td>${esc(p.state||'?')}</td>`+
              `<td>${esc(p.direction||'?')}</td></tr>`;
    }
    html += '</table></div>';
  }
  $('sync').innerHTML = html;

  // ── Validator activity ──
  let vhtml = '';
  if(s.slot_into !== undefined && s.slot_into !== null && s.seconds_per_slot){
    const pct = Math.min(100, Math.round(100*s.slot_into/s.seconds_per_slot));
    vhtml += kv([['slot timing', `t+${s.slot_into}s / ${s.seconds_per_slot}s`]]);
    vhtml += `<div class="bar"><span style="width:${pct}%"></span></div>`;
  }
  const rb = s.recent_blocks || [];
  vhtml += '<table style="margin-top:10px"><tr><th>slot</th><th>proposer</th><th>root</th></tr>';
  for(const b of rb){
    if(b.missed){
      vhtml += `<tr class="missed"><td>${b.slot}</td><td colspan="2">— missed —</td></tr>`;
    } else {
      vhtml += `<tr><td>${b.slot}</td><td>#${b.proposer_index}</td>`+
               `<td class="muted">${short(b.root)}</td></tr>`;
    }
  }
  vhtml += '</table>';
  $('validator').innerHTML = vhtml;

  // ── Execution layer (pharos's view) ──
  const el = s.execution;
  if(!el){
    $('execution').innerHTML = '<span class="muted">pre-merge head — no execution payload</span>';
  } else {
    const optimistic = s.execution_optimistic;
    const elRows = [
      ['payload', optimistic ? pill('OPTIMISTIC (unverified)','warn')
                             : pill('VALID','ok')],
      ['block #', el.block_number ?? '—'],
      ['block hash', `<span class="muted">${short(el.block_hash)}</span>`],
      ['gas', `${el.gas_used ?? '?'} / ${el.gas_limit ?? '?'}`],
      ['fee recipient', `<span class="muted">${short(el.fee_recipient)}</span>`],
    ];
    if(el.blob_count !== undefined) elRows.push(['blobs', el.blob_count]);
    if(el.blob_gas_used !== undefined) elRows.push(['blob gas used', el.blob_gas_used]);
    if(el.excess_blob_gas !== undefined) elRows.push(['excess blob gas', el.excess_blob_gas]);
    $('execution').innerHTML = kv(elRows);
  }
}

async function tick(){
  try {
    const r = await fetch('/data', {cache:'no-store'});
    render(await r.json());
  } catch(e){
    $('status').innerHTML = '<span class="dot off"></span>dashboard fetch error';
  }
}
tick();
setInterval(tick, 1000);
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

    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(poller))
    print(f"pharos devnet dashboard → http://127.0.0.1:{args.port}")
    print(f"  polling Beacon API at {args.beacon} every {args.interval}s")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
