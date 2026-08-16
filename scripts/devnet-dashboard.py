#!/usr/bin/env python3
"""Pharos devnet dashboard — a standalone local-devnet monitor.

Primary data source is pharos's own Beacon API (the axum server shipped in M7):
chain status, sync/peers, validator activity, head-block contents, fork choice,
and block history all come from there. Optionally (`--el-rpc`) it also queries
the paired execution-layer JSON-RPC directly for richer EL detail (txpool,
net_peerCount, eth_syncing, live block). The browser only ever talks to THIS
server (same origin), so Beacon API / EL CORS never enters the picture.

Features:
  - Hero metrics + chain / sync-peers / validator / head-block / EL panels
  - Fork-choice tree (forky-style): canonical vs orphaned branches, node
    weights, finalized/head markers, multiple heads, reorg detection
  - Block-history explorer: recent slots (missed flagged), click to expand
    per-block detail (proxied on demand from the Beacon API)
  - Time-series sparklines (in-memory ring buffer, no DB): wall-lag,
    sync-participation %, attestations/block, gas used, base fee

Usage:
    scripts/devnet-dashboard.py
    scripts/devnet-dashboard.py --beacon http://127.0.0.1:5053 \\
        --el-rpc http://127.0.0.1:28545 --host 0.0.0.0 --port 8080

Pairs with ~/.cache/pharos-devnet/run-blockprod.sh (pharos BN on :5053,
pharos's ethrex EL on :28545).
"""

import argparse
import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── helpers ───────────────────────────────────────────────────────────────────


def _hex_bytes(s):
    """0x-prefixed hex string -> bytes, or b'' on bad input."""
    if not isinstance(s, str):
        return b""
    try:
        return bytes.fromhex(s[2:] if s.startswith("0x") else s)
    except ValueError:
        return b""


def _count_bits(hex_bitfield):
    """Count set bits in a 0x hex SSZ bitfield."""
    return sum(bin(b).count("1") for b in _hex_bytes(hex_bitfield))


def _bitfield_len(hex_bitfield):
    """Total bits in a fixed-size 0x hex bitvector (sync_committee_bits is a
    Bitvector, so every byte is 8 real bits — no length delimiter)."""
    return len(_hex_bytes(hex_bitfield)) * 8


def _decode_graffiti(hex_graffiti):
    """Decode a 32-byte graffiti field to printable text (trailing zeros
    trimmed); returns '' if empty/unprintable."""
    raw = _hex_bytes(hex_graffiti).rstrip(b"\x00")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.hex()
    return "".join(c if c.isprintable() else "" for c in text)


def _hex_int(s):
    """Parse a 0x hex quantity to int, or None."""
    if not isinstance(s, str):
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


def _dec_int(s):
    """Parse a decimal string/number to int, or None (Beacon API encodes EL
    payload numerics as decimal strings)."""
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _block_summary(block_json):
    """Trim a /eth/v2/beacon/blocks/{id} response to a compact detail object."""
    data = (block_json or {}).get("data", {})
    msg = data.get("message", {})
    body = msg.get("body", {})
    payload = body.get("execution_payload") or {}
    return {
        "slot": _dec_int(msg.get("slot")),
        "proposer_index": _dec_int(msg.get("proposer_index")),
        "parent_root": msg.get("parent_root"),
        "state_root": msg.get("state_root"),
        "graffiti": _decode_graffiti(body.get("graffiti")),
        "attestations": len(body.get("attestations") or []),
        "deposits": len(body.get("deposits") or []),
        "proposer_slashings": len(body.get("proposer_slashings") or []),
        "attester_slashings": len(body.get("attester_slashings") or []),
        "voluntary_exits": len(body.get("voluntary_exits") or []),
        "bls_changes": len(body.get("bls_to_execution_changes") or []),
        "el_block_number": payload.get("block_number"),
        "el_block_hash": payload.get("block_hash"),
        "transactions": len(payload.get("transactions") or []),
        "execution_optimistic": (block_json or {}).get("execution_optimistic"),
        "finalized": (block_json or {}).get("finalized"),
    }


# ── HTTP clients ───────────────────────────────────────────────────────────────


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


class ElRpc:
    """Minimal JSON-RPC client for the execution layer. Returns the `result`
    field or None (errors/unknown methods tolerated — ethrex may not implement
    every method)."""

    def __init__(self, base, timeout=3.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._id = 0

    def call(self, method, params):
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0", "id": self._id, "method": method, "params": params,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.base, data=payload,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                if r.status != 200:
                    return None
                obj = json.loads(r.read().decode("utf-8"))
                if "error" in obj:
                    return None
                return obj.get("result")
        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                ValueError, TimeoutError):
            return None


# ── Aggregation ────────────────────────────────────────────────────────────--


class Poller:
    """Background poller: refreshes a cached snapshot every `interval` seconds."""

    def __init__(self, beacon, interval, recent_window, el=None, series_len=64):
        self.beacon = beacon
        self.el = el
        self.interval = interval
        self.recent_window = recent_window
        self.lock = threading.Lock()
        self.snapshot = {"online": False, "ts": 0}
        # Genesis + spec are immutable; fetch once and memoize.
        self._genesis_time = None
        self._seconds_per_slot = None
        self._slots_per_epoch = None
        self._fork_schedule = None
        # Fork-choice / reorg tracking + time series.
        self._prev_head_root = None
        self._reorgs = deque(maxlen=12)
        self._series = deque(maxlen=series_len)
        self._series_last_slot = None

    # ── constants ──
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
        if self._fork_schedule is None:
            fs = self.beacon.get("/eth/v1/config/fork_schedule")
            if fs and fs.get("data") is not None:
                sched = []
                for f in fs["data"]:
                    try:
                        sched.append({"epoch": int(f["epoch"]),
                                      "version": f.get("current_version")})
                    except (KeyError, ValueError, TypeError):
                        continue
                self._fork_schedule = sorted(sched, key=lambda x: x["epoch"])

    def _next_fork(self, current_epoch):
        if not self._fork_schedule or current_epoch is None:
            return None
        far = (1 << 63)
        for f in self._fork_schedule:
            if current_epoch < f["epoch"] < far:
                eta = None
                if self._genesis_time and self._seconds_per_slot and self._slots_per_epoch:
                    fork_ts = (self._genesis_time
                               + f["epoch"] * self._slots_per_epoch * self._seconds_per_slot)
                    eta = max(0, fork_ts - int(time.time()))
                return {"epoch": f["epoch"], "version": f["version"], "eta_s": eta}
        return None

    def _wall_slot(self):
        if self._genesis_time is None or not self._seconds_per_slot:
            return None
        now = int(time.time())
        if now < self._genesis_time:
            return 0
        return (now - self._genesis_time) // self._seconds_per_slot

    def _slot_into(self):
        if self._genesis_time is None or not self._seconds_per_slot:
            return None
        return (int(time.time()) - self._genesis_time) % self._seconds_per_slot

    # ── block history ──
    def _recent_blocks(self, head_slot):
        out = []
        if head_slot is None:
            return out
        lo = max(0, head_slot - self.recent_window + 1)
        for slot in range(head_slot, lo - 1, -1):
            h = self.beacon.get(f"/eth/v1/beacon/headers?slot={slot}")
            if h and h.get("data"):
                item = h["data"][0]
                msg = item["header"]["message"]
                out.append({"slot": slot,
                            "proposer_index": int(msg["proposer_index"]),
                            "root": item["root"], "missed": False})
            else:
                out.append({"slot": slot, "proposer_index": None,
                            "root": None, "missed": True})
        return out

    def block_detail(self, block_id):
        """On-demand per-block detail for the history explorer (proxied)."""
        return _block_summary(self.beacon.get(f"/eth/v2/beacon/blocks/{block_id}"))

    # ── fork choice ──
    def _fork_choice(self, head_root, finalized_root):
        fc = self.beacon.get("/eth/v1/debug/fork_choice")
        if not fc or fc.get("fork_choice_nodes") is None:
            return None
        nodes, by_root = [], {}
        for n in fc["fork_choice_nodes"]:
            try:
                node = {"slot": int(n["slot"]), "root": n["block_root"],
                        "parent": n.get("parent_root"),
                        "weight": _dec_int(n.get("weight")) or 0,
                        "validity": (n.get("validity") or "valid").lower()}
            except (KeyError, ValueError, TypeError):
                continue
            nodes.append(node)
            by_root[node["root"]] = node

        # Canonical = ancestry of head via parent links within the dump.
        canonical = []
        cur = head_root
        seen = set()
        while cur in by_root and cur not in seen:
            seen.add(cur)
            canonical.append(cur)
            cur = by_root[cur]["parent"]

        # Keep the tree readable: cap to the most recent slots.
        if len(nodes) > 60:
            nodes.sort(key=lambda x: x["slot"])
            nodes = nodes[-60:]

        heads = self.beacon.get("/eth/v2/debug/beacon/heads")
        head_list = []
        if heads and heads.get("data"):
            head_list = [h.get("root") for h in heads["data"] if h.get("root")]

        self._detect_reorg(by_root, head_root, set(canonical))
        return {"nodes": nodes, "canonical": canonical, "head": head_root,
                "finalized": finalized_root, "heads": head_list}

    def _detect_reorg(self, by_root, head_root, canonical_set):
        prev = self._prev_head_root
        self._prev_head_root = head_root
        if prev is None or prev == head_root or prev in canonical_set:
            return  # first sample, no change, or normal linear extension
        if prev not in by_root:
            return  # previous head already pruned — can't measure
        # Walk the orphaned branch from the old head up to the new canonical chain.
        depth, cur, top_slot = 0, prev, None
        guard = 0
        while cur in by_root and cur not in canonical_set and guard < 256:
            top_slot = by_root[cur]["slot"]
            depth += 1
            cur = by_root[cur]["parent"]
            guard += 1
        self._reorgs.appendleft({
            "ts": int(time.time()), "depth": depth,
            "old_head": prev, "new_head": head_root, "slot": top_slot,
        })

    # ── time series ──
    def _append_series(self, head_slot, lag, sync_pct, atts, gas_used, base_fee):
        if head_slot is None or head_slot == self._series_last_slot:
            return
        self._series_last_slot = head_slot
        self._series.append({"slot": head_slot, "lag": lag, "sync_pct": sync_pct,
                             "atts": atts, "gas": gas_used, "base_fee": base_fee})

    # ── EL RPC ──
    def _el_node(self):
        if not self.el:
            return None
        out = {}
        blk = self.el.call("eth_getBlockByNumber", ["latest", False])
        if blk:
            out.update({
                "number": _hex_int(blk.get("number")),
                "hash": blk.get("hash"),
                "gas_used": _hex_int(blk.get("gasUsed")),
                "gas_limit": _hex_int(blk.get("gasLimit")),
                "base_fee": _hex_int(blk.get("baseFeePerGas")),
                "timestamp": _hex_int(blk.get("timestamp")),
                "transactions": len(blk.get("transactions") or []),
            })
        syncing = self.el.call("eth_syncing", [])
        out["syncing"] = bool(syncing) if syncing is not None else None
        peers = self.el.call("net_peerCount", [])
        out["peer_count"] = _hex_int(peers)
        chain_id = self.el.call("eth_chainId", [])
        out["chain_id"] = _hex_int(chain_id)
        txpool = self.el.call("txpool_status", [])
        if isinstance(txpool, dict):
            out["txpool"] = {"pending": _hex_int(txpool.get("pending")),
                             "queued": _hex_int(txpool.get("queued"))}
        out["reachable"] = bool(blk or peers is not None or chain_id is not None)
        return out

    # ── main poll ──
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

        head_slot = head_root = None
        if head and head.get("data"):
            hm = head["data"]["header"]["message"]
            head_slot = int(hm["slot"])
            head_root = head["data"]["root"]
            snap["head"] = {"slot": head_slot, "root": head_root,
                            "proposer_index": int(hm["proposer_index"]),
                            "parent_root": hm["parent_root"],
                            "state_root": hm["state_root"]}

        wall = self._wall_slot()
        snap["wall_slot"] = wall
        snap["slot_into"] = self._slot_into()
        snap["seconds_per_slot"] = self._seconds_per_slot
        snap["slots_per_epoch"] = self._slots_per_epoch
        lag = None
        if wall is not None and head_slot is not None:
            lag = wall - head_slot
            snap["wall_lag"] = lag
        if head_slot is not None and self._slots_per_epoch:
            snap["epoch"] = head_slot // self._slots_per_epoch

        finalized_root = None
        if finality and finality.get("data"):
            d = finality["data"]
            snap["finality"] = {"finalized": d["finalized"],
                                "current_justified": d["current_justified"],
                                "previous_justified": d["previous_justified"]}
            finalized_root = d["finalized"].get("root")

        if syncing and syncing.get("data"):
            snap["syncing"] = syncing["data"]
        if peer_count and peer_count.get("data"):
            snap["peer_count"] = peer_count["data"]
        if peers and peers.get("data") is not None:
            snap["peers"] = peers["data"]

        sync_pct = atts = gas_used = base_fee = None
        if head_block:
            snap["fork"] = head_block.get("version")
            snap["execution_optimistic"] = head_block.get("execution_optimistic")
            snap["finalized_head"] = head_block.get("finalized")
            body = head_block.get("data", {}).get("message", {}).get("body", {})
            atts = len(body.get("attestations") or [])
            snap["block"] = {
                "graffiti": _decode_graffiti(body.get("graffiti")),
                "attestations": atts,
                "deposits": len(body.get("deposits") or []),
                "proposer_slashings": len(body.get("proposer_slashings") or []),
                "attester_slashings": len(body.get("attester_slashings") or []),
                "voluntary_exits": len(body.get("voluntary_exits") or []),
                "bls_changes": len(body.get("bls_to_execution_changes") or []),
            }
            agg = body.get("sync_aggregate")
            if agg and agg.get("sync_committee_bits"):
                bset = _count_bits(agg["sync_committee_bits"])
                btot = _bitfield_len(agg["sync_committee_bits"])
                snap["block"]["sync_participation"] = {"set": bset, "total": btot}
                if btot:
                    sync_pct = round(100 * bset / btot)
            payload = body.get("execution_payload")
            if payload:
                gas_used = _dec_int(payload.get("gas_used"))
                base_fee = _dec_int(payload.get("base_fee_per_gas"))
                el = {"block_number": payload.get("block_number"),
                      "block_hash": payload.get("block_hash"),
                      "timestamp": payload.get("timestamp"),
                      "gas_used": payload.get("gas_used"),
                      "gas_limit": payload.get("gas_limit"),
                      "fee_recipient": payload.get("fee_recipient"),
                      "base_fee_per_gas": payload.get("base_fee_per_gas"),
                      "transactions": len(payload.get("transactions") or [])}
                if payload.get("withdrawals") is not None:
                    el["withdrawals"] = len(payload["withdrawals"])
                if "blob_gas_used" in payload:
                    el["blob_gas_used"] = payload["blob_gas_used"]
                if "excess_blob_gas" in payload:
                    el["excess_blob_gas"] = payload["excess_blob_gas"]
                kzg = body.get("blob_kzg_commitments")
                if kzg is not None:
                    el["blob_count"] = len(kzg)
                snap["execution"] = el

        if self._genesis_time is not None:
            snap["genesis_time"] = self._genesis_time
            snap["uptime_s"] = max(0, int(time.time()) - self._genesis_time)
        snap["next_fork"] = self._next_fork(snap.get("epoch"))

        snap["recent_blocks"] = self._recent_blocks(head_slot)

        fc = self._fork_choice(head_root, finalized_root) if head_root else None
        if fc:
            snap["fork_choice"] = fc
        snap["reorgs"] = list(self._reorgs)

        el_node = self._el_node()
        if el_node is not None:
            snap["el_node"] = el_node

        self._append_series(head_slot, lag, sync_pct, atts, gas_used, base_fee)
        snap["series"] = list(self._series)
        return snap

    def run(self):
        while True:
            try:
                snap = self.poll_once()
            except Exception as e:  # never let the poll thread die
                snap = {"online": False, "ts": int(time.time()), "error": str(e)}
            with self.lock:
                self.snapshot = snap
            time.sleep(self.interval)

    def latest(self):
        with self.lock:
            return dict(self.snapshot)


# ── HTTP server ────────────────────────────────────────────────────────────--

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pharos devnet</title>
<style>
  :root {
    --bg:#070b12; --border:#1e2937; --border2:#2a3a4d; --fg:#e6edf6;
    --muted:#7d8da3; --dim:#56657c; --accent:#4aa8ff; --accent2:#7c5cff;
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
    -webkit-font-smoothing:antialiased; min-height:100vh; padding-bottom:32px;
  }
  header {
    display:flex; align-items:center; gap:18px; padding:20px 30px;
    border-bottom:1px solid var(--border);
    background:linear-gradient(180deg,#0b111b 0%, #070b1200 100%);
    position:sticky; top:0; z-index:5; backdrop-filter:blur(8px);
  }
  .brand { display:flex; align-items:baseline; gap:12px; }
  .brand h1 { margin:0; font-size:26px; font-weight:800; letter-spacing:-.02em;
    background:linear-gradient(90deg,#fff,#9fc7ff 60%,#b9a6ff);
    -webkit-background-clip:text; background-clip:text; color:transparent; }
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
  .dot.on  { background:var(--ok); box-shadow:0 0 0 0 #34d39966; animation:pulse 1.8s infinite; }
  .dot.off { background:var(--err); box-shadow:0 0 8px #f8717188; }
  @keyframes pulse { 70%{box-shadow:0 0 0 9px #34d39900;} 100%{box-shadow:0 0 0 0 #34d39900;} }

  .hero { display:grid; gap:16px; padding:26px 30px 6px;
          grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); }
  .stat { background:linear-gradient(180deg,#121b28cc,#0c121bcc);
    border:1px solid var(--border); border-radius:16px; padding:18px 20px;
    position:relative; overflow:hidden; }
  .stat::before { content:""; position:absolute; inset:0 auto 0 0; width:4px;
                  background:var(--accent); opacity:.85; }
  .stat.accent2::before { background:var(--accent2); }
  .stat.ok::before{background:var(--ok);} .stat.warn::before{background:var(--warn);}
  .stat.err::before{background:var(--err);}
  .stat .label { font-size:12px; letter-spacing:.14em; text-transform:uppercase;
                 color:var(--dim); font-weight:700; }
  .stat .val { font-size:42px; font-weight:800; line-height:1.05; margin-top:8px;
               font-variant-numeric:tabular-nums; letter-spacing:-.02em; }
  .stat .sub { font-size:13px; color:var(--muted); margin-top:5px; font-family:var(--mono); }
  .stat .val.ok{color:var(--ok);} .stat .val.warn{color:var(--warn);}
  .stat .val.err{color:var(--err);} .stat .val.accent{color:var(--accent);}

  .grid { display:grid; gap:18px; padding:18px 30px;
          grid-template-columns:repeat(auto-fit,minmax(360px,1fr)); }
  .panel { background:linear-gradient(180deg,#0e1622cc,#0a0f17cc);
    border:1px solid var(--border); border-radius:16px; padding:20px 22px;
    box-shadow:0 8px 30px #00000040; }
  .panel.wide { grid-column:1/-1; }
  .panel h2 { margin:0 0 16px; font-size:13px; text-transform:uppercase;
              letter-spacing:.16em; color:var(--accent); font-weight:700;
              display:flex; align-items:center; gap:9px; }
  .panel h2::before { content:""; width:7px; height:7px; border-radius:2px;
                      background:var(--accent); box-shadow:0 0 8px var(--accent); }
  .kv { display:grid; grid-template-columns:auto 1fr; gap:11px 18px;
        font-size:15px; align-items:baseline; }
  .kv dt { color:var(--muted); white-space:nowrap; font-weight:500; }
  .kv dd { margin:0; font-family:var(--mono); word-break:break-all; text-align:right; }
  .pill { display:inline-block; padding:3px 11px; border-radius:999px;
          font-size:12.5px; font-family:var(--mono); font-weight:600;
          border:1px solid transparent; }
  .pill.ok{background:#34d39920;color:var(--ok);border-color:#34d39940;}
  .pill.warn{background:#fbbf2420;color:var(--warn);border-color:#fbbf2440;}
  .pill.err{background:#f8717120;color:var(--err);border-color:#f8717140;}
  .pill.neutral{background:#4aa8ff18;color:var(--accent);border-color:#4aa8ff35;}
  .muted { color:var(--muted); }

  table { width:100%; border-collapse:collapse; font-size:13.5px; font-family:var(--mono); }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--border); }
  th { color:var(--dim); font-weight:600; text-transform:uppercase;
       font-size:11px; letter-spacing:.08em; }
  tbody tr:last-child td { border-bottom:none; }
  tr.missed td { color:var(--warn); opacity:.85; }
  tr.clickable { cursor:pointer; } tr.clickable:hover td { background:#4aa8ff12; }
  td.r, th.r { text-align:right; }
  .scroll { max-height:300px; overflow:auto; margin:-2px; padding:2px; }
  .scroll::-webkit-scrollbar { width:8px; height:8px; }
  .scroll::-webkit-scrollbar-thumb { background:var(--border2); border-radius:4px; }
  .detail { background:#0a0f17; font-size:12.5px; }
  .detail td { padding:10px 12px; }

  .timing { margin-bottom:18px; }
  .timing .row { display:flex; justify-content:space-between; font-size:13px;
                 color:var(--muted); margin-bottom:7px; font-family:var(--mono); }
  .bar { height:12px; background:#0a1019; border:1px solid var(--border);
         border-radius:7px; overflow:hidden; }
  .bar > span { display:block; height:100%;
                background:linear-gradient(90deg,var(--accent),var(--accent2));
                transition:width .4s ease; box-shadow:0 0 12px #4aa8ff66; }

  .reorg { margin:0 30px 4px; padding:11px 16px; border-radius:12px;
           background:#f8717118; border:1px solid #f8717140; color:#fda4a4;
           font-size:13.5px; font-family:var(--mono); }
  .ftree { overflow-x:auto; overflow-y:hidden; max-height:440px; border-radius:10px;
           scrollbar-width:none; -ms-overflow-style:none; }
  .ftree::-webkit-scrollbar { display:none; }
  .ftree svg { display:block; }
  /* new-node entrance animations (only applied to genuinely new roots) */
  @keyframes fcpop { 0%{opacity:0;transform:scale(.2);} 100%{opacity:1;transform:scale(1);} }
  @keyframes fcring { 0%{opacity:.85;transform:scale(.5);} 100%{opacity:0;transform:scale(2.6);} }
  .ftree circle.new { animation:fcpop .45s ease-out; transform-box:fill-box; transform-origin:center; }
  .ftree circle.newring { fill:none; stroke:#4aa8ff; stroke-width:2;
    animation:fcring .9s ease-out forwards; transform-box:fill-box; transform-origin:center; }
  .legend { display:flex; gap:18px; margin-top:12px; font-size:12px; color:var(--muted);
            flex-wrap:wrap; }
  .legend i { display:inline-block; width:10px; height:10px; border-radius:50%;
              margin-right:6px; vertical-align:middle; }
  .series { display:grid; grid-template-columns:auto 1fr auto; gap:9px 14px;
            align-items:center; font-size:13px; }
  .series .lbl { color:var(--muted); white-space:nowrap; }
  .series .cur { font-family:var(--mono); text-align:right; color:var(--fg); }
  svg.spark { vertical-align:middle; }
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
<div id="reorg-area"></div>

<div class="grid">
  <section class="panel wide"><h2>Fork choice</h2><div id="forkchoice"></div></section>
  <section class="panel"><h2>Chain</h2><div id="chain"></div></section>
  <section class="panel"><h2>Sync &amp; peers</h2><div id="sync"></div></section>
  <section class="panel"><h2>Validator activity</h2><div id="validator"></div></section>
  <section class="panel"><h2>Head block contents</h2><div id="block"></div></section>
  <section class="panel"><h2>Execution layer</h2><div id="execution"></div></section>
  <section class="panel"><h2>Trends</h2><div id="trends"></div></section>
  <section class="panel wide"><h2>Block history</h2><div id="history"></div></section>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const short = h => !h ? '—' : (h.length>16 ? h.slice(0,10)+'…'+h.slice(-6) : h);
const pill = (t,c) => `<span class="pill ${c}">${esc(t)}</span>`;
const cp = c => c ? `<span class="muted">ep</span> ${esc(c.epoch)} · ${short(c.root)}` : '—';
const num = n => (n===undefined||n===null) ? '—' : Number(n).toLocaleString('en-US');
const kv = rows => '<dl class="kv">'+rows.map(([k,v])=>`<dt>${k}</dt><dd>${v}</dd>`).join('')+'</dl>';
function dur(s){
  if(s==null) return '—';
  const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),sec=s%60;
  if(d) return `${d}d ${h}h`; if(h) return `${h}h ${m}m`; if(m) return `${m}m ${sec}s`;
  return `${sec}s`;
}
function stat(label,val,cls,sub){
  return `<div class="stat ${cls||''}"><div class="label">${label}</div>`+
         `<div class="val ${cls||''}">${val}</div>`+(sub?`<div class="sub">${sub}</div>`:'')+`</div>`;
}
function spark(vals,color){
  const w=130,h=30,v=vals.filter(x=>x!=null&&!isNaN(x));
  if(v.length<2) return '<span class="muted">—</span>';
  const mn=Math.min(...v),mx=Math.max(...v),rng=(mx-mn)||1;
  const pts=v.map((x,i)=>`${(i/(v.length-1)*w).toFixed(1)},${(h-2-((x-mn)/rng)*(h-4)).toFixed(1)}`).join(' ');
  return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">`+
         `<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.6"/></svg>`;
}

// ── fork-choice tree (forky-style SVG) ──
function renderForkTree(fc){
  if(!fc || !fc.nodes || !fc.nodes.length)
    return '<span class="muted">no fork-choice data</span>';
  const nodes = fc.nodes.slice().sort((a,b)=>a.slot-b.slot || (a.root<b.root?-1:1));
  const byRoot = {}; nodes.forEach(n=>byRoot[n.root]=n);
  // Roots seen on the previous render → animate only the genuinely new ones
  // (undefined on first render, so nothing animates on initial load).
  const seen = window._fcSeen;
  const canon = new Set(fc.canonical||[]);
  const heads = new Set(fc.heads||[]);
  const children = {}; nodes.forEach(n=>{ (children[n.parent]=children[n.parent]||[]).push(n); });

  // lane (y): canonical chain = lane 0; each fork branch gets its own lane.
  const laneOf={}, branchLane={}; let nextLane=1;
  function branchRoot(n){
    let cur=n;
    while(byRoot[cur.parent] && !canon.has(cur.parent)) cur=byRoot[cur.parent];
    return cur.root;
  }
  nodes.forEach(n=>{
    if(canon.has(n.root)){ laneOf[n.root]=0; return; }
    const br=branchRoot(n);
    if(branchLane[br]===undefined) branchLane[br]=nextLane++;
    laneOf[n.root]=branchLane[br];
  });

  const slots=[...new Set(nodes.map(n=>n.slot))].sort((a,b)=>a-b);
  const xIdx={}; slots.forEach((s,i)=>xIdx[s]=i);
  const colW=48,rowH=44,r=10,padX=34,padY=26;
  const maxLane=Math.max(0,...Object.values(laneOf));
  const W=padX*2+Math.max(1,slots.length-1)*colW+20;
  const H=padY*2+maxLane*rowH+24;
  const cx=n=>padX+xIdx[n.slot]*colW;
  const cy=n=>padY+laneOf[n.root]*rowH;

  let edges='',dots='',labels='';
  // slot axis labels (every node's slot, deduped)
  slots.forEach(s=>{ const x=padX+xIdx[s]*colW;
    labels+=`<text x="${x}" y="${H-6}" fill="#56657c" font-size="10" text-anchor="middle" font-family="monospace">${s}</text>`;
  });
  nodes.forEach(n=>{
    const p=byRoot[n.parent];
    if(p){ const c=canon.has(n.root)&&canon.has(p.root);
      edges+=`<path d="M${cx(p)},${cy(p)} C${(cx(p)+cx(n))/2},${cy(p)} ${(cx(p)+cx(n))/2},${cy(n)} ${cx(n)},${cy(n)}" `+
             `fill="none" stroke="${c?'#34d399':'#3a4658'}" stroke-width="${c?2.4:1.6}" opacity="${c?0.9:0.7}"/>`;
    }
  });
  nodes.forEach(n=>{
    let fill='#3a4658', strok='none';
    if(n.validity==='invalid') fill='#f87171';
    else if(n.validity==='optimistic') fill='#fbbf24';
    else if(canon.has(n.root)) fill='#34d399';
    if(n.root===fc.finalized) strok='#7c5cff';
    if(n.root===fc.head) strok='#fff';
    const ring = strok!=='none' ? `stroke="${strok}" stroke-width="2.5"` : '';
    const isHead = heads.has(n.root) && n.root!==fc.head;
    const isNew = seen && !seen.has(n.root);
    dots+=`<circle class="${isNew?'new':''}" cx="${cx(n)}" cy="${cy(n)}" r="${r}" fill="${fill}" ${ring}>`+
          `<title>slot ${n.slot}\nroot ${n.root}\nweight ${Number(n.weight).toLocaleString()}\nvalidity ${n.validity}${n.root===fc.head?'\n(head)':''}${n.root===fc.finalized?'\n(finalized)':''}</title></circle>`;
    if(isNew) dots+=`<circle class="newring" cx="${cx(n)}" cy="${cy(n)}" r="${r}"/>`;
    if(isHead) dots+=`<circle cx="${cx(n)}" cy="${cy(n)}" r="${r+4}" fill="none" stroke="#4aa8ff" stroke-width="1.3" stroke-dasharray="2 2"/>`;
  });
  window._fcSeen = new Set(nodes.map(n=>n.root));
  const legend='<div class="legend">'+
    '<span><i style="background:#34d399"></i>canonical</span>'+
    '<span><i style="background:#3a4658"></i>orphaned</span>'+
    '<span><i style="background:#fbbf24"></i>optimistic</span>'+
    '<span><i style="background:#f87171"></i>invalid</span>'+
    '<span><i style="background:#0a0f17;border:2px solid #fff"></i>head</span>'+
    '<span><i style="background:#0a0f17;border:2px solid #7c5cff"></i>finalized</span></div>';
  return `<div class="ftree"><svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`+
         edges+dots+labels+`</svg></div>`+
         `<div class="muted" style="margin-top:8px;font-size:12.5px">${nodes.length} nodes · `+
         `${(fc.heads||[]).length} head(s) · canonical depth ${(fc.canonical||[]).length}</div>`+legend;
}

let expanded = null;  // slot whose detail row is open
async function toggleBlock(slot, root){
  if(expanded===slot){ expanded=null; renderHistory(window._lastHist); return; }
  expanded=slot;
  renderHistory(window._lastHist);
  try {
    const d = await (await fetch('/api/block?id='+encodeURIComponent(root),{cache:'no-store'})).json();
    const cell = document.getElementById('detail-'+slot);
    if(cell) cell.innerHTML = blockDetailHtml(d);
  } catch(e){ const c=document.getElementById('detail-'+slot); if(c) c.textContent='fetch failed'; }
}
function blockDetailHtml(d){
  if(!d) return '<span class="muted">no detail</span>';
  return kv([
    ['proposer', '#'+num(d.proposer_index)],
    ['attestations', num(d.attestations)],
    ['deposits', num(d.deposits)],
    ['slashings', `${num(d.proposer_slashings)}p / ${num(d.attester_slashings)}a`],
    ['exits / bls', `${num(d.voluntary_exits)} / ${num(d.bls_changes)}`],
    ['graffiti', d.graffiti?esc(d.graffiti):'<span class="muted">—</span>'],
    ['EL block', d.el_block_number!=null?('#'+num(d.el_block_number)):'—'],
    ['EL txs', num(d.transactions)],
    ['parent', `<span class="muted">${short(d.parent_root)}</span>`],
  ]);
}
function renderHistory(rb){
  window._lastHist = rb;
  if(!rb || !rb.length){ $('history').innerHTML='<span class="muted">no history</span>'; return; }
  let h='<div class="scroll"><table><thead><tr><th>slot</th><th>proposer</th>'+
        '<th>root</th><th class="r">status</th></tr></thead><tbody>';
  for(const b of rb){
    if(b.missed){ h+=`<tr class="missed"><td>${b.slot}</td><td colspan="3">— missed —</td></tr>`; continue; }
    const open = expanded===b.slot;
    h+=`<tr class="clickable" onclick="toggleBlock(${b.slot},'${b.root}')">`+
       `<td>${b.slot}</td><td>#${b.proposer_index}</td>`+
       `<td class="muted">${short(b.root)}</td>`+
       `<td class="r">${open?'▼':'▸'}</td></tr>`;
    if(open) h+=`<tr class="detail"><td colspan="4" id="detail-${b.slot}">loading…</td></tr>`;
  }
  h+='</tbody></table></div>';
  $('history').innerHTML=h;
}

function render(s){
  if(!s.online){
    $('status').innerHTML = '<span class="dot off"></span>node offline';
    $('hero').innerHTML=''; $('reorg-area').innerHTML='';
    for(const id of ['forkchoice','chain','sync','validator','block','execution','trends','history'])
      $(id).innerHTML = '<span class="muted">waiting for pharos Beacon API…</span>';
    return;
  }
  const age = Math.max(0, Math.floor(Date.now()/1000) - s.ts);
  $('status').innerHTML = `<span class="dot on"></span>live · ${age}s ago`;
  $('node-version').textContent = s.node_version || '';

  const head=s.head||{}, fin=s.finality||{}, sy=s.syncing||{};
  const lag=s.wall_lag;
  const lagCls = lag===undefined?'':(lag<=0?'ok':(lag<=2?'warn':'err'));
  const lagTxt = lag===undefined?'—':((lag<=0?'':'+')+lag);

  const nf=s.next_fork;
  const forkSub = nf?`next: ep ${nf.epoch}${nf.eta_s!=null?` · ${dur(nf.eta_s)}`:''}`:'latest fork';
  $('hero').innerHTML =
    stat('Fork', s.fork?esc(s.fork.toUpperCase()):'—','accent',forkSub) +
    stat('Head slot', num(head.slot),'',`wall ${num(s.wall_slot)}`) +
    stat('Epoch', num(s.epoch),'accent2') +
    stat('Wall lag', lagTxt,lagCls,lag===undefined?'':'slots behind tip') +
    stat('Peers', num((s.peer_count||{}).connected),'',
         (s.peers&&s.peers.length)?`${s.peers.length} listed`:'as reported') +
    stat('Uptime', dur(s.uptime_s),'','since genesis');

  // reorg banner (most recent few)
  const ro = s.reorgs||[];
  $('reorg-area').innerHTML = ro.length
    ? ro.slice(0,3).map(r=>`<div class="reorg">⟲ reorg: ${r.depth} block(s) orphaned `+
        `from slot ${r.slot==null?'?':r.slot} · old ${short(r.old_head)} → new ${short(r.new_head)}</div>`).join('')
    : '';

  // Fork-choice tree: only rebuild the SVG when the data actually changes
  // (new node, head move, reorg, finalized move) — rebuilding every second
  // would reset scroll and re-run animations. When it does change, pin to the
  // right INSTANTLY (no smooth scroll), so existing nodes shift one column left
  // and the new node pops in — instead of the whole tree re-scrolling.
  {
    const host = $('forkchoice');
    const fc = s.fork_choice;
    const last = fc && fc.nodes.length ? fc.nodes[fc.nodes.length-1].root : '';
    const sig = fc ? `${fc.head}|${fc.nodes.length}|${last}|${fc.finalized}` : 'none';
    if(sig !== window._fcSig){
      window._fcSig = sig;
      const prev = host.querySelector('.ftree');
      const stick = !prev ||
        (prev.scrollWidth - prev.scrollLeft - prev.clientWidth < 60);
      host.innerHTML = renderForkTree(fc);
      const ft = host.querySelector('.ftree');
      if(ft && stick) ft.scrollLeft = ft.scrollWidth;
    }
  }

  $('chain').innerHTML = kv([
    ['fork', s.fork?pill(s.fork,'neutral'):'—'],
    ['head slot', num(head.slot)],
    ['head root', `<span class="muted">${short(head.root)}</span>`],
    ['parent root', `<span class="muted">${short(head.parent_root)}</span>`],
    ['epoch', num(s.epoch)],
    ['wall slot', num(s.wall_slot)],
    ['wall lag', pill(lagTxt+' slots', lagCls||'neutral')],
    ['justified', cp(fin.current_justified)],
    ['finalized', cp(fin.finalized)],
  ]);

  const b2 = v => pill(v?'true':'false', v?'warn':'ok');
  let html = kv([
    ['syncing', b2(sy.is_syncing)],
    ['optimistic', b2(sy.is_optimistic)],
    ['el offline', pill(sy.el_offline?'true':'false', sy.el_offline?'err':'ok')],
    ['sync distance', num(sy.sync_distance)],
    ['connected', num((s.peer_count||{}).connected)],
  ]);
  const peers=s.peers||[];
  if(peers.length){
    html+='<div class="scroll" style="margin-top:14px"><table><thead><tr>'+
          '<th>peer</th><th>state</th><th>dir</th></tr></thead><tbody>';
    for(const p of peers)
      html+=`<tr><td>${short(p.peer_id)}</td><td>${esc(p.state||'?')}</td><td>${esc(p.direction||'?')}</td></tr>`;
    html+='</tbody></table></div>';
  } else html+='<p class="muted" style="margin:14px 0 0;font-size:13.5px">no peers listed by pharos API</p>';
  $('sync').innerHTML=html;

  let v='';
  if(s.slot_into!=null && s.seconds_per_slot){
    const pct=Math.min(100,Math.round(100*s.slot_into/s.seconds_per_slot));
    v+=`<div class="timing"><div class="row"><span>slot timing</span>`+
       `<span>t+${s.slot_into}s / ${s.seconds_per_slot}s</span></div>`+
       `<div class="bar"><span style="width:${pct}%"></span></div></div>`;
  }
  const sp=(s.block||{}).sync_participation;
  if(sp&&sp.total){
    const pct=Math.round(100*sp.set/sp.total);
    const cls=pct>=66?'ok':(pct>=33?'warn':'err');
    v+=`<div class="timing"><div class="row"><span>sync committee</span>`+
       `<span>${sp.set}/${sp.total} · ${pct}%</span></div>`+
       `<div class="bar"><span style="width:${pct}%;background:var(--${cls})"></span></div></div>`;
  }
  v+='<div class="muted" style="font-size:13px">recent block proposers in the history panel below ↓</div>';
  $('validator').innerHTML=v;

  const bl=s.block;
  $('block').innerHTML = bl ? kv([
    ['graffiti', bl.graffiti?esc(bl.graffiti):'<span class="muted">—</span>'],
    ['attestations', num(bl.attestations)],
    ['deposits', num(bl.deposits)],
    ['proposer slashings', num(bl.proposer_slashings)],
    ['attester slashings', num(bl.attester_slashings)],
    ['voluntary exits', num(bl.voluntary_exits)],
    ['bls changes', num(bl.bls_changes)],
  ]) : '<span class="muted">no head block yet</span>';

  // EL panel: pharos's view + (if available) direct EL RPC.
  const el=s.execution, eln=s.el_node;
  let elh='';
  if(!el){ elh='<p class="muted">pre-merge head — no execution payload</p>'; }
  else {
    const gp=(el.gas_used!=null&&el.gas_limit)?Math.round(100*Number(el.gas_used)/Number(el.gas_limit)):null;
    const rows=[
      ['payload', s.execution_optimistic?pill('OPTIMISTIC','warn'):pill('VALID','ok')],
      ['block #', num(el.block_number)],
      ['block hash', `<span class="muted">${short(el.block_hash)}</span>`],
      ['transactions', num(el.transactions)],
      ['gas', `${num(el.gas_used)} / ${num(el.gas_limit)}`+(gp!=null?` <span class="muted">(${gp}%)</span>`:'')],
      ['base fee', num(el.base_fee_per_gas)],
      ['fee recipient', `<span class="muted">${short(el.fee_recipient)}</span>`],
    ];
    if(el.withdrawals!==undefined) rows.push(['withdrawals', num(el.withdrawals)]);
    if(el.blob_count!==undefined) rows.push(['blobs', el.blob_count]);
    if(el.blob_gas_used!==undefined) rows.push(['blob gas used', num(el.blob_gas_used)]);
    elh=kv(rows);
  }
  if(eln){
    const rows=[
      ['EL reachable', eln.reachable?pill('yes','ok'):pill('no','err')],
      ['EL syncing', eln.syncing==null?'—':pill(eln.syncing?'true':'false', eln.syncing?'warn':'ok')],
      ['EL block #', num(eln.number)],
      ['EL peers', num(eln.peer_count)],
      ['chain id', num(eln.chain_id)],
    ];
    if(eln.txpool) rows.push(['txpool', `${num(eln.txpool.pending)} pend · ${num(eln.txpool.queued)} queued`]);
    elh += `<div style="margin-top:14px;border-top:1px solid var(--border);padding-top:14px">`+
           `<div class="muted" style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:10px">EL node (direct RPC)</div>`+
           kv(rows)+`</div>`;
  }
  $('execution').innerHTML=elh;

  // Trends (sparklines)
  const ser=s.series||[];
  if(ser.length<2){ $('trends').innerHTML='<span class="muted">collecting samples…</span>'; }
  else {
    const col=(k,c)=>{ const vals=ser.map(x=>x[k]); const cur=vals[vals.length-1];
      return `<span class="lbl">${k}</span>${spark(vals,c)}<span class="cur">${cur==null?'—':num(cur)}</span>`; };
    $('trends').innerHTML='<div class="series">'+
      col('lag','#f87171')+col('sync_pct','#34d399')+col('atts','#4aa8ff')+
      col('gas','#7c5cff')+col('base_fee','#fbbf24')+'</div>'+
      `<div class="muted" style="margin-top:10px;font-size:12px">last ${ser.length} slots</div>`;
  }

  renderHistory(s.recent_blocks);
}

function clock(){ $('clock').textContent = new Date().toLocaleTimeString('en-GB'); }
async function tick(){
  try { render(await (await fetch('/data',{cache:'no-store'})).json()); }
  catch(e){ $('status').innerHTML='<span class="dot off"></span>fetch error'; }
}
clock(); setInterval(clock,1000);
tick();  setInterval(tick,1000);
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
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/" or path.startswith("/index"):
                self._send(200, PAGE, "text/html; charset=utf-8")
            elif path == "/data":
                self._send(200, json.dumps(poller.latest()), "application/json")
            elif path == "/api/block":
                q = parse_qs(parsed.query)
                bid = (q.get("id") or [""])[0]
                # Only allow 0x-roots or numeric slots through to the Beacon API.
                if not bid or not (bid.startswith("0x") or bid.isdigit()):
                    self._send(400, "bad id", "text/plain")
                    return
                self._send(200, json.dumps(poller.block_detail(bid)), "application/json")
            else:
                self._send(404, "not found", "text/plain")

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Pharos devnet dashboard")
    ap.add_argument("--beacon", default="http://127.0.0.1:5053",
                    help="pharos Beacon API base URL (default: %(default)s)")
    ap.add_argument("--el-rpc", default="",
                    help="execution-layer JSON-RPC URL for the EL panel "
                         "(e.g. http://127.0.0.1:28545); empty disables it")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address; pass 0.0.0.0 for LAN access (default: %(default)s)")
    ap.add_argument("--port", type=int, default=8080,
                    help="dashboard HTTP port (default: %(default)s)")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="Beacon API poll interval, seconds (default: %(default)s)")
    ap.add_argument("--recent-window", type=int, default=32,
                    help="block-history slot window (default: %(default)s)")
    args = ap.parse_args()

    el = ElRpc(args.el_rpc) if args.el_rpc else None
    poller = Poller(Beacon(args.beacon), args.interval, args.recent_window, el=el)
    threading.Thread(target=poller.run, daemon=True).start()

    server = ThreadingHTTPServer((args.host, args.port), make_handler(poller))
    print(f"pharos devnet dashboard → http://{args.host}:{args.port}")
    print(f"  beacon: {args.beacon}  el-rpc: {args.el_rpc or '(disabled)'}  every {args.interval}s")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
