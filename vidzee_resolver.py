#!/usr/bin/env python3
"""
Vidzee embed resolver — extracts only main streaming URLs (m3u8/mp4/embed).
Minimal requests (no playlist expansion, no segment fetching).
Modes: CLI JSON output (GitHub Actions) or Flask web server (Render).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from urllib.parse import parse_qs, quote, unquote, urlparse

try:
    import requests
except ImportError:
    requests = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    AES = None
    unpad = None

# ── constants ────────────────────────────────────────────────────────────────

STATIC_API_KEY_SECRET = "c4a8f1d7e2b9a6c3d0f5e8a1b7c4d9e2"
CORE_API_KEY_URL      = "https://core.vidzee.wtf/api-key"
DEFAULT_TEST_URL      = "https://player.vidzee.wtf/embed/movie/254"

DEFAULT_SERVERS = [
    {"server": 0, "sr": "0", "name": "Tcloud",    "flag": "US", "lang": "English"},
    {"server": 1, "sr": "1", "name": "IpCloud",   "flag": "US", "lang": "English"},
    {"server": 2, "sr": "2", "name": "Achilles",  "flag": "US", "lang": "English"},
    {"server": 3, "sr": "3", "name": "Nflix",     "flag": "US", "lang": "English"},
    {"server": 4, "sr": "4", "name": "Drag",      "flag": "US", "lang": "English"},
    {"server": 5, "sr": "5", "name": "Viet",      "flag": "VN", "lang": "Vietnamese"},
    {"server": 6, "sr": "6", "name": "Hindi",     "flag": "IN", "lang": "Hindi"},
    {"server": 7, "sr": "7", "name": "Hindi_v2",  "flag": "IN", "lang": "Hindi"},
]

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Only these are considered "main" streaming URLs worth returning
MAIN_STREAM_EXTS = (".m3u8", ".mpd", ".mp4", ".webm", ".mov", ".m4v", ".txt")

# ── crypto ───────────────────────────────────────────────────────────────────

def decrypt_core_api_key(encrypted_text: str) -> str:
    if AESGCM is None:
        raise RuntimeError("cryptography package not installed")
    raw    = base64.b64decode(re.sub(r"\s+", "", encrypted_text))
    nonce  = raw[:12]
    tag    = raw[12:28]
    cipher = raw[28:]
    key    = hashlib.sha256(STATIC_API_KEY_SECRET.encode()).digest()
    return AESGCM(key).decrypt(nonce, cipher + tag, None).decode()


def decrypt_source_link(encrypted_link: str, runtime_key: str) -> str:
    if AES is None:
        raise RuntimeError("pycryptodome not installed")
    decoded = base64.b64decode(encrypted_link).decode("utf-8", errors="ignore")
    if ":" not in decoded:
        raise ValueError("bad encrypted link format")
    iv_b64, cipher_b64 = decoded.split(":", 1)
    iv         = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(cipher_b64)
    key        = runtime_key.encode()[:32].ljust(32, b"\0")
    plain      = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)
    return plain.decode("utf-8", errors="ignore")

# ── helpers ──────────────────────────────────────────────────────────────────

def is_main_stream(url: str) -> bool:
    """Return True only for playlist/container URLs, not segments or thumbnails."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) or ext in path.split("?")[0] for ext in MAIN_STREAM_EXTS)


def parse_embed_url(url: str) -> dict:
    parsed = urlparse(url)
    parts  = [unquote(p) for p in parsed.path.split("/") if p]
    query  = parse_qs(parsed.query)
    if len(parts) >= 3 and parts[0] == "embed":
        return {
            "media_type": parts[1],
            "media_id":   parts[2],
            "season":     parts[3] if len(parts) > 3 else query.get("ss", [None])[0],
            "episode":    parts[4] if len(parts) > 4 else query.get("ep", [None])[0],
            "server":     query.get("server", [None])[0],
        }
    raise ValueError(f"Expected URL like /embed/movie/123, got: {url}")

# ── core resolver ─────────────────────────────────────────────────────────────

class VidzeeResolver:
    def __init__(self, timeout: float = 12.0):
        if requests is None:
            raise RuntimeError("requests not installed")
        self.session = requests.Session()
        self.timeout = timeout
        self._base_headers = {
            "User-Agent":      USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
        }

    def _get(self, url: str, extra_headers: dict | None = None) -> requests.Response:
        headers = {**self._base_headers, **(extra_headers or {})}
        return self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)

    # ------------------------------------------------------------------

    def resolve(self, input_url: str) -> dict:
        t0 = int(time.time() * 1000)
        out = {
            "input_url":    input_url,
            "streams":      [],   # ← ONLY main streaming URLs end up here
            "errors":       [],
            "elapsed_ms":   0,
            "status":       "error",
        }

        # 1. Parse embed URL
        try:
            embed = parse_embed_url(input_url)
        except Exception as e:
            out["errors"].append(str(e))
            out["elapsed_ms"] = int(time.time() * 1000) - t0
            return out

        # 1b. Prime session — fetch embed page to get CF cookies  (1 request)
        try:
            prime = self._get(input_url, {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            })
            if re.search(r"captcha|cf-challenge|turnstile|recaptcha", prime.text, re.I):
                out["errors"].append("Cloudflare challenge on embed page — needs FlareSolverr")
                out["elapsed_ms"] = int(time.time() * 1000) - t0
                return out
        except Exception as e:
            out["errors"].append(f"embed prime failed: {e}")

        # 2. Fetch runtime API key  (1 request)
        try:
            resp = self._get(CORE_API_KEY_URL, {
                "Origin":           "https://player.vidzee.wtf",
                "Referer":          input_url,
                "Accept":           "*/*",
                "Sec-Fetch-Site":   "cross-site",
                "Sec-Fetch-Mode":   "cors",
                "Sec-Fetch-Dest":   "empty",
            })
            resp.raise_for_status()
            runtime_key = decrypt_core_api_key(resp.text.strip())
        except Exception as e:
            out["errors"].append(f"api-key fetch failed: {e}")
            out["elapsed_ms"] = int(time.time() * 1000) - t0
            return out

        # 3. Try each server — stop after we have at least one good stream per server
        #    (1 request per server, no playlist follow-up)
        server_order = self._server_order(embed.get("server"))
        seen_urls: set[str] = set()

        for srv in server_order:
            api_url = (
                f"https://player.vidzee.wtf/api/server"
                f"?id={quote(embed['media_id'])}&sr={quote(srv['sr'])}"
            )
            if embed.get("season") and embed.get("episode"):
                api_url += f"&ss={quote(embed['season'])}&ep={quote(embed['episode'])}"

            referer = (
                input_url if srv["server"] == 0
                else f"{input_url}?server={srv['server']}"
            )
            try:
                resp = self._get(api_url, {
                    "Accept":          "*/*",
                    "Referer":         referer,
                    "Sec-Fetch-Site":  "same-origin",
                    "Sec-Fetch-Mode":  "cors",
                    "Sec-Fetch-Dest":  "empty",
                })
                if resp.status_code == 404:
                    continue          # server doesn't have this content — skip silently
                resp.raise_for_status()

                payload = resp.json()
                if isinstance(payload, dict) and payload.get("error"):
                    out["errors"].append(f"{srv['name']}: {payload['error']}")
                    continue

                for item in (payload.get("url") or []):
                    enc = item.get("link") if isinstance(item, dict) else None
                    if not enc:
                        continue
                    try:
                        url_dec = decrypt_source_link(enc, runtime_key)
                    except Exception as e:
                        out["errors"].append(f"{srv['name']}: decrypt error: {e}")
                        continue

                    if not url_dec or not is_main_stream(url_dec):
                        continue
                    if url_dec in seen_urls:
                        continue
                    seen_urls.add(url_dec)

                    out["streams"].append({
                        "server":   srv["name"],
                        "flag":     srv["flag"],
                        "lang":     srv["lang"],
                        "url":      url_dec,
                        "kind":     self._kind(url_dec),
                        "headers":  payload.get("headers") or {},
                    })

            except requests.HTTPError as e:
                out["errors"].append(f"{srv['name']}: HTTP {e.response.status_code}")
            except Exception as e:
                out["errors"].append(f"{srv['name']}: {e}")

        out["elapsed_ms"] = int(time.time() * 1000) - t0
        out["status"]     = "ok" if out["streams"] else "no_streams"
        return out

    # ------------------------------------------------------------------

    @staticmethod
    def _kind(url: str) -> str:
        path = urlparse(url).path.lower()
        if ".m3u8" in path: return "hls"
        if ".mpd"  in path: return "dash"
        if any(path.endswith(e) for e in (".mp4", ".webm", ".mov", ".m4v")): return "mp4"
        return "stream"

    @staticmethod
    def _server_order(selected: str | None) -> list[dict]:
        if selected is None:
            return DEFAULT_SERVERS
        try:
            idx = int(selected)
        except (TypeError, ValueError):
            return DEFAULT_SERVERS
        sel  = [s for s in DEFAULT_SERVERS if s["server"] == idx]
        rest = [s for s in DEFAULT_SERVERS if s["server"] != idx]
        return sel + rest


# ── Flask web app (Render) ────────────────────────────────────────────────────

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vidzee Resolver</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;padding:2rem 1rem}
  h1{font-size:1.5rem;font-weight:700;color:#a78bfa;margin-bottom:1.5rem;text-align:center}
  .card{background:#1e2130;border:1px solid #2d3148;border-radius:12px;padding:1.5rem;max-width:700px;margin:0 auto}
  input{width:100%;padding:.75rem 1rem;border-radius:8px;border:1px solid #3d4163;background:#0f1117;color:#e2e8f0;font-size:.9rem;margin-bottom:.75rem}
  input:focus{outline:none;border-color:#a78bfa}
  button{width:100%;padding:.75rem;border-radius:8px;border:none;background:#7c3aed;color:#fff;font-size:1rem;font-weight:600;cursor:pointer;transition:.15s}
  button:hover{background:#6d28d9}
  button:disabled{background:#3d4163;cursor:not-allowed}
  .results{margin-top:1.5rem}
  .stream{background:#0f1117;border:1px solid #2d3148;border-radius:8px;padding:1rem;margin-bottom:.75rem}
  .stream-header{display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem}
  .badge{font-size:.7rem;font-weight:700;padding:.2rem .5rem;border-radius:999px;background:#2d3148;color:#94a3b8;text-transform:uppercase}
  .badge.hls{background:#064e3b;color:#6ee7b7}
  .badge.dash{background:#1e3a5f;color:#93c5fd}
  .badge.mp4{background:#451a03;color:#fcd34d}
  .server-name{font-weight:600;color:#c4b5fd}
  .lang{color:#64748b;font-size:.8rem}
  .url-row{display:flex;gap:.5rem;align-items:center}
  .url-text{flex:1;font-size:.75rem;color:#94a3b8;word-break:break-all;font-family:monospace;padding:.5rem;background:#1e2130;border-radius:4px;border:1px solid #2d3148}
  .copy-btn{flex-shrink:0;padding:.4rem .75rem;border-radius:6px;border:none;background:#2d3148;color:#e2e8f0;font-size:.75rem;cursor:pointer}
  .copy-btn:hover{background:#3d4163}
  .copy-btn.copied{background:#064e3b;color:#6ee7b7}
  .errors{margin-top:.75rem;padding:.75rem;background:#1a0505;border:1px solid #7f1d1d;border-radius:8px;color:#fca5a5;font-size:.8rem}
  .errors ul{padding-left:1rem}
  .meta{text-align:center;color:#475569;font-size:.75rem;margin-top:.75rem}
  .spinner{display:none;text-align:center;color:#a78bfa;margin-top:1rem;font-size:.9rem}
  .empty{text-align:center;color:#475569;padding:1rem}
</style>
</head>
<body>
<div class="card">
  <h1>🎬 Vidzee Resolver</h1>
  <input id="url" type="text" placeholder="https://player.vidzee.wtf/embed/movie/254" value="https://player.vidzee.wtf/embed/movie/254">
  <button id="btn" onclick="resolve()">Extract Streams</button>
  <div class="spinner" id="spin">⏳ Resolving…</div>
  <div class="results" id="results"></div>
</div>
<script>
async function resolve() {
  const url = document.getElementById('url').value.trim();
  if (!url) return;
  const btn  = document.getElementById('btn');
  const spin = document.getElementById('spin');
  const out  = document.getElementById('results');
  btn.disabled = true;
  spin.style.display = 'block';
  out.innerHTML = '';
  try {
    const r = await fetch('/resolve?url=' + encodeURIComponent(url));
    const d = await r.json();
    let html = '';
    if (d.streams && d.streams.length) {
      d.streams.forEach((s, i) => {
        html += `<div class="stream">
          <div class="stream-header">
            <span class="server-name">${s.server}</span>
            <span class="badge ${s.kind}">${s.kind.toUpperCase()}</span>
            <span class="badge">${s.flag}</span>
            <span class="lang">${s.lang}</span>
          </div>
          <div class="url-row">
            <div class="url-text">${escHtml(s.url)}</div>
            <button class="copy-btn" onclick="copy(this, '${escAttr(s.url)}')">Copy</button>
          </div>
        </div>`;
      });
    } else {
      html += '<div class="empty">No streams found.</div>';
    }
    if (d.errors && d.errors.length) {
      html += '<div class="errors"><strong>Errors / skipped:</strong><ul>' +
        d.errors.map(e => `<li>${escHtml(e)}</li>`).join('') + '</ul></div>';
    }
    html += `<div class="meta">Resolved in ${d.elapsed_ms}ms · status: ${d.status}</div>`;
    out.innerHTML = html;
  } catch(e) {
    out.innerHTML = '<div class="errors">Request failed: ' + e + '</div>';
  }
  btn.disabled = false;
  spin.style.display = 'none';
}
function copy(btn, url) {
  navigator.clipboard.writeText(url).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
  });
}
function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function escAttr(s) { return s.replace(/'/g,"\\'"); }
document.getElementById('url').addEventListener('keydown', e => { if (e.key==='Enter') resolve(); });
</script>
</body>
</html>"""


def create_flask_app() -> "Flask":
    from flask import Flask, request, jsonify, Response
    app = Flask(__name__)
    resolver = VidzeeResolver()

    @app.route("/")
    def index():
        return Response(HTML_PAGE, mimetype="text/html")

    @app.route("/resolve")
    def resolve():
        url = request.args.get("url", DEFAULT_TEST_URL)
        result = resolver.resolve(url)
        return jsonify(result)

    @app.route("/health")
    def health():
        return jsonify({"ok": True})

    return app


# ── entry point ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vidzee stream resolver")
    parser.add_argument("url", nargs="?", default=DEFAULT_TEST_URL, help="Embed URL to resolve")
    parser.add_argument("--serve", action="store_true", help="Run Flask web server")
    parser.add_argument("--host",  default="0.0.0.0",  help="Flask host")
    parser.add_argument("--port",  type=int, default=int(os.environ.get("PORT", 8787)), help="Flask port")
    args = parser.parse_args(argv)

    if args.serve:
        app = create_flask_app()
        print(f"Starting server on http://{args.host}:{args.port}")
        app.run(host=args.host, port=args.port)
        return 0

    resolver = VidzeeResolver()
    result   = resolver.resolve(args.url)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())