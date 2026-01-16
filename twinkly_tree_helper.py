#! /bin/python3
"""Twinkly Tree Helper (v1)

Goal
----
A tiny Linux-friendly CLI to help you *physically* find specific LEDs (especially
string ends) by lighting individual lamps or running simple chase patterns.

This talks directly to the Twinkly local LAN HTTP API (xled v1).

What it can do (v1)
-------------------
- Discover devices on your LAN via UDP broadcast (port 5555)
- Login/verify to obtain an auth token
- Set mode to `rt` and push single-frame data to /xled/v1/led/rt/frame
- Light a single LED index (optionally blink)
- Chase a single lit LED across a range
- "Find end" helper that blinks the last LED (or last N LEDs)

Notes / assumptions
-------------------
- Uses the REST endpoint /xled/v1/led/rt/frame (HTTP). Docs mention a UDP realtime
  protocol too; HTTP is simpler and works for the "mapping" use case.
- Color bytes are sent as R,G,B for 3-bytes-per-led devices.
  For 4-bytes-per-led devices (RGBW), this script sends R,G,B,0.
- LED index 0 is the LED closest to the controller/driver; last LED is the far end.

References
----------
- xled-docs REST API: /xled/v1/login, /xled/v1/verify, /xled/v1/led/mode, /xled/v1/led/rt/frame
- xled-docs protocol details: discovery UDP broadcast to port 5555 and RGB byte order

Usage examples
--------------
# 1) Discover Twinkly devices
./twinkly_tree_helper_v1.py discover

# 2) Print info, including LED count
./twinkly_tree_helper_v1.py info --ip 192.168.1.123

# 3) Blink the very last LED (good for finding the end)
./twinkly_tree_helper_v1.py find-end --ip 192.168.1.123

# 4) Chase the last 50 LEDs backward to the controller (helps trace a strand)
./twinkly_tree_helper_v1.py chase --ip 192.168.1.123 --start -1 --end -50 --delay 0.08

# 5) Light a specific LED index (0-based)
./twinkly_tree_helper_v1.py light --ip 192.168.1.123 --led 299 --rgb 255,0,0

"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


DEFAULT_TIMEOUT_S = 3.0
DISCOVERY_PORT = 5555
DISCOVERY_PAYLOAD = b"\x01discover"


def _http_json(
    url: str,
    method: str,
    body_obj: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> dict:
    data = None
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    if body_obj is not None:
        payload = json.dumps(body_obj).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
        data = payload

    req = urllib.request.Request(url=url, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} for {method} {url}: {raw}") from e


def _http_octet_stream(
    url: str,
    body_bytes: bytes,
    headers: Optional[dict] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> dict:
    req_headers = {"Content-Type": "application/octet-stream", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url=url, data=body_bytes, method="POST", headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} for POST {url}: {raw}") from e


def discover(timeout_s: float = 0.8) -> List[str]:
    """Return a list of IPs of Twinkly devices discovered on the local network."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout_s)

    # Send broadcast on all interfaces (best-effort)
    sock.sendto(DISCOVERY_PAYLOAD, ("255.255.255.255", DISCOVERY_PORT))

    ips: List[str] = []
    start = time.time()
    while True:
        try:
            data, _addr = sock.recvfrom(1024)
        except socket.timeout:
            break
        # First 4 bytes are reversed IP octets per docs; we can also trust sender address.
        if len(data) >= 6 and data[4:6] == b"OK":
            ip = ".".join(str(b) for b in data[3::-1])
            if ip not in ips:
                ips.append(ip)
        if time.time() - start > timeout_s:
            break

    sock.close()
    return ips


def _cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "twinkly-tree-helper"
    return Path.home() / ".cache" / "twinkly-tree-helper"


@dataclass
class TokenInfo:
    token_b64: str
    expires_at_unix: float
    # stored for debugging / future expansion
    ip: str


class TwinklyClient:
    def __init__(self, ip: str, timeout_s: float = DEFAULT_TIMEOUT_S):
        self.ip = ip
        self.base = f"http://{ip}/xled/v1"
        self.timeout_s = timeout_s
        self._token: Optional[TokenInfo] = None

    def _token_path(self) -> Path:
        return _cache_dir() / f"{self.ip}.token.json"

    def _load_cached_token(self) -> Optional[TokenInfo]:
        p = self._token_path()
        if not p.exists():
            return None
        try:
            obj = json.loads(p.read_text("utf-8"))
            return TokenInfo(
                token_b64=str(obj["token_b64"]),
                expires_at_unix=float(obj["expires_at_unix"]),
                ip=self.ip,
            )
        except Exception:
            return None

    def _save_cached_token(self, ti: TokenInfo) -> None:
        p = self._token_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(
                {
                    "token_b64": ti.token_b64,
                    "expires_at_unix": ti.expires_at_unix,
                    "ip": ti.ip,
                },
                indent=2,
            ),
            "utf-8",
        )

    def _auth_headers(self) -> Dict[str, str]:
        if not self._token:
            self.login()
        assert self._token
        return {"X-Auth-Token": self._token.token_b64}

    def gestalt(self) -> dict:
        return _http_json(f"{self.base}/gestalt", "GET", timeout_s=self.timeout_s)

    def get_mode(self) -> str:
        j = _http_json(
            f"{self.base}/led/mode",
            "GET",
            headers=self._auth_headers(),
            timeout_s=self.timeout_s,
        )
        return str(j.get("mode", ""))

    def set_mode(self, mode: str) -> None:
        _http_json(
            f"{self.base}/led/mode",
            "POST",
            body_obj={"mode": mode},
            headers=self._auth_headers(),
            timeout_s=self.timeout_s,
        )

    def login(self) -> None:
        # If we have a cached token that likely isn't expired, try it first.
        cached = self._load_cached_token()
        if cached and cached.expires_at_unix > time.time() + 30:
            self._token = cached
            try:
                # Some firmwares accept token without re-verify; others require verify.
                _http_json(
                    f"{self.base}/led/mode",
                    "GET",
                    headers={"X-Auth-Token": cached.token_b64},
                    timeout_s=self.timeout_s,
                )
                return
            except Exception:
                self._token = None

        challenge = os.urandom(32)
        challenge_b64 = base64.b64encode(challenge).decode("ascii")
        login_resp = _http_json(
            f"{self.base}/login",
            "POST",
            body_obj={"challenge": challenge_b64},
            timeout_s=self.timeout_s,
        )
        token_b64 = str(login_resp["authentication_token"])
        expires_in = float(login_resp.get("authentication_token_expires_in", 14400))
        chall_resp = login_resp.get("challenge-response")

        # Verify step (required before most authenticated endpoints)
        _http_json(
            f"{self.base}/verify",
            "POST",
            body_obj={"challenge-response": chall_resp} if chall_resp else {},
            headers={"X-Auth-Token": token_b64},
            timeout_s=self.timeout_s,
        )

        ti = TokenInfo(token_b64=token_b64, expires_at_unix=time.time() + expires_in, ip=self.ip)
        self._token = ti
        self._save_cached_token(ti)

    def rt_frame(self, frame: bytes) -> None:
        _http_octet_stream(
            f"{self.base}/led/rt/frame",
            frame,
            headers=self._auth_headers(),
            timeout_s=self.timeout_s,
        )


def _parse_rgb(s: str) -> Tuple[int, int, int]:
    parts = s.split(",")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("RGB must look like 255,0,0")
    vals = tuple(int(p.strip()) for p in parts)
    if any(v < 0 or v > 255 for v in vals):
        raise argparse.ArgumentTypeError("RGB values must be 0..255")
    return vals  # type: ignore[return-value]


def _resolve_index(idx: int, nleds: int) -> int:
    # Allow negative indices like Python lists: -1 means last LED
    if idx < 0:
        idx = nleds + idx
    if idx < 0 or idx >= nleds:
        raise ValueError(f"LED index out of range: {idx} (nleds={nleds})")
    return idx


def build_frame_single(
    nleds: int,
    bytes_per_led: int,
    lit_indices: Iterable[int],
    rgb: Tuple[int, int, int],
) -> bytes:
    """Build a single-frame payload with only selected indices lit."""
    if bytes_per_led not in (3, 4):
        # best-effort; many devices are 3 (RGB) or 4 (RGBW)
        raise ValueError(f"Unsupported bytes_per_led={bytes_per_led}; expected 3 or 4")

    r, g, b = rgb
    lit = set(lit_indices)
    out = bytearray(nleds * bytes_per_led)

    for i in range(nleds):
        if i in lit:
            base = i * bytes_per_led
            out[base + 0] = r
            out[base + 1] = g
            out[base + 2] = b
            if bytes_per_led == 4:
                out[base + 3] = 0  # white channel off by default

    return bytes(out)


def cmd_discover(_args: argparse.Namespace) -> int:
    ips = discover(timeout_s=0.9)
    if not ips:
        print("No Twinkly devices found via UDP broadcast.")
        return 1

    for ip in ips:
        try:
            c = TwinklyClient(ip)
            g = c.gestalt()
            name = g.get("device_name") or g.get("deviceName") or "(unknown)"
            n = g.get("number_of_led")
            prof = g.get("led_profile")
            bpl = g.get("bytes_per_led")
            print(f"{ip}\t{name}\tleds={n}\tprofile={prof}\tbytes_per_led={bpl}")
        except Exception as e:
            print(f"{ip}\t(error reading gestalt: {e})")

    return 0


def cmd_info(args: argparse.Namespace) -> int:
    c = TwinklyClient(args.ip, timeout_s=args.timeout)
    g = c.gestalt()
    # auth only when needed
    try:
        mode = c.get_mode()
    except Exception:
        mode = "(auth required / unavailable)"

    print(json.dumps({"ip": args.ip, "mode": mode, "gestalt": g}, indent=2))
    return 0


def _with_rt_mode(c: TwinklyClient):
    """Context manager-ish helper: set rt mode and restore previous mode on exit."""
    class _Ctx:
        def __init__(self):
            self.prev: Optional[str] = None

        def __enter__(self):
            try:
                self.prev = c.get_mode()
            except Exception:
                self.prev = None
            c.set_mode("rt")
            return self

        def __exit__(self, exc_type, exc, tb):
            # Best-effort restore.
            if self.prev:
                try:
                    c.set_mode(self.prev)
                except Exception:
                    pass
            return False

    return _Ctx()


def cmd_light(args: argparse.Namespace) -> int:
    c = TwinklyClient(args.ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    idx = _resolve_index(args.led, nleds)
    rgb = args.rgb

    with _with_rt_mode(c):
        if args.blink_hz:
            period = 1.0 / float(args.blink_hz)
            for _ in range(args.blink_cycles):
                c.rt_frame(build_frame_single(nleds, bpl, [idx], rgb))
                time.sleep(period / 2)
                c.rt_frame(build_frame_single(nleds, bpl, [], rgb))
                time.sleep(period / 2)
        else:
            c.rt_frame(build_frame_single(nleds, bpl, [idx], rgb))
            if args.hold_s > 0:
                time.sleep(args.hold_s)

    return 0


def cmd_find_end(args: argparse.Namespace) -> int:
    c = TwinklyClient(args.ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    count = max(1, int(args.last_n))
    idxs = list(range(nleds - count, nleds))

    with _with_rt_mode(c):
        period = 1.0 / float(args.blink_hz)
        for _ in range(args.blink_cycles):
            c.rt_frame(build_frame_single(nleds, bpl, idxs, args.rgb))
            time.sleep(period / 2)
            c.rt_frame(build_frame_single(nleds, bpl, [], args.rgb))
            time.sleep(period / 2)

    return 0


def cmd_chase(args: argparse.Namespace) -> int:
    c = TwinklyClient(args.ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    start = _resolve_index(args.start, nleds) if args.start is not None else 0
    end = _resolve_index(args.end, nleds) if args.end is not None else (nleds - 1)

    step = int(args.step)
    if step == 0:
        raise ValueError("step cannot be 0")

    # If user gave start > end but positive step, invert automatically
    if start > end and step > 0:
        step = -step
    if start < end and step < 0:
        step = -step

    path = list(range(start, end + (1 if step > 0 else -1), step))
    if not path:
        return 0

    with _with_rt_mode(c):
        for _ in range(max(1, int(args.loops))):
            for i in path:
                c.rt_frame(build_frame_single(nleds, bpl, [i], args.rgb))
                time.sleep(float(args.delay))

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Twinkly Tree Helper (v1)")
    p.set_defaults(func=None)

    sub = p.add_subparsers(dest="cmd", required=True)

    p_disc = sub.add_parser("discover", help="Discover Twinkly devices on LAN")
    p_disc.set_defaults(func=cmd_discover)

    p_info = sub.add_parser("info", help="Print device gestalt + current mode")
    p_info.add_argument("--ip", required=True, help="Device IP")
    p_info.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    p_info.set_defaults(func=cmd_info)

    p_light = sub.add_parser("light", help="Light a specific LED index (0-based; allow -1 for last)")
    p_light.add_argument("--ip", required=True)
    p_light.add_argument("--led", type=int, required=True)
    p_light.add_argument("--rgb", type=_parse_rgb, default=(255, 0, 0))
    p_light.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    p_light.add_argument("--hold-s", type=float, default=0.0, help="Hold time after setting (non-blink mode)")
    p_light.add_argument("--blink-hz", type=float, default=0.0, help="If >0, blink at this frequency")
    p_light.add_argument("--blink-cycles", type=int, default=10)
    p_light.set_defaults(func=cmd_light)

    p_end = sub.add_parser("find-end", help="Blink the last LED (or last N LEDs)")
    p_end.add_argument("--ip", required=True)
    p_end.add_argument("--last-n", type=int, default=1)
    p_end.add_argument("--rgb", type=_parse_rgb, default=(255, 0, 0))
    p_end.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    p_end.add_argument("--blink-hz", type=float, default=2.0)
    p_end.add_argument("--blink-cycles", type=int, default=20)
    p_end.set_defaults(func=cmd_find_end)

    p_chase = sub.add_parser("chase", help="Chase a single lit LED across a range")
    p_chase.add_argument("--ip", required=True)
    p_chase.add_argument("--start", type=int, default=0, help="Start index (allow negative, e.g. -1)")
    p_chase.add_argument("--end", type=int, default=-1, help="End index (allow negative)")
    p_chase.add_argument("--step", type=int, default=1)
    p_chase.add_argument("--delay", type=float, default=0.05)
    p_chase.add_argument("--loops", type=int, default=1)
    p_chase.add_argument("--rgb", type=_parse_rgb, default=(255, 0, 0))
    p_chase.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    p_chase.set_defaults(func=cmd_chase)

    args = p.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
