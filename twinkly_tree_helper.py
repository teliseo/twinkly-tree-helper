#! /bin/python3
"""Twinkly Tree Helper (v2)

Objective
---------
A small Linux-friendly CLI to help you *physically* locate LEDs (especially the
end of each physical string) by lighting specific lamps or running simple chase
patterns, using Twinkly's local LAN API.

v2 changes
----------
- Keep a *single* filename (this file) and track the revision in-code.
- `discover` can write a current-directory parameter file that defines named
  *strings* (segments) derived from each device's `device_name`.
- Other commands can target a string via `--string NAME` instead of `--ip`.

String naming and segmentation
------------------------------
`discover --write-params` creates one or more *string* entries per Twinkly device.
Each string name is:

    <device_name><suffix>

where suffix is 'a', 'b', 'c', ... for each segment.

Segmentation heuristic (no extra user input required):
- If the device LED count is divisible by 300, it is split into 300-LED segments.
  (e.g., 600 -> two strings: 'a' and 'b')
- Otherwise, it is treated as a single string (suffix 'a')

Parameter file format
---------------------
JSON file in the current working directory.
Default name: ./twinkly_strings.json

Example entry:
  {
    "MyTreea": {"ip":"192.168.1.10","start":0,"length":300,"device_name":"MyTree",...},
    "MyTreeb": {"ip":"192.168.1.10","start":300,"length":300,"device_name":"MyTree",...}
  }

Notes / assumptions
-------------------
- Uses Twinkly's local HTTP API under /xled/v1.
- Uses realtime HTTP frames (/xled/v1/led/rt/frame) because it's simple and fits
  the "find the LED" use-case.
- LED indexing is 0-based within the addressed device; for `--string`, indexes are
  0-based within the segment (and negative indexes work like Python).

"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


VERSION = 2
DEFAULT_TIMEOUT_S = 3.0

DISCOVERY_PORT = 5555
DISCOVERY_PAYLOAD = b"discover"

DEFAULT_PARAMS_FILENAME = "twinkly_strings.json"
DEFAULT_SEGMENT_LEN = 300


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


def discover(timeout_s: float = 0.9) -> List[str]:
    """Return a list of IPs of Twinkly devices discovered on the local network."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout_s)

    sock.sendto(DISCOVERY_PAYLOAD, ("255.255.255.255", DISCOVERY_PORT))

    ips: List[str] = []
    start = time.time()
    while True:
        try:
            data, _addr = sock.recvfrom(1024)
        except socket.timeout:
            break
        # First 4 bytes are reversed IP octets per docs.
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
        cached = self._load_cached_token()
        if cached and cached.expires_at_unix > time.time() + 30:
            self._token = cached
            try:
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
    # Allow negative indices like Python lists: -1 means last
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
                out[base + 3] = 0  # white channel off

    return bytes(out)


def _params_path(path_arg: Optional[str]) -> Path:
    if path_arg:
        return Path(path_arg)
    return Path.cwd() / DEFAULT_PARAMS_FILENAME


def _load_params(path: Path) -> Dict[str, dict]:
    try:
        return json.loads(path.read_text("utf-8"))
    except FileNotFoundError as e:
        raise RuntimeError(
            f"Params file not found: {path}. Run: discover --write-params"
        ) from e


def _save_params(path: Path, data: Dict[str, dict]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "
", "utf-8")


def _suffix_letters(n: int) -> List[str]:
    # 'a'..'z', then 'aa'.. (basic spreadsheet-style)
    out: List[str] = []
    i = 0
    while len(out) < n:
        x = i
        s = ""
        while True:
            s = chr(ord("a") + (x % 26)) + s
            x = x // 26 - 1
            if x < 0:
                break
        out.append(s)
        i += 1
    return out


def _segment_count(nleds: int, segment_len: int) -> int:
    if segment_len <= 0:
        return 1
    if nleds % segment_len == 0:
        return max(1, nleds // segment_len)
    return 1


def _string_target_from_args(args: argparse.Namespace) -> Tuple[str, int, int]:
    """Return (ip, start_offset, length) based on either --ip or --string."""
    if getattr(args, "ip", None):
        return (args.ip, 0, -1)

    name = getattr(args, "string", None)
    if not name:
        raise RuntimeError("Internal error: neither --ip nor --string provided")

    params = _load_params(_params_path(getattr(args, "params", None)))
    if name not in params:
        known = ", ".join(sorted(params.keys()))
        raise RuntimeError(f"Unknown string '{name}'. Known: {known}")

    ent = params[name]
    return (str(ent["ip"]), int(ent["start"]), int(ent["length"]))


def _add_target_args(ap: argparse.ArgumentParser) -> None:
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--ip", help="Device IP")
    g.add_argument("--string", help="Named string from params file (see discover --write-params)")
    ap.add_argument(
        "--params",
        help=f"Params file path (default: ./{DEFAULT_PARAMS_FILENAME})",
        default=None,
    )


def cmd_discover(args: argparse.Namespace) -> int:
    ips = discover(timeout_s=float(args.discovery_timeout))
    if not ips:
        print("No Twinkly devices found via UDP broadcast.")
        return 1

    params_out: Dict[str, dict] = {}

    for ip in ips:
        try:
            c = TwinklyClient(ip, timeout_s=args.timeout)
            g = c.gestalt()
            device_name = g.get("device_name") or g.get("deviceName") or "(unknown)"
            nleds = int(g.get("number_of_led"))
            bpl = int(g.get("bytes_per_led", 3))

            print(f"{ip}	{device_name}	leds={nleds}	bytes_per_led={bpl}")

            if args.write_params:
                seg_len = int(args.segment_len)
                segs = _segment_count(nleds, seg_len)
                suffixes = _suffix_letters(segs)

                for si, suf in enumerate(suffixes):
                    start = si * seg_len if segs > 1 else 0
                    length = seg_len if segs > 1 else nleds
                    key = f"{device_name}{suf}"
                    if key in params_out:
                        # If duplicate device_name on LAN, disambiguate by IP.
                        key = f"{device_name}{suf}_{ip}"

                    params_out[key] = {
                        "ip": ip,
                        "device_name": device_name,
                        "start": start,
                        "length": length,
                        "number_of_led": nleds,
                        "bytes_per_led": bpl,
                        "segment_len": seg_len,
                        "version": VERSION,
                    }

        except Exception as e:
            print(f"{ip}	(error reading gestalt: {e})")

    if args.write_params:
        path = _params_path(args.params_out)
        _save_params(path, params_out)
        print(f"
Wrote {len(params_out)} string entries to: {path}")

    return 0


def cmd_info(args: argparse.Namespace) -> int:
    ip, start, length = _string_target_from_args(args)

    c = TwinklyClient(ip, timeout_s=args.timeout)
    g = c.gestalt()

    try:
        mode = c.get_mode()
    except Exception:
        mode = "(auth required / unavailable)"

    out = {
        "version": VERSION,
        "target": {"ip": ip, "start": start, "length": length, "string": getattr(args, "string", None)},
        "mode": mode,
        "gestalt": g,
    }
    print(json.dumps(out, indent=2))
    return 0


def _with_rt_mode(c: TwinklyClient):
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
            if self.prev:
                try:
                    c.set_mode(self.prev)
                except Exception:
                    pass
            return False

    return _Ctx()


def cmd_light(args: argparse.Namespace) -> int:
    ip, start, seg_len = _string_target_from_args(args)

    c = TwinklyClient(ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    # Resolve LED index within segment -> device-wide index
    seg_n = seg_len if seg_len > 0 else nleds
    rel = _resolve_index(int(args.led), seg_n)
    idx = start + rel
    if idx < 0 or idx >= nleds:
        raise ValueError(f"Resolved LED index out of device range: {idx} (nleds={nleds})")

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
    ip, start, seg_len = _string_target_from_args(args)

    c = TwinklyClient(ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    seg_n = seg_len if seg_len > 0 else nleds

    count = max(1, int(args.last_n))
    # last N within the segment
    rel_idxs = list(range(seg_n - count, seg_n))
    idxs = [start + r for r in rel_idxs]

    with _with_rt_mode(c):
        period = 1.0 / float(args.blink_hz)
        for _ in range(args.blink_cycles):
            c.rt_frame(build_frame_single(nleds, bpl, idxs, args.rgb))
            time.sleep(period / 2)
            c.rt_frame(build_frame_single(nleds, bpl, [], args.rgb))
            time.sleep(period / 2)

    return 0


def cmd_chase(args: argparse.Namespace) -> int:
    ip, start, seg_len = _string_target_from_args(args)

    c = TwinklyClient(ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    seg_n = seg_len if seg_len > 0 else nleds

    start_rel = _resolve_index(int(args.start), seg_n)
    end_rel = _resolve_index(int(args.end), seg_n)

    step = int(args.step)
    if step == 0:
        raise ValueError("step cannot be 0")

    # Auto-adjust direction for user convenience
    if start_rel > end_rel and step > 0:
        step = -step
    if start_rel < end_rel and step < 0:
        step = -step

    path_rel = list(range(start_rel, end_rel + (1 if step > 0 else -1), step))
    if not path_rel:
        return 0

    with _with_rt_mode(c):
        for _ in range(max(1, int(args.loops))):
            for r in path_rel:
                idx = start + r
                c.rt_frame(build_frame_single(nleds, bpl, [idx], args.rgb))
                time.sleep(float(args.delay))

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=f"Twinkly Tree Helper (v{VERSION})")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_disc = sub.add_parser("discover", help="Discover Twinkly devices on LAN")
    p_disc.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="HTTP timeout")
    p_disc.add_argument("--discovery-timeout", type=float, default=0.9, help="UDP discovery timeout")
    p_disc.add_argument(
        "--write-params",
        action="store_true",
        help=f"Write named strings to ./{DEFAULT_PARAMS_FILENAME} (or --params-out)",
    )
    p_disc.add_argument(
        "--params-out",
        default=None,
        help=f"Output params file path (default: ./{DEFAULT_PARAMS_FILENAME})",
    )
    p_disc.add_argument(
        "--segment-len",
        type=int,
        default=DEFAULT_SEGMENT_LEN,
        help=f"Segment length used when device LED count is divisible by it (default: {DEFAULT_SEGMENT_LEN})",
    )
    p_disc.set_defaults(func=cmd_discover)

    p_info = sub.add_parser("info", help="Print device gestalt + current mode")
    _add_target_args(p_info)
    p_info.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    p_info.set_defaults(func=cmd_info)

    p_light = sub.add_parser("light", help="Light a LED index (0-based within string; allow -1 for last)")
    _add_target_args(p_light)
    p_light.add_argument("--led", type=int, required=True)
    p_light.add_argument("--rgb", type=_parse_rgb, default=(255, 0, 0))
    p_light.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    p_light.add_argument("--hold-s", type=float, default=0.0)
    p_light.add_argument("--blink-hz", type=float, default=0.0)
    p_light.add_argument("--blink-cycles", type=int, default=10)
    p_light.set_defaults(func=cmd_light)

    p_end = sub.add_parser("find-end", help="Blink the last LED (or last N) within the target string")
    _add_target_args(p_end)
    p_end.add_argument("--last-n", type=int, default=1)
    p_end.add_argument("--rgb", type=_parse_rgb, default=(255, 0, 0))
    p_end.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    p_end.add_argument("--blink-hz", type=float, default=2.0)
    p_end.add_argument("--blink-cycles", type=int, default=20)
    p_end.set_defaults(func=cmd_find_end)

    p_chase = sub.add_parser("chase", help="Chase a single lit LED across a range within the target string")
    _add_target_args(p_chase)
    p_chase.add_argument("--start", type=int, default=0, help="Start index within string (allow negative)")
    p_chase.add_argument("--end", type=int, default=-1, help="End index within string (allow negative)")
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
