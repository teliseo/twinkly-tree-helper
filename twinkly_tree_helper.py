#! /bin/python3
"""Twinkly Tree Helper (v9)

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

v3 changes
----------
- Add `strings` command to list known string names from the params file.

v4 changes
----------
- Help now shows default values (ArgumentDefaultsHelpFormatter).
- Duration/count parameters default to infinite (support special value "inf").
- RGB parsing supports "R,G,B" as well as "#RRGGBB" (and "#RRGGBBWW").
- `light` can light a *range* (like `chase`) and supports --rgb2 for interpolation.
- `chase` supports --rgb2 for interpolation.

v5 changes
----------
- Help defaults now display meaningful values (e.g. params file name, and "inf" instead of None).

v6 changes
----------
- Add help text for previously-undocumented options so defaults display consistently.
- User-facing color defaults are now shown as hex strings (e.g. "#ff0000").
- Decimal color parsing now accepts R,G,B,W for RGBW strings.

v7 changes
----------
- Keepalive refresh: when holding a static frame (e.g. light --hold-s inf), periodically resend the frame so the device does not revert to its built-in effect.

v8 changes
----------
- Make auth failures visible (info now reports the auth error instead of a vague placeholder).
- Add `login` command to explicitly authenticate and (re)write the cached token file.

v9 changes
----------
- RT keepalive is now "mode-aware": while holding, periodically re-assert mode=rt and re-send the frame, because some firmwares revert to movie even if HTTP /led/rt/frame is posted.
- Fix RGBW frame byte order to W,R,G,B as documented.

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
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


VERSION = 9
DEFAULT_TIMEOUT_S = 3.0

DISCOVERY_PORT = 5555
DISCOVERY_PAYLOAD = b"\x01discover"

DEFAULT_PARAMS_FILENAME = "twinkly_strings.json"
DEFAULT_SEGMENT_LEN = 300


Color = Tuple[int, int, int, int]  # (r,g,b,w)


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


def _clamp_u8(x: int) -> int:
    if x < 0:
        return 0
    if x > 255:
        return 255
    return x


def _parse_color(s: str) -> Color:
    s = s.strip()

    if s.startswith("#"):
        h = s[1:]
        if len(h) not in (6, 8):
            raise argparse.ArgumentTypeError("Hex color must be #RRGGBB or #RRGGBBWW")
        try:
            r = int(h[0:2], 16)
            g = int(h[2:4], 16)
            b = int(h[4:6], 16)
            w = int(h[6:8], 16) if len(h) == 8 else 0
        except ValueError as e:
            raise argparse.ArgumentTypeError("Invalid hex color") from e
        return (_clamp_u8(r), _clamp_u8(g), _clamp_u8(b), _clamp_u8(w))

    parts = [p.strip() for p in s.split(",") if p.strip() != ""]
    if len(parts) not in (3, 4):
        raise argparse.ArgumentTypeError(
            "Color must be R,G,B or R,G,B,W or #RRGGBB (or #RRGGBBWW)"
        )
    try:
        nums = [int(p) for p in parts]
    except ValueError as e:
        raise argparse.ArgumentTypeError("RGB values must be integers") from e
    if any(v < 0 or v > 255 for v in nums):
        raise argparse.ArgumentTypeError("RGB/W values must be 0..255")

    r, g, b = nums[0], nums[1], nums[2]
    w = nums[3] if len(nums) == 4 else 0
    return (_clamp_u8(r), _clamp_u8(g), _clamp_u8(b), _clamp_u8(w))


def _resolve_index(idx: int, nleds: int) -> int:
    # Allow negative indices like Python lists: -1 means last
    if idx < 0:
        idx = nleds + idx
    if idx < 0 or idx >= nleds:
        raise ValueError(f"LED index out of range: {idx} (nleds={nleds})")
    return idx


def _lerp(a: int, b: int, t: float) -> int:
    return _clamp_u8(int(round(a + (b - a) * t)))


def _lerp_color(c1: Color, c2: Color, t: float) -> Color:
    return (
        _lerp(c1[0], c2[0], t),
        _lerp(c1[1], c2[1], t),
        _lerp(c1[2], c2[2], t),
        _lerp(c1[3], c2[3], t),
    )


def build_frame(
    nleds: int,
    bytes_per_led: int,
    indices_and_colors: Sequence[Tuple[int, Color]],
) -> bytes:
    """Build a single-frame payload with the given indices set to specific colors.

    Note on byte order:
    - RGB profile (bytes_per_led=3): R,G,B
    - RGBW profile (bytes_per_led=4): W,R,G,B (per xled-docs)
    """
    if bytes_per_led not in (3, 4):
        raise ValueError(f"Unsupported bytes_per_led={bytes_per_led}; expected 3 or 4")

    out = bytearray(nleds * bytes_per_led)

    for idx, c in indices_and_colors:
        if idx < 0 or idx >= nleds:
            continue
        base = idx * bytes_per_led
        if bytes_per_led == 3:
            out[base + 0] = c[0]
            out[base + 1] = c[1]
            out[base + 2] = c[2]
        else:
            # RGBW is W,R,G,B
            out[base + 0] = c[3]
            out[base + 1] = c[0]
            out[base + 2] = c[1]
            out[base + 3] = c[2]

    return bytes(out)

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
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", "utf-8")


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
        help="Params file path",
        default=DEFAULT_PARAMS_FILENAME,
    )


def _parse_inf_int(s: str) -> Optional[int]:
    s = str(s).strip().lower()
    if s in ("inf", "infinite", "infinity"):
        return None
    try:
        v = int(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError("Expected an integer or 'inf'") from e
    return v


def _parse_inf_float(s: str) -> Optional[float]:
    s = str(s).strip().lower()
    if s in ("inf", "infinite", "infinity"):
        return None
    try:
        v = float(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError("Expected a number or 'inf'") from e
    return v


def _iter_range(start_rel: int, end_rel: int, step: int) -> List[int]:
    if step == 0:
        raise ValueError("step cannot be 0")
    # Auto-adjust direction for user convenience
    if start_rel > end_rel and step > 0:
        step = -step
    if start_rel < end_rel and step < 0:
        step = -step
    return list(range(start_rel, end_rel + (1 if step > 0 else -1), step))


def _sleep_forever() -> None:
    while True:
        time.sleep(3600)


def _hold_with_keepalive(
    client: TwinklyClient,
    frame_on: bytes,
    keepalive_s: float,
    assert_rt_every_s: float,
) -> None:
    """Hold a frame indefinitely by periodically resending it.

    Some Twinkly firmwares revert from mode=rt back to movie after a short time
    even if HTTP /led/rt/frame is used. (The original protocol uses UDP frames.)

    To be robust, we periodically:
      - ensure mode=rt
      - re-send the same frame
    """
    ka = float(keepalive_s)
    if ka <= 0:
        ka = 0.8

    assert_every = float(assert_rt_every_s)
    if assert_every <= 0:
        assert_every = 3.0

    t_last_assert = 0.0

    while True:
        now = time.time()
        if (now - t_last_assert) >= assert_every:
            try:
                # Cheap "belt and suspenders" — reassert rt periodically.
                client.set_mode("rt")
            except Exception:
                # If auth expired or mode query fails, rt_frame below will still
                # attempt to re-auth via _auth_headers().
                pass
            t_last_assert = now

        client.rt_frame(frame_on)
        time.sleep(ka)


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
        print(f"\nWrote {len(params_out)} string entries to: {path}")

    return 0


def cmd_info(args: argparse.Namespace) -> int:
    ip, start, length = _string_target_from_args(args)

    c = TwinklyClient(ip, timeout_s=args.timeout)
    g = c.gestalt()

    mode_error = None
    try:
        mode = c.get_mode()
    except Exception as e:
        mode = None
        mode_error = str(e)

    out = {
        "version": VERSION,
        "target": {
            "ip": ip,
            "start": start,
            "length": length,
            "string": getattr(args, "string", None),
        },
        "mode": mode,
        "mode_error": mode_error,
        "gestalt": g,
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    """Explicitly authenticate and write a fresh token to the cache."""
    ip, _start, _length = _string_target_from_args(args)
    c = TwinklyClient(ip, timeout_s=args.timeout)

    # Force a login; Twinkly issues a new token and invalidates any previous one.
    c.login()

    # Re-load from disk to show what's now cached.
    ti = c._load_cached_token()
    out = {
        "version": VERSION,
        "ip": ip,
        "token_cache_path": str(c._token_path()),
        "cached": bool(ti),
        "expires_at_unix": ti.expires_at_unix if ti else None,
        "seconds_remaining": (ti.expires_at_unix - time.time()) if ti else None,
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_strings(args: argparse.Namespace) -> int:
    """List known string names from the params file."""
    params_path = _params_path(getattr(args, "params", None))
    params = _load_params(params_path)

    keys = sorted(params.keys())
    if args.json:
        print(json.dumps({k: params[k] for k in keys}, indent=2, sort_keys=True))
        return 0

    if not keys:
        print(f"No strings found in {params_path}")
        return 1

    if args.details:
        for k in keys:
            ent = params[k]
            ip = ent.get("ip")
            start = ent.get("start")
            length = ent.get("length")
            device_name = ent.get("device_name")
            print(f"{k}	ip={ip}	start={start}	length={length}	device_name={device_name}")
    else:
        for k in keys:
            print(k)

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


def _resolve_segment_indices(
    args: argparse.Namespace,
    seg_n: int,
) -> Tuple[int, int, int, bool]:
    """Return (start_rel, end_rel, step, used_explicit_start).

    - If user provides --start/--led, default --end to start.
    - If user provides neither, default start=0, end=-1.
    """
    used_explicit_start = args.start is not None
    start_val = args.start

    if not used_explicit_start:
        start_rel = 0
        end_rel = _resolve_index(-1, seg_n)
    else:
        start_rel = _resolve_index(int(start_val), seg_n)
        if args.end is None:
            end_rel = start_rel
        else:
            end_rel = _resolve_index(int(args.end), seg_n)

    step = int(args.step)
    return (start_rel, end_rel, step, used_explicit_start)


def cmd_light(args: argparse.Namespace) -> int:
    ip, start_off, seg_len = _string_target_from_args(args)

    c = TwinklyClient(ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    seg_n = seg_len if seg_len > 0 else nleds

    # Determine range within segment
    start_rel, end_rel, step, _used_explicit_start = _resolve_segment_indices(args, seg_n)
    rel_path = _iter_range(start_rel, end_rel, step)

    rgb1 = args.rgb
    rgb2 = args.rgb2

    idxs_and_colors: List[Tuple[int, Color]] = []
    if not rel_path:
        return 0

    denom = max(1, len(rel_path) - 1)
    for i, r in enumerate(rel_path):
        idx = start_off + r
        if idx < 0 or idx >= nleds:
            continue
        if rgb2 is None:
            c_here = rgb1
        else:
            t = i / denom
            c_here = _lerp_color(rgb1, rgb2, t)
        idxs_and_colors.append((idx, c_here))

    with _with_rt_mode(c):
        frame_on = build_frame(nleds, bpl, idxs_and_colors)
        c.rt_frame(frame_on)

        # Hold
        hold_s = args.hold_s
        if hold_s is None:
            _hold_with_keepalive(c, frame_on, float(args.keepalive_s), float(args.assert_rt_every_s))
        elif float(hold_s) > 0:
            time.sleep(float(hold_s))

        # Optional blink
        if args.blink_hz:
            period = 1.0 / float(args.blink_hz)
            cycles = args.blink_cycles
            while True:
                c.rt_frame(build_frame(nleds, bpl, idxs_and_colors))
                time.sleep(period / 2)
                c.rt_frame(build_frame(nleds, bpl, []))
                time.sleep(period / 2)
                if cycles is not None:
                    cycles -= 1
                    if cycles <= 0:
                        break

    return 0


def cmd_find_end(args: argparse.Namespace) -> int:
    ip, start_off, seg_len = _string_target_from_args(args)

    c = TwinklyClient(ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    seg_n = seg_len if seg_len > 0 else nleds

    count = max(1, int(args.last_n))
    rel_idxs = list(range(seg_n - count, seg_n))
    idxs = [start_off + r for r in rel_idxs]

    on_frame = build_frame(nleds, bpl, [(i, args.rgb) for i in idxs])
    off_frame = build_frame(nleds, bpl, [])

    with _with_rt_mode(c):
        period = 1.0 / float(args.blink_hz)
        cycles = args.blink_cycles
        while True:
            c.rt_frame(on_frame)
            time.sleep(period / 2)
            c.rt_frame(off_frame)
            time.sleep(period / 2)
            if cycles is not None:
                cycles -= 1
                if cycles <= 0:
                    break

    return 0


def cmd_chase(args: argparse.Namespace) -> int:
    ip, start_off, seg_len = _string_target_from_args(args)

    c = TwinklyClient(ip, timeout_s=args.timeout)
    g = c.gestalt()
    nleds = int(g["number_of_led"])
    bpl = int(g.get("bytes_per_led", 3))

    seg_n = seg_len if seg_len > 0 else nleds

    start_rel = _resolve_index(int(args.start), seg_n)
    end_rel = _resolve_index(int(args.end), seg_n)
    rel_path = _iter_range(start_rel, end_rel, int(args.step))
    if not rel_path:
        return 0

    rgb1 = args.rgb
    rgb2 = args.rgb2

    loops = args.loops

    with _with_rt_mode(c):
        loop_idx = 0
        while True:
            denom = max(1, len(rel_path) - 1)
            for i, r in enumerate(rel_path):
                idx = start_off + r
                if idx < 0 or idx >= nleds:
                    continue
                if rgb2 is None:
                    c_here = rgb1
                else:
                    t = i / denom
                    c_here = _lerp_color(rgb1, rgb2, t)

                c.rt_frame(build_frame(nleds, bpl, [(idx, c_here)]))
                time.sleep(float(args.delay))

            loop_idx += 1
            if loops is not None and loop_idx >= loops:
                break

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description=f"Twinkly Tree Helper (v{VERSION})",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_disc = sub.add_parser(
        "discover",
        help="Discover Twinkly devices on LAN",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p_disc.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help="HTTP request timeout (seconds)",
    )
    p_disc.add_argument(
        "--discovery-timeout",
        type=float,
        default=0.9,
        help="UDP discovery listen timeout (seconds)",
    )
    p_disc.add_argument(
        "--write-params",
        action="store_true",
        help="Write named strings to params file",
    )
    p_disc.add_argument(
        "--params-out",
        default=DEFAULT_PARAMS_FILENAME,
        help=f"Output params file path (default: ./{DEFAULT_PARAMS_FILENAME})",
    )
    p_disc.add_argument(
        "--segment-len",
        type=int,
        default=DEFAULT_SEGMENT_LEN,
        help="Segment length used when device LED count is divisible by it",
    )
    p_disc.set_defaults(func=cmd_discover)

    p_info = sub.add_parser(
        "info",
        help="Print device gestalt + current mode",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_target_args(p_info)
    p_info.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help="HTTP request timeout (seconds)",
    )
    p_info.set_defaults(func=cmd_info)

    p_login = sub.add_parser(
        "login",
        help="Authenticate to the device and (re)write the cached token file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_target_args(p_login)
    p_login.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help="HTTP request timeout (seconds)",
    )
    p_login.set_defaults(func=cmd_login)

    p_strings = sub.add_parser(
        "strings",
        help="List known string names from params file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p_strings.add_argument(
        "--params",
        help="Params file path",
        default=DEFAULT_PARAMS_FILENAME,
    )
    p_strings.add_argument("--details", action="store_true", help="Show per-string details")
    p_strings.add_argument("--json", action="store_true", help="Emit JSON (full params contents)")
    p_strings.set_defaults(func=cmd_strings)

    p_light = sub.add_parser(
        "light",
        help="Light one LED or a range within the target string",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_target_args(p_light)
    # Range semantics:
    # - --led is a synonym for --start
    # - If start provided, default end=start
    # - If neither provided, default start=0 end=-1
    p_light.add_argument("--start", type=int, default=None, help="Start index within string (allow negative)")
    p_light.add_argument("--led", type=int, default=None, help="Synonym for --start")
    p_light.add_argument("--end", type=int, default=None, help="End index within string (allow negative)")
    p_light.add_argument(
        "--step",
        type=int,
        default=1,
        help="Step for the range (direction auto-adjusts if needed)",
    )
    p_light.add_argument(
        "--rgb",
        type=_parse_color,
        default="#ff0000",
        help="Primary color: R,G,B or R,G,B,W or #RRGGBB (or #RRGGBBWW)",
    )
    p_light.add_argument("--rgb2", type=_parse_color, default=None, help="If set, interpolate from --rgb to --rgb2")
    p_light.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help="HTTP request timeout (seconds)",
    )
    p_light.add_argument(
        "--hold-s",
        type=_parse_inf_float,
        default="inf",
        help="Hold time after setting (seconds). Use 'inf' to hold forever.",
    )
    p_light.add_argument(
        "--keepalive-s",
        type=float,
        default=0.8,
        help="When holding forever, resend the same frame every N seconds to reduce reversion",
    )
    p_light.add_argument(
        "--assert-rt-every-s",
        type=float,
        default=3.0,
        help="While holding, re-send mode=rt every N seconds (helps on firmwares that revert despite keepalive)",
    )
    p_light.add_argument("--blink-hz", type=float, default=0.0, help="If >0, blink at this frequency")
    p_light.add_argument("--blink-cycles", type=_parse_inf_int, default="inf", help="Blink cycle count (use 'inf' for infinite)")
    p_light.set_defaults(func=cmd_light)

    p_end = sub.add_parser(
        "find-end",
        help="Blink the last LED (or last N) within the target string",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_target_args(p_end)
    p_end.add_argument(
        "--last-n",
        type=int,
        default=1,
        help="How many LEDs at the end of the string to blink",
    )
    p_end.add_argument(
        "--rgb",
        type=_parse_color,
        default="#ff0000",
        help="Color: R,G,B or R,G,B,W or #RRGGBB (or #RRGGBBWW)",
    )
    p_end.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help="HTTP request timeout (seconds)",
    )
    p_end.add_argument(
        "--blink-hz",
        type=float,
        default=2.0,
        help="Blink frequency in Hz",
    )
    p_end.add_argument("--blink-cycles", type=_parse_inf_int, default="inf", help="Blink cycle count (use 'inf' for infinite)")
    p_end.set_defaults(func=cmd_find_end)

    p_chase = sub.add_parser(
        "chase",
        help="Chase a single lit LED across a range within the target string",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    _add_target_args(p_chase)
    p_chase.add_argument("--start", type=int, default=0, help="Start index within string (allow negative)")
    p_chase.add_argument("--end", type=int, default=-1, help="End index within string (allow negative)")
    p_chase.add_argument(
        "--step",
        type=int,
        default=1,
        help="Step for the chase path (direction auto-adjusts if needed)",
    )
    p_chase.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Delay between frames (seconds)",
    )
    p_chase.add_argument("--loops", type=_parse_inf_int, default="inf", help="Loop count (use 'inf' for infinite)")
    p_chase.add_argument(
        "--rgb",
        type=_parse_color,
        default="#ff0000",
        help="Primary color: R,G,B or R,G,B,W or #RRGGBB (or #RRGGBBWW)",
    )
    p_chase.add_argument("--rgb2", type=_parse_color, default=None, help="If set, interpolate from --rgb to --rgb2")
    p_chase.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help="HTTP request timeout (seconds)",
    )
    p_chase.set_defaults(func=cmd_chase)

    args = p.parse_args(argv)

    # Normalize defaults that are strings (argparse does not type-convert defaults)
    for attr, conv in (
        ("hold_s", _parse_inf_float),
        ("blink_cycles", _parse_inf_int),
        ("loops", _parse_inf_int),
        ("rgb", _parse_color),
        ("rgb2", _parse_color),
    ):
        if hasattr(args, attr):
            v = getattr(args, attr)
            if isinstance(v, str):
                setattr(args, attr, conv(v))

    # Normalize light --led synonym and defaults
    if getattr(args, "cmd", None) == "light":
        if args.led is not None:
            args.start = args.led
        # leave args.start as-is (None means "no explicit start")

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
