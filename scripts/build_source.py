#!/usr/bin/env python3
"""Builds apps.json, an AltStore source, from the owner's GitHub releases.

Every public repository of the owner is scanned. Each release asset ending in
.ipa becomes an app version; the bundle identifier, version, build number,
minimum iOS version, entitlements and privacy usage descriptions are read
from the IPA itself, so the source always matches what AltStore downloads
(AltStore refuses an IPA whose identifier, version or permissions differ
from the source). A new repository shows up on the next run with no change
here, and repositories that match the "upcoming" pattern but have no IPA yet
are announced as news.

Only the Python standard library is used. Environment:
  GITHUB_TOKEN   optional, raises the API rate limit
  SOURCE_OWNER   overrides "owner" in config.json
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import plistlib
import re
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
import zlib
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config.json"
CACHE = ROOT / "cache" / "ipa-metadata.json"
ICONS = ROOT / "icons"
API = "https://api.github.com"
# Bumped whenever the metadata read from an IPA changes, so old cache
# entries are read again.
CACHE_VERSION = 4
# Entitlements every signed app carries; AltStore does not want them listed.
IMPLICIT_ENTITLEMENTS = {
    "application-identifier",
    "com.apple.developer.team-identifier",
}


def log(*args):
    print(*args, file=sys.stderr, flush=True)


# --- GitHub -----------------------------------------------------------------

def request(url: str, accept: str = "application/vnd.github+json", attempts: int = 4) -> bytes:
    headers = {"Accept": accept, "User-Agent": "altstore-source-builder", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(API):
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code in (403, 429, 500, 502, 503, 504) and attempt + 1 < attempts:
                time.sleep(5 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if attempt + 1 < attempts:
                time.sleep(5 * (attempt + 1))
                continue
            raise
    raise RuntimeError("unreachable")


def api_list(path: str) -> list:
    items, page = [], 1
    while True:
        separator = "&" if "?" in path else "?"
        batch = json.loads(request(f"{API}{path}{separator}per_page=100&page={page}"))
        items.extend(batch)
        if len(batch) < 100:
            return items
        page += 1


# --- Mach-O entitlements -----------------------------------------------------

def macho_slices(data: bytes):
    """Offsets and sizes of the thin Mach-O images in a (possibly fat) binary."""
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):  # fat; 0xCAFEBABF has 64-bit entries
        count = struct.unpack_from(">I", data, 4)[0]
        wide = magic == 0xCAFEBABF
        for i in range(count):
            if wide:
                _, _, offset, size, _, _ = struct.unpack_from(">iiQQII", data, 8 + i * 32)
            else:
                _, _, offset, size, _ = struct.unpack_from(">iiIII", data, 8 + i * 20)
            yield offset, size
    else:
        yield 0, len(data)


def entitlements_of(data: bytes) -> dict:
    """The entitlements in a Mach-O's code signature (empty when unsigned)."""
    result: dict = {}
    for base, size in macho_slices(data):
        image = memoryview(data)[base:base + size]
        magic = struct.unpack_from("<I", image, 0)[0]
        if magic not in (0xFEEDFACF, 0xFEEDFACE):
            continue
        wide = magic == 0xFEEDFACF
        ncmds = struct.unpack_from("<I", image, 16)[0]
        offset = 32 if wide else 28
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", image, offset)
            if cmd == 0x1D:  # LC_CODE_SIGNATURE
                dataoff, datasize = struct.unpack_from("<II", image, offset + 8)
                blob = bytes(image[dataoff:dataoff + datasize])
                result.update(superblob_entitlements(blob))
            offset += cmdsize
    return result


def superblob_entitlements(blob: bytes) -> dict:
    if len(blob) < 12 or struct.unpack_from(">I", blob, 0)[0] != 0xFADE0CC0:
        return {}
    count = struct.unpack_from(">I", blob, 8)[0]
    for i in range(count):
        slot, offset = struct.unpack_from(">II", blob, 12 + i * 8)
        if slot == 5 and struct.unpack_from(">I", blob, offset)[0] == 0xFADE7171:
            length = struct.unpack_from(">I", blob, offset + 4)[0]
            try:
                value = plistlib.loads(blob[offset + 8:offset + length])
                return value if isinstance(value, dict) else {}
            except Exception:
                return {}
    return {}


# --- PNG ---------------------------------------------------------------------

def png_chunks(data: bytes):
    at = 8
    while at + 8 <= len(data):
        length, kind = struct.unpack_from(">I4s", data, at)
        yield kind, data[at + 8:at + 8 + length]
        at += 12 + length


def make_png(width: int, height: int, rows: list[bytes]) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + row for row in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def unfilter(width: int, height: int, channels: int, raw: bytes) -> list[bytearray]:
    stride = width * channels
    rows, previous, at = [], bytearray(stride), 0
    for _ in range(height):
        kind, line = raw[at], bytearray(raw[at + 1:at + 1 + stride])
        at += 1 + stride
        for x in range(stride):
            a = line[x - channels] if x >= channels else 0
            b = previous[x]
            c = previous[x - channels] if x >= channels else 0
            if kind == 1:
                line[x] = (line[x] + a) & 255
            elif kind == 2:
                line[x] = (line[x] + b) & 255
            elif kind == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif kind == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(line)
        previous = line
    return rows


def decode_png(data: bytes) -> tuple[int, int, list[bytearray]] | None:
    """RGBA rows of an 8-bit PNG, including Apple's CgBI variant (BGRA,
    premultiplied, raw deflate) that Xcode writes into app bundles."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    cgbi, header, idat = False, None, b""
    for kind, body in png_chunks(data):
        if kind == b"CgBI":
            cgbi = True
        elif kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat += body
    if not header:
        return None
    width, height, depth, color, _, _, interlace = header
    if depth != 8 or interlace or color not in (2, 6):
        return None
    channels = 4 if color == 6 else 3
    raw = zlib.decompress(idat, -15) if cgbi else zlib.decompress(idat)
    rows = unfilter(width, height, channels, raw)
    out = []
    for row in rows:
        if channels == 3:
            rgba = bytearray()
            for x in range(width):
                rgba += row[x * 3:x * 3 + 3] + b"\xff"
            row = rgba
        if cgbi:
            for x in range(0, len(row), 4):
                b, g, r, a = row[x:x + 4]
                if a:
                    r, g, b = (min(255, v * 255 // a) for v in (r, g, b))
                row[x:x + 4] = bytes((r, g, b, a))
        out.append(row)
    return width, height, out


def shrink(width: int, height: int, rows: list[bytearray], limit: int = 512):
    """Averages blocks of pixels so the icon is at most limit pixels wide."""
    factor = -(-width // limit)
    if factor <= 1:
        return width, height, rows
    out_width, out_height = width // factor, height // factor
    out = []
    for oy in range(out_height):
        row = bytearray(out_width * 4)
        for ox in range(out_width):
            total = [0, 0, 0, 0]
            for y in range(oy * factor, oy * factor + factor):
                source = rows[y]
                for x in range(ox * factor, ox * factor + factor):
                    for c in range(4):
                        total[c] += source[x * 4 + c]
            count = factor * factor
            row[ox * 4:ox * 4 + 4] = bytes(v // count for v in total)
        out.append(row)
    return out_width, out_height, out


def tint_of(rows: list[bytearray]) -> str | None:
    """The average of an icon's saturated pixels, as #RRGGBB."""
    total = [0, 0, 0]
    weight = 0
    for row in rows[::4]:
        for x in range(0, len(row), 16):
            r, g, b, a = row[x:x + 4]
            if a < 128:
                continue
            high, low = max(r, g, b), min(r, g, b)
            saturation = (high - low) / high if high else 0
            if saturation < 0.25 or high < 60:
                continue
            w = saturation * high
            total = [total[0] + r * w, total[1] + g * w, total[2] + b * w]
            weight += w
    if not weight:
        return None
    return "#" + "".join(f"{int(v / weight):02X}" for v in total)


# --- IPA ---------------------------------------------------------------------

def read_ipa(path: Path) -> dict:
    with zipfile.ZipFile(path) as ipa:
        names = ipa.namelist()
        apps = sorted({m.group(1) for n in names if (m := re.match(r"^(Payload/[^/]+\.app)/", n))})
        if not apps:
            raise ValueError("no Payload/*.app in the IPA")
        app = apps[0]
        info = plistlib.loads(ipa.read(f"{app}/Info.plist"))
        entitlements: dict = {}
        privacy: dict = {}

        def collect(bundle: str, bundle_info: dict):
            for key, value in bundle_info.items():
                if key.startswith("NS") and key.endswith("UsageDescription") and isinstance(value, str):
                    privacy.setdefault(key, value)
            executable = bundle_info.get("CFBundleExecutable")
            if executable and f"{bundle}/{executable}" in names:
                entitlements.update(entitlements_of(ipa.read(f"{bundle}/{executable}")))

        collect(app, info)
        for name in names:
            match = re.match(rf"^({re.escape(app)}/(?:PlugIns|Extensions)/[^/]+\.appex)/Info\.plist$", name)
            if match:
                collect(match.group(1), plistlib.loads(ipa.read(name)))

        icon = best_icon(ipa, names, app, info)
        return {
            "bundleIdentifier": info.get("CFBundleIdentifier"),
            "version": str(info.get("CFBundleShortVersionString", "")),
            "buildVersion": str(info.get("CFBundleVersion", "")),
            "name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
            "minOSVersion": info.get("MinimumOSVersion"),
            "entitlements": sorted(k for k in entitlements if k not in IMPLICIT_ENTITLEMENTS),
            "privacy": dict(sorted(privacy.items())),
            "icon": icon,
        }


def best_icon(ipa: zipfile.ZipFile, names: list[str], app: str, info: dict):
    """The largest icon PNG at the bundle's top level, as a standard PNG."""
    stems = set()
    for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        stems.update(info.get(key, {}).get("CFBundlePrimaryIcon", {}).get("CFBundleIconFiles", []))
    stems.update(info.get("CFBundleIconFiles", []))
    candidates = []
    for name in names:
        if not name.startswith(app + "/") or name.count("/") != 2 or not name.lower().endswith(".png"):
            continue
        base = name.rsplit("/", 1)[1]
        if any(base.startswith(stem) for stem in stems) or base.lower().startswith(("appicon", "icon")):
            candidates.append((ipa.getinfo(name).file_size, name))
    best = None
    for _, name in sorted(candidates, reverse=True):
        decoded = decode_png(ipa.read(name))
        if decoded and (not best or decoded[0] > best[0]):
            best = decoded
    if not best:
        return None
    width, height, rows = shrink(*best)
    return {"png": make_png(width, height, rows), "width": width, "tint": tint_of(rows)}


# --- Source ------------------------------------------------------------------

def clean_notes(text: str | None) -> str:
    text = (text or "").replace("\r\n", "\n")
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)          # images
    text = re.sub(r"<[^>]+>", "", text)                         # HTML tags
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)  # links
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def caption_of(text: str | None) -> str:
    """The first line of release notes that says something, without Markdown."""
    for line in clean_notes(text).split("\n"):
        line = re.sub(r"^\s*(#+|[-*+]|\d+\.)\s*", "", line)
        line = re.sub(r"[*_`]+", "", line).strip()
        if line:
            return line[:140]
    return ""


def iso(timestamp: str) -> str:
    return dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).isoformat().replace("+00:00", "Z")


def main() -> int:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    owner = os.environ.get("SOURCE_OWNER") or config["owner"]
    base_url = config["baseURL"].rstrip("/")
    overrides = config.get("apps", {})
    cache = {}
    if CACHE.exists():
        cache = json.loads(CACHE.read_text(encoding="utf-8"))
    used_cache_keys = set()
    ICONS.mkdir(exist_ok=True)

    this_repository = os.environ.get("GITHUB_REPOSITORY", "").split("/")[-1]
    repos = [r for r in api_list(f"/users/{owner}/repos?type=owner&sort=pushed")
             if not r.get("private") and r["name"] not in config.get("exclude_repos", [])
             and r["name"] != this_repository
             and (config.get("include_forks", True) or not r.get("fork"))
             and not overrides.get(r["name"], {}).get("exclude")]
    log(f"{len(repos)} repositories of {owner}")

    apps: dict[str, dict] = {}       # bundle identifier -> app
    news: list[dict] = []
    upcoming_pattern = re.compile(config.get("upcoming", {}).get("match", r"(?i)ios"))
    for repo in repos:
        name = repo["name"]
        settings = overrides.get(name, {})
        try:
            releases = api_list(f"/repos/{owner}/{name}/releases")
        except urllib.error.HTTPError as error:
            log(f"{name}: releases unavailable ({error.code})")
            continue
        releases = [r for r in releases if not r.get("draft") and
                    (config.get("include_prereleases", True) or not r.get("prerelease"))]
        releases.sort(key=lambda r: r.get("published_at") or r["created_at"], reverse=True)
        found_ipa = False
        for release in releases:
            for asset in release.get("assets", []):
                if not asset["name"].lower().endswith(".ipa"):
                    continue
                found_ipa = True
                key = f"{asset['id']}:{asset['updated_at']}:{asset['size']}"
                used_cache_keys.add(key)
                meta = cache.get(key)
                if not meta or meta.get("cacheVersion") != CACHE_VERSION:
                    log(f"{name} {release['tag_name']}: reading {asset['name']} ({asset['size'] // 1048576} MB)")
                    with tempfile.NamedTemporaryFile(suffix=".ipa") as temporary:
                        temporary.write(request(asset["browser_download_url"], accept="application/octet-stream"))
                        temporary.flush()
                        try:
                            meta = read_ipa(Path(temporary.name))
                        except Exception as error:  # a broken IPA must not stop the others
                            log(f"  skipped: {error}")
                            cache[key] = {"cacheVersion": CACHE_VERSION, "error": str(error)}
                            continue
                    icon = meta.pop("icon")
                    meta["cacheVersion"] = CACHE_VERSION
                    if icon:
                        digest = hashlib.sha256(icon["png"]).hexdigest()[:12]
                        icon_name = f"{meta['bundleIdentifier']}-{digest}.png"
                        (ICONS / icon_name).write_bytes(icon["png"])
                        meta["icon"] = {"file": icon_name, "width": icon["width"], "tint": icon["tint"]}
                    cache[key] = meta
                if meta.get("error") or not meta.get("bundleIdentifier"):
                    continue
                bundle = meta["bundleIdentifier"]
                app = apps.setdefault(bundle, {"repo": repo, "settings": settings, "versions": [], "meta": meta})
                if app["repo"]["name"] != name:
                    log(f"{name}: {bundle} is already published by {app['repo']['name']}; skipped")
                    continue
                if any(v["version"] == meta["version"] and v["buildVersion"] == meta["buildVersion"]
                       for v in app["versions"]):
                    continue  # an older upload of the same build
                version = {
                    "version": meta["version"],
                    "buildVersion": meta["buildVersion"],
                    "marketingVersion": release.get("name") or release["tag_name"],
                    "date": iso(release.get("published_at") or release["created_at"]),
                    "localizedDescription": clean_notes(release.get("body")) or release.get("name") or release["tag_name"],
                    "downloadURL": asset["browser_download_url"],
                    "size": asset["size"],
                }
                if meta.get("minOSVersion"):
                    version["minOSVersion"] = str(meta["minOSVersion"])
                app["versions"].append(version)
                if len([n for n in news if n.get("appID") == bundle]) < config.get("news_per_app", 3):
                    news.append({
                        "title": f"{settings.get('name') or meta.get('name') or name} {release.get('name') or release['tag_name']}",
                        "identifier": f"release-{name}-{release['tag_name']}",
                        "caption": (caption_of(release.get("body")) or
                                    f"New release of {settings.get('name') or meta.get('name') or name}."),
                        "date": iso(release.get("published_at") or release["created_at"]),
                        "url": release["html_url"],
                        "appID": bundle,
                        "notify": False,
                    })
        if not found_ipa and config.get("upcoming", {}).get("enabled", True) and \
                upcoming_pattern.search(f"{name} {repo.get('description') or ''}"):
            news.append({
                "title": f"In development: {settings.get('name') or name}",
                "identifier": f"upcoming-{name}",
                "caption": (repo.get("description") or "A new port is in the works.")[:140],
                "date": iso(repo["created_at"]),
                "url": repo["html_url"],
                "notify": False,
            })

    source_tint = config["source"].get("tintColor", "#3478F6")
    entries = []
    for bundle, app in apps.items():
        repo, settings, meta = app["repo"], app["settings"], app["meta"]
        versions = sorted(app["versions"], key=lambda v: v["date"], reverse=True)[:config.get("max_versions", 10)]
        if not versions:
            continue
        latest = versions[0]
        # Permissions as the newest build declares them.
        latest_meta = next((m for m in cache.values() if isinstance(m, dict) and m.get("bundleIdentifier") == bundle
                            and m.get("version") == latest["version"] and m.get("buildVersion") == latest["buildVersion"]),
                           meta)
        icon = latest_meta.get("icon") or meta.get("icon")
        icon_url = settings.get("iconURL") or (f"{base_url}/icons/{icon['file']}" if icon else
                                              f"https://github.com/{owner}.png?size=512")
        tint = settings.get("tintColor") or (icon or {}).get("tint") or source_tint
        description = settings.get("localizedDescription") or "\n\n".join(filter(None, [
            repo.get("description"),
            f"Source code, game-file requirements and instructions: {repo['html_url']}",
        ]))
        entry = {
            "name": settings.get("name") or latest_meta.get("name") or repo["name"],
            "bundleIdentifier": bundle,
            "developerName": settings.get("developerName") or config["source"].get("developerName", owner),
            "subtitle": settings.get("subtitle") or (repo.get("description") or "")[:120],
            "localizedDescription": description,
            "iconURL": icon_url,
            "tintColor": tint,
            "category": settings.get("category", "games"),
            "screenshots": settings.get("screenshots", []),
            "versions": versions,
            "appPermissions": {
                "entitlements": latest_meta.get("entitlements", []),
                "privacy": latest_meta.get("privacy", {}),
            },
            # Older AltStore and SideStore releases, Feather and ESign read these.
            "version": latest["version"],
            "versionDate": latest["date"],
            "versionDescription": latest["localizedDescription"],
            "downloadURL": latest["downloadURL"],
            "size": latest["size"],
        }
        entries.append(entry)
        for item in news:
            if item.get("appID") == bundle:
                item["tintColor"] = tint
    entries.sort(key=lambda e: e["versionDate"], reverse=True)
    for item in news:
        item.setdefault("tintColor", source_tint)
    news.sort(key=lambda n: n["date"], reverse=True)
    news = news[:config.get("max_news", 20)]

    source = {key: value for key, value in config["source"].items() if key != "developerName"}
    source["sourceURL"] = f"{base_url}/apps.json"
    source["featuredApps"] = [e["bundleIdentifier"] for e in entries[:5]]
    source["apps"] = entries
    source["news"] = news
    output = json.dumps(source, indent=2, ensure_ascii=False) + "\n"
    (ROOT / "apps.json").write_text(output, encoding="utf-8")

    # Drop cache entries and icons nothing refers to any more.
    cache = {k: v for k, v in cache.items() if k in used_cache_keys}
    CACHE.parent.mkdir(exist_ok=True)
    CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    referenced = {m["icon"]["file"] for m in cache.values() if isinstance(m, dict) and m.get("icon")}
    for icon in ICONS.glob("*.png"):
        if icon.name not in referenced:
            icon.unlink()

    write_index(source, base_url)
    log(f"{len(entries)} apps, {len(news)} news items")
    return 0


def write_index(source: dict, base_url: str):
    source_url = f"{base_url}/apps.json"
    add_link = f"https://altdirect.app/?url={source_url}"
    cards = []
    for app in source["apps"]:
        latest = app["versions"][0]
        minimum = f" · iOS {latest['minOSVersion']}+" if latest.get("minOSVersion") else ""
        cards.append(f"""
      <li class="app">
        <img src="{escape(app['iconURL'])}" alt="" width="64" height="64" loading="lazy">
        <div class="meta">
          <h2>{escape(app['name'])}</h2>
          <p class="sub">{escape(app.get('subtitle') or '')}</p>
          <p class="ver">{escape(latest['version'])} · {latest['date'][:10]}{minimum}</p>
        </div>
        <a class="get" href="{escape(latest['downloadURL'])}">IPA</a>
      </li>""")
    news = "".join(f"""
      <li><a href="{escape(n.get('url', '#'))}">{escape(n['title'])}</a> <span>{n['date'][:10]}</span></li>"""
                   for n in source["news"][:8])
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(source['name'])}</title>
<style>
  :root {{ --bg:#f5f5f7; --fg:#1d1d1f; --muted:#6e6e73; --card:#fff; --tint:{source.get('tintColor', '#3478F6')}; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg:#000; --fg:#f5f5f7; --muted:#a1a1a6; --card:#1c1c1e; }} }}
  body {{ margin:0; background:var(--bg); color:var(--fg); font:16px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
  main {{ max-width:720px; margin:0 auto; padding:32px 16px 48px; }}
  header {{ text-align:center; }}
  header img {{ border-radius:50%; }}
  h1 {{ margin:12px 0 4px; font-size:28px; }}
  .lead {{ color:var(--muted); margin:0 0 20px; }}
  .add {{ display:inline-block; background:var(--tint); color:#fff; padding:12px 22px; border-radius:12px; text-decoration:none; font-weight:600; }}
  .url {{ display:block; margin-top:10px; color:var(--muted); font-size:13px; word-break:break-all; }}
  ul {{ list-style:none; padding:0; }}
  .app {{ display:flex; align-items:center; gap:14px; background:var(--card); border-radius:16px; padding:12px; margin:10px 0; }}
  .app img {{ border-radius:14px; flex:none; }}
  .meta {{ flex:1; min-width:0; }}
  .meta h2 {{ font-size:17px; margin:0; }}
  .meta p {{ margin:2px 0 0; color:var(--muted); font-size:14px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .get {{ flex:none; background:var(--bg); color:var(--tint); padding:6px 14px; border-radius:999px; text-decoration:none; font-weight:600; }}
  .news li {{ margin:6px 0; }} .news span {{ color:var(--muted); font-size:13px; }}
  a {{ color:var(--tint); }}
</style>
</head>
<body>
<main>
  <header>
    <img src="{escape(source.get('iconURL', ''))}" alt="" width="88" height="88">
    <h1>{escape(source['name'])}</h1>
    <p class="lead">{escape(source.get('subtitle', ''))}</p>
    <a class="add" href="{escape(add_link)}">Add to AltStore / SideStore</a>
    <span class="url">{escape(source_url)}</span>
  </header>
  <ul>{''.join(cards)}
  </ul>
  <h3>News</h3>
  <ul class="news">{news}
  </ul>
</main>
</body>
</html>
"""
    (ROOT / "index.html").write_text(html, encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
