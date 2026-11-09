"""Build the architecture-independent LuCI package using Python's standard library."""

import gzip
import io
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NAME = "luci-app-wireguard-manager"
VERSION = "1.3.1-1"
CONTROL = f"""Package: {NAME}
Version: {VERSION}
Architecture: all
Section: luci
Priority: optional
Depends: luci-base, lua, libuci-lua, libubus-lua, luci-lib-nixio, luci-lib-ip, luci-lib-jsonc, wireguard-tools, kmod-wireguard
Maintainer: WireGuard Manager
Description: Manage WireGuard servers and client tunnels on legacy Lua LuCI.
"""
CLEAR_CACHE = """#!/bin/sh
[ -n "$IPKG_INSTROOT" ] || rm -f /tmp/luci-indexcache \
    /tmp/luci-modulecache/6C7563692E636F6E74726F6C6C65722E7769726567756172645F6D616E61676572 \
    /tmp/luci-modulecache/6C7563692E6D6F64656C2E7769726567756172645F6D616E61676572
exit 0
"""


def archive(files, directories=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for directory in directories:
            entry = tarfile.TarInfo("./" + directory)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            entry.uname = entry.gname = "root"
            tar.addfile(entry)
        for name, content, mode in files:
            entry = tarfile.TarInfo("./" + name)
            entry.size = len(content)
            entry.mode = mode
            entry.uname = entry.gname = "root"
            tar.addfile(entry, io.BytesIO(content))
    return gzip.compress(buffer.getvalue(), mtime=0)


def build():
    source = ROOT / "package"
    text_suffixes = {".lua", ".htm", ".js", ".css"}
    logo = "www/luci-static/resources/wireguard-manager/wireguard-logo.png"
    files = [
        (path.relative_to(source).as_posix(), path.read_bytes().replace(b"\r\n", b"\n"), 0o644)
        for path in sorted(source.rglob("*"))
        if path.is_file() and path.suffix in text_suffixes
    ]
    if len(files) != 6:
        raise SystemExit("Expected six LuCI files, including the vendored QR encoder")
    files.append((logo, (source / logo).read_bytes(), 0o644))
    control = archive([
        ("control", CONTROL.encode(), 0o644),
        ("postinst", CLEAR_CACHE.encode(), 0o755),
        ("postrm", CLEAR_CACHE.encode(), 0o755),
    ])
    directories = sorted({
        parent.as_posix() for name, _, _ in files for parent in Path(name).parents if parent != Path(".")
    })
    data = archive(files, directories)
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    path = dist / f"{NAME}_{VERSION}_all.ipk"
    path.write_bytes(archive([
        ("debian-binary", b"2.0\n", 0o644),
        ("control.tar.gz", control, 0o644),
        ("data.tar.gz", data, 0o644),
    ]))
    return path


if __name__ == "__main__":
    print(build())
