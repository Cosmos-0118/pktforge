"""Build dist/pktforge-<version>.zip and .tar.gz (what the installers download).

    python scripts/make_release.py

Both archives have one top-level folder, `pktforge-<version>/`, which the installers strip.
"""
import os
import sys
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import pktforge  # noqa: E402

SKIP_DIRS = {"__pycache__", ".git", "dist", "out", ".pytest_cache"}
SKIP_EXT = {".pyc", ".pyo"}


def files():
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            if os.path.splitext(n)[1] in SKIP_EXT:
                continue
            path = os.path.join(base, n)
            yield path, os.path.relpath(path, ROOT).replace(os.sep, "/")


def main():
    name = "pktforge-%s" % pktforge.__version__
    dist = os.path.join(ROOT, "dist")
    os.makedirs(dist, exist_ok=True)
    zpath, tpath = os.path.join(dist, name + ".zip"), os.path.join(dist, name + ".tar.gz")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z, tarfile.open(tpath, "w:gz") as t:
        for path, rel in files():
            z.write(path, "%s/%s" % (name, rel))
            t.add(path, "%s/%s" % (name, rel))
    for p in (zpath, tpath):
        print("%s  %d bytes" % (p, os.path.getsize(p)))


if __name__ == "__main__":
    main()
