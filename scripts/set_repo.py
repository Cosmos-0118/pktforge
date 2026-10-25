"""Point the install commands at your GitHub repo.

    python scripts/set_repo.py yourname/pktforge

Replaces the OWNER/pktforge placeholder in README.md, AGENTS.md, SKILL.md, install.sh and install.ps1.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["README.md", "AGENTS.md", "SKILL.md", "install.sh", "install.ps1"]


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", sys.argv[1]):
        sys.exit("usage: python scripts/set_repo.py owner/name")
    repo = sys.argv[1]
    for f in FILES:
        path = os.path.join(ROOT, f)
        with open(path, encoding="utf-8", newline="") as fh:
            text = fh.read()
        new = re.sub(r"OWNER/pktforge", repo, text)
        if new != text:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(new)
            print("updated", f)
    print("Done. Push to https://github.com/%s and the install one-liners will work." % repo)


if __name__ == "__main__":
    main()
