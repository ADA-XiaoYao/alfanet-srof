#!/usr/bin/env python3
"""
ALFANET SROF · Build Script
Run from project root or build/ directory:

  python build/build.py
  python build.py          (if run from build/)

Output:
  dist/SROF-Win.exe      (Windows)
  dist/SROF-macOS.app    (macOS)
  dist/SROF-Linux        (Linux)
"""
import subprocess, sys, shutil, platform, os
from pathlib import Path

OS    = platform.system()

# Resolve ROOT correctly whether run from project root or build/ subdirectory
_HERE = Path(__file__).resolve().parent
ROOT  = _HERE.parent if _HERE.name == "build" else _HERE

DIST  = ROOT / "dist"
TMP   = ROOT / "build" / "_work"
SEP  = ";" if OS == "Windows" else ":"

NAMES = {"Windows": "SROF-Win", "Darwin": "SROF-macOS", "Linux": "SROF-Linux"}
NAME  = NAMES.get(OS, "SROF")


def run(cmd):
    print("▶ " + " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit(r.returncode)


def main():
    print(f"\n{'='*56}")
    print(f"  ALFANET SROF Build  [{OS} · {platform.machine()}]")
    print(f"  ROOT: {ROOT}")
    print(f"{'='*56}\n")

    if not shutil.which("pyinstaller"):
        run([sys.executable, "-m", "pip", "install", "pyinstaller"])

    DIST.mkdir(exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)

    pf = {
        "Windows": ["--onefile", "--windowed"],
        "Darwin":  ["--onedir", "--windowed",
                    "--osx-bundle-identifier=net.alfanet.srof"],
        "Linux":   ["--onefile"],
    }.get(OS, ["--onefile"])

    data = [f"--add-data={ROOT / d}{SEP}{d}"
            for d in ("modules", "core", "data", "assets")
            if (ROOT / d).exists()]

    hidden = [
        "--hidden-import=tkinter",
        "--hidden-import=tkinter.ttk",
        "--hidden-import=tkinter.scrolledtext",
        "--hidden-import=sqlite3",
        "--hidden-import=modules.recon.plugins",
        "--hidden-import=modules.scan.plugins",
        "--hidden-import=modules.exploit.plugins",
        "--hidden-import=modules.post.plugins",
        "--hidden-import=modules.ctf.plugins",
        "--hidden-import=modules.cloud.plugins",
        "--hidden-import=modules.mobile.plugins",
        "--hidden-import=core.database",
        "--hidden-import=core.engine",
        "--hidden-import=core.plugin",
    ]

    run([
        "pyinstaller", "--noconfirm", "--clean",
        f"--name={NAME}",
        "--distpath", str(DIST),
        "--workpath", str(TMP),
        "--specpath", str(TMP),
        *data, *hidden, *pf,
        str(ROOT / "main.py"),
    ])

    out = DIST / (f"{NAME}.exe" if OS == "Windows"
                  else f"{NAME}.app" if OS == "Darwin"
                  else NAME)

    if out.exists():
        if OS != "Windows" and out.is_file():
            os.chmod(out, 0o755)
        sz = (sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
              if out.is_dir() else out.stat().st_size)
        print(f"\n✓  {out}  ({sz/1024/1024:.1f} MB)")
    else:
        print(f"\n✗  Output not found: {out}")
        sys.exit(1)


if __name__ == "__main__":
    main()
