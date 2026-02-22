# SROF · Quick Start

## Requirements

- **Python 3.8+** (no pip dependencies for core runtime)
- `tkinter` (included with most Python distributions; on Debian/Ubuntu: `sudo apt install python3-tk`)

## Run from Source

```bash
git clone https://github.com/ADA-XiaoYao/alfanet-srof
cd alfanet-srof
python main.py
```

## Build Standalone Executable

```bash
pip install pyinstaller
python build/build.py
# Output: dist/SROF-Linux  (or SROF-Win.exe / SROF-macOS.app)
```

## Run Tests

```bash
pip install pytest pytest-timeout
pytest tests/ -v
```

## Project Layout

```
alfanet-srof/
├── main.py                    ← Entry point
├── toolbox.py                 ← GUI (72+ tool cards)
├── requirements.txt           ← Optional deps
├── .gitignore
│
├── core/
│   ├── __init__.py
│   ├── database.py            ← SQLite data layer
│   ├── plugin.py              ← Plugin base class + registry
│   └── engine.py              ← Scheduling engine
│
├── modules/
│   ├── __init__.py
│   ├── recon/
│   │   ├── __init__.py
│   │   └── plugins.py         ← Subfinder, httpx, Nmap, ffuf, ...
│   ├── scan/
│   │   ├── __init__.py
│   │   └── plugins.py         ← Nuclei, Xray, fscan, Nikto
│   ├── exploit/
│   │   ├── __init__.py
│   │   └── plugins.py         ← sqlmap, Metasploit RPC
│   ├── post/
│   │   ├── __init__.py
│   │   └── plugins.py         ← BloodHound, CrackMapExec
│   ├── ctf/
│   │   ├── __init__.py
│   │   └── plugins.py         ← Strings, Volatility3
│   ├── cloud/
│   │   ├── __init__.py
│   │   └── plugins.py         ← CDK, kube-hunter
│   └── mobile/
│       ├── __init__.py
│       └── plugins.py         ← jadx, Frida
│
├── reports/
│   ├── __init__.py
│   └── generator.py           ← Markdown + HTML report generator
│
├── build/
│   ├── __init__.py
│   └── build.py               ← Cross-platform packaging
│
├── tests/
│   ├── __init__.py
│   └── test_core.py           ← Unit tests
│
├── docs/
│   ├── quickstart.md          ← This file
│   ├── plugin-dev.md          ← Plugin development guide
│   └── architecture.md        ← Architecture overview
│
└── .github/workflows/
    ├── ci.yml                 ← Syntax check + tests
    └── build.yml              ← Cross-platform build + Release
```
