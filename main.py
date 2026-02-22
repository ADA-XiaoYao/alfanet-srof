#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ALFANET · SROF 2026
Security Research Operating Framework
Run: python main.py
"""
import sys, os, threading, importlib

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def _init_backend():
    try:
        from core.database import init_db
        init_db()
        from core.plugin import PluginRegistry
        # Dynamically load all plugin modules (import * not allowed inside functions)
        for mod_name in ("modules.recon.plugins", "modules.scan.plugins"):
            try:
                importlib.import_module(mod_name)
            except Exception as e:
                print(f"[SROF] Plugin module warning ({mod_name}): {e}")
        print(f"[SROF] {PluginRegistry.count()} plugins loaded")
    except Exception as e:
        print(f"[SROF] Backend warning: {e}")


def main():
    threading.Thread(target=_init_backend, daemon=True).start()
    from toolbox import Toolbox
    Toolbox().mainloop()


if __name__ == "__main__":
    main()
