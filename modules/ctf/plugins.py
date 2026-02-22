"""
SROF · CTF Plugins
pwntools, CyberChef, Volatility3, SageMath, Ghidra helpers
"""
import subprocess, shutil, json, re
from typing import Generator
from core.plugin import SROFPlugin, PluginConfig, Finding, register, PluginCategory, Severity


def _which(cmd): return shutil.which(cmd) is not None


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


# ─── STRINGS EXTRACTOR (pure Python) ─────────────────────────────────────────
@register
class StringsPlugin(SROFPlugin):
    id          = "ctf.strings"
    name        = "Strings Extractor"
    category    = PluginCategory.CTF
    description = "Extract printable strings from binary files (CTF reverse)"
    tags        = ["reverse", "binary", "strings", "ctf"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        filepath = config.get("file", config.target)
        min_len  = config.get("min_length", 6)
        self.info(f"Extracting strings from {filepath} (min_len={min_len})")

        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            self.error(f"Cannot open file: {e}")
            return

        pattern = re.compile(rb"[ -~]{%d,}" % min_len)
        matches = pattern.findall(data)

        for m in matches:
            s = m.decode("ascii", errors="replace")
            # Flag-like patterns
            flag_pat = re.compile(r"[A-Za-z0-9_]{2,10}\{[^}]{3,60}\}")
            if flag_pat.search(s):
                yield Finding(
                    type="vuln",
                    value=s,
                    severity=Severity.HIGH,
                    title=f"Possible Flag: {s[:80]}",
                    source=self.id,
                    metadata={"tool": "strings", "type": "flag"},
                )
            else:
                yield Finding(
                    type="asset",
                    value=s,
                    severity=Severity.INFO,
                    title=s[:80],
                    source=self.id,
                    metadata={"tool": "strings"},
                )

        self.info(f"Extracted {len(matches)} strings")


# ─── VOLATILITY3 ─────────────────────────────────────────────────────────────
@register
class Volatility3Plugin(SROFPlugin):
    id          = "ctf.volatility3"
    name        = "Volatility3"
    category    = PluginCategory.CTF
    description = "Memory forensics: process list, network, cmdline"
    tags        = ["forensics", "memory", "volatility", "ctf"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        vol = shutil.which("vol") or shutil.which("vol3") or shutil.which("volatility3")
        if not vol:
            self.warn("Volatility3 not installed.\n"
                      "Install: pip install volatility3")
            return

        image   = config.get("image", config.target)
        plugin  = config.get("vol_plugin", "windows.pslist.PsList")
        self.info(f"Volatility3: {plugin} on {image}")

        cmd = [vol, "-f", image, plugin]
        rc, out, err = _run(cmd, timeout=300)
        if rc == -2:
            self.warn("volatility3 not found")
            return

        for line in out.splitlines():
            if line.strip() and not line.startswith("Volatility"):
                yield Finding(
                    type="asset",
                    value=line.strip(),
                    severity=Severity.INFO,
                    title=line.strip()[:100],
                    source=self.id,
                    metadata={"tool": "volatility3", "plugin": plugin},
                )

        self.info("Volatility3 analysis complete")
