"""
SROF · Mobile Security Plugins
jadx, Frida, objection, MobSF
"""
import subprocess, shutil, json, re
from typing import Generator
from core.plugin import SROFPlugin, PluginConfig, Finding, register, PluginCategory, Severity


def _which(cmd): return shutil.which(cmd) is not None


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


# ─── JADX DECOMPILER ─────────────────────────────────────────────────────────
@register
class JadxPlugin(SROFPlugin):
    id          = "mobile.jadx"
    name        = "jadx Decompiler"
    category    = PluginCategory.MOBILE
    description = "Decompile APK/DEX to Java source and search for secrets"
    tags        = ["android", "apk", "decompile", "reverse"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        jadx = shutil.which("jadx")
        if not jadx:
            self.warn("jadx not installed.\n"
                      "Download: https://github.com/skylot/jadx/releases")
            return

        apk_path = config.get("apk", config.target)
        self.info(f"jadx decompiling {apk_path}")

        import tempfile, os
        with tempfile.TemporaryDirectory() as outdir:
            cmd = [jadx, "-d", outdir, apk_path]
            rc, out, err = _run(cmd, timeout=300)
            if rc == -2:
                self.warn("jadx not found")
                return

            # Search for hardcoded secrets in decompiled sources
            secret_patterns = [
                (r"(?i)(api[_-]?key|secret|password|token)\s*=\s*[\"'][^\"']{8,}[\"']",
                 "Hardcoded Secret"),
                (r"(?i)(http|https)://[^\s\"']{10,}", "Hardcoded URL"),
                (r"(?i)BEGIN\s+(RSA|EC)\s+PRIVATE\s+KEY", "Embedded Private Key"),
            ]

            for root, dirs, files in os.walk(outdir):
                for fname in files:
                    if not fname.endswith(".java"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                    except Exception:
                        continue

                    for pattern, label in secret_patterns:
                        for match in re.finditer(pattern, content):
                            yield Finding(
                                type="vuln",
                                value=match.group()[:120],
                                severity=Severity.HIGH,
                                title=f"{label} in {fname}",
                                description=f"Found in {fpath}",
                                source=self.id,
                                metadata={"tool": "jadx", "file": fname},
                            )

        self.info("jadx analysis complete")


# ─── FRIDA PROCESS LIST ───────────────────────────────────────────────────────
@register
class FridaPlugin(SROFPlugin):
    id          = "mobile.frida"
    name        = "Frida"
    category    = PluginCategory.MOBILE
    description = "Dynamic instrumentation: list processes on connected device"
    tags        = ["android", "ios", "frida", "dynamic", "hook"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("frida"):
            self.warn("Frida not installed.\n"
                      "Install: pip install frida-tools")
            return

        device = config.get("device", "usb")
        self.info(f"Frida listing processes on device: {device}")

        cmd = ["frida-ps", f"-{device[0]}"]  # -u for usb, -r for remote
        rc, out, err = _run(cmd, timeout=30)
        if rc == -2:
            self.warn("frida-ps not found")
            return

        for line in out.splitlines()[1:]:  # skip header
            parts = line.split(None, 1)
            if len(parts) == 2:
                pid, name = parts
                yield Finding(
                    type="asset",
                    value=f"PID {pid}: {name}",
                    severity=Severity.INFO,
                    title=f"Process: {name.strip()}",
                    source=self.id,
                    metadata={"tool": "frida", "pid": pid, "name": name.strip()},
                )

        self.info("Frida process enumeration complete")
