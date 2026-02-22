"""
SROF · Post-Exploitation Plugins
BloodHound, Impacket, ligolo-ng, etc.
"""
import subprocess, shutil, json, tempfile, os
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


# ─── BLOODHOUND PYTHON ───────────────────────────────────────────────────────
@register
class BloodhoundPlugin(SROFPlugin):
    id          = "post.bloodhound"
    name        = "BloodHound Python"
    category    = PluginCategory.POST
    description = "AD attack path enumeration via bloodhound-python"
    tags        = ["AD", "kerberos", "lateral-movement", "BloodHound"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("bloodhound-python"):
            self.warn("bloodhound-python not installed.\n"
                      "Install: pip install bloodhound")
            return

        domain   = config.get("domain", "")
        username = config.get("username", "")
        password = config.get("password", "")
        dc_ip    = config.get("dc_ip", config.target)

        if not domain:
            self.warn("domain not set in config.extra['domain']")
            return

        self.info(f"BloodHound collecting from {domain} ({dc_ip})")

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "bloodhound-python",
                "-d", domain,
                "-u", username,
                "-p", password,
                "-ns", dc_ip,
                "-c", "All",
                "--zip",
                "-o", tmpdir,
            ]
            rc, out, err = _run(cmd, timeout=300)
            if rc == -2:
                self.warn("bloodhound-python not found")
                return

            for fname in os.listdir(tmpdir):
                fpath = os.path.join(tmpdir, fname)
                yield Finding(
                    type="asset",
                    value=fpath,
                    severity=Severity.INFO,
                    title=f"BloodHound data: {fname}",
                    description="BloodHound collection file",
                    source=self.id,
                    metadata={"tool": "bloodhound-python", "file": fname},
                )

        self.info("BloodHound collection complete")


# ─── CRACKMAPEXEC ────────────────────────────────────────────────────────────
@register
class CrackMapExecPlugin(SROFPlugin):
    id          = "post.cme"
    name        = "CrackMapExec"
    category    = PluginCategory.POST
    description = "SMB/WinRM/LDAP lateral movement and credential testing"
    tags        = ["SMB", "WinRM", "lateral", "credential"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        cme = shutil.which("cme") or shutil.which("crackmapexec")
        if not cme:
            self.warn("CrackMapExec not installed.\n"
                      "Install: pip install crackmapexec")
            return

        protocol = config.get("protocol", "smb")
        target   = config.target
        self.info(f"CME {protocol} scanning {target}")

        cmd = [cme, protocol, target, "--shares"]
        rc, out, err = _run(cmd, timeout=120)
        if rc == -2:
            self.warn("crackmapexec not found")
            return

        for line in out.splitlines():
            if "[+]" in line or "SHARE" in line.upper():
                yield Finding(
                    type="asset",
                    value=line.strip(),
                    severity=Severity.INFO,
                    title=f"CME: {line.strip()[:100]}",
                    source=self.id,
                    metadata={"tool": "crackmapexec", "protocol": protocol},
                )

        self.info("CrackMapExec scan complete")
