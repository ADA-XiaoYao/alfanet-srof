"""
SROF · Scan Plugins
Vulnerability scanning: Nuclei, Xray, fscan, nikto
"""
import subprocess, shutil, json, re, tempfile, os
from typing import Generator
from core.plugin import SROFPlugin, PluginConfig, Finding, register, PluginCategory, Severity


def _which(cmd):  return shutil.which(cmd) is not None
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


SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "unknown":  Severity.INFO,
}


# ─── NUCLEI ──────────────────────────────────────────────────────────────────
@register
class NucleiPlugin(SROFPlugin):
    id          = "scan.nuclei"
    name        = "Nuclei v3"
    category    = PluginCategory.SCAN
    description = "Template-based vulnerability scanner (9000+ templates)"
    tags        = ["vuln-scan", "poc", "templates", "oast"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("nuclei"):
            self.warn("nuclei not installed.\n"
                      "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
                      "Update templates: nuclei -update-templates")
            return

        severity  = config.get("severity", "critical,high,medium")
        templates = config.get("templates", "")
        target    = config.target

        self.info(f"Nuclei scanning {target} [severity: {severity}]")

        cmd = [
            "nuclei",
            "-u", target,
            "-severity", severity,
            "-json", "-silent",
            "-timeout", str(config.timeout),
            "-c", str(config.threads),
        ]
        if templates:
            cmd += ["-t", templates]
        if config.proxy:
            cmd += ["-proxy", config.proxy]

        rc, out, err = _run(cmd, timeout=600)
        if rc == -2:
            self.warn("nuclei binary not found")
            return

        count = 0
        for line in out.strip().splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue

            sev      = d.get("info", {}).get("severity", "info").lower()
            name     = d.get("info", {}).get("name", d.get("template-id", ""))
            matched  = d.get("matched-at", target)
            desc     = d.get("info", {}).get("description", "")
            cve_list = d.get("info", {}).get("classification", {}).get("cve-id", [])
            cvss     = d.get("info", {}).get("classification", {}).get("cvss-score", 0.0)
            request  = d.get("request", "")
            response = d.get("response", "")[:500] if d.get("response") else ""
            cve      = cve_list[0] if cve_list else ""

            yield Finding(
                type="vuln",
                value=matched,
                severity=SEV_MAP.get(sev, Severity.INFO),
                title=name,
                description=desc,
                cve=cve,
                cvss=float(cvss) if cvss else 0.0,
                evidence={
                    "request":     request,
                    "response":    response,
                    "template_id": d.get("template-id", ""),
                    "matcher":     d.get("matcher-name", ""),
                },
                source=self.id,
                metadata={"tool": "nuclei", "severity": sev},
            )
            count += 1

        self.info(f"Nuclei found {count} issues")


# ─── XRAY ────────────────────────────────────────────────────────────────────
@register
class XrayPlugin(SROFPlugin):
    id          = "scan.xray"
    name        = "Xray"
    category    = PluginCategory.SCAN
    description = "Passive scanner from Chaitin (OWASP Top10 coverage)"
    tags        = ["passive-scan", "owasp", "chaitin"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        xray_bin = shutil.which("xray") or shutil.which("xray_linux_amd64") \
                   or shutil.which("xray_darwin_amd64") or shutil.which("xray_windows_amd64.exe")

        if not xray_bin:
            self.warn("xray not found. Download: https://github.com/chaitin/xray/releases")
            return

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_file = tmp.name

        target = config.target
        self.info(f"Xray scanning {target}")

        cmd = [
            xray_bin, "webscan",
            "--basic-crawler", target,
            "--json-output", out_file,
        ]
        if config.proxy:
            cmd += ["--http-proxy", config.proxy]

        rc, _, err = _run(cmd, timeout=300)
        if rc == -2:
            self.warn("xray binary not found")
            if os.path.exists(out_file):
                os.unlink(out_file)
            return

        try:
            with open(out_file) as f:
                content = f.read()
            os.unlink(out_file)
        except Exception:
            return

        for line in content.strip().splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue

            vuln_type = d.get("type", "unknown")
            detail    = d.get("detail", {})
            url       = detail.get("addr", target)
            payload   = detail.get("payload", "")

            severity_map = {
                "xss":   Severity.HIGH,
                "sqli":  Severity.CRITICAL,
                "ssrf":  Severity.HIGH,
                "xxe":   Severity.HIGH,
                "jsonp": Severity.MEDIUM,
            }
            sev = severity_map.get(vuln_type.lower(), Severity.MEDIUM)

            yield Finding(
                type="vuln",
                value=url,
                severity=sev,
                title=f"Xray: {vuln_type.upper()} at {url}",
                description=f"Xray detected {vuln_type}",
                evidence={"payload": payload, "detail": detail},
                source=self.id,
                metadata={"tool": "xray", "vuln_type": vuln_type},
            )

        self.info("Xray scan complete")


# ─── FSCAN (内网) ──────────────────────────────────────────────────────────
@register
class FscanPlugin(SROFPlugin):
    id          = "scan.fscan"
    name        = "fscan"
    category    = PluginCategory.SCAN
    description = "Internal network scanner: port + service + weak creds + PoC"
    tags        = ["intranet", "weak-creds", "hvv", "PoC"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        fscan_bin = shutil.which("fscan") or shutil.which("fscan_amd64")
        if not fscan_bin:
            self.warn("fscan not found. Download: https://github.com/shadow1ng/fscan/releases")
            return

        target = config.target
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tmp:
            out_file = tmp.name

        self.info(f"fscan scanning {target}")
        cmd = [fscan_bin, "-h", target, "-o", out_file, "-np", "-nobr"]
        rc, out, err = _run(cmd, timeout=600)
        if rc == -2:
            self.warn("fscan not found")
            if os.path.exists(out_file): os.unlink(out_file)
            return

        try:
            with open(out_file) as f:
                lines = f.readlines()
            os.unlink(out_file)
        except Exception:
            lines = out.splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            sev = Severity.INFO
            vtype = "info"
            if any(k in line.lower() for k in ["vulnerab", "poc", "rce", "cve"]):
                sev   = Severity.HIGH
                vtype = "vuln"
            elif "weak" in line.lower() or "password" in line.lower():
                sev   = Severity.HIGH
                vtype = "vuln"
            elif "open" in line.lower():
                sev   = Severity.INFO
                vtype = "asset"

            yield Finding(
                type=vtype,
                value=line,
                severity=sev,
                title=line[:80],
                source=self.id,
                metadata={"tool": "fscan"},
            )

        self.info("fscan complete")


# ─── NIKTO ───────────────────────────────────────────────────────────────────
@register
class NiktoPlugin(SROFPlugin):
    id          = "scan.nikto"
    name        = "Nikto"
    category    = PluginCategory.SCAN
    description = "Web server scanner: dangerous files, outdated software"
    tags        = ["web-server", "cve", "configuration"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("nikto"):
            self.warn("nikto not installed. Install: https://github.com/sullo/nikto")
            return

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_file = tmp.name

        cmd = [
            "nikto", "-h", config.target,
            "-o", out_file, "-Format", "json", "-nointeractive",
        ]
        if config.proxy:
            cmd += ["-useproxy", config.proxy]

        rc, _, _ = _run(cmd, timeout=300)
        if rc == -2:
            self.warn("nikto not found")
            if os.path.exists(out_file): os.unlink(out_file)
            return

        try:
            with open(out_file) as f:
                data = json.load(f)
            os.unlink(out_file)
        except Exception:
            return

        for vuln in data.get("vulnerabilities", []):
            url  = vuln.get("url", config.target)
            msg  = vuln.get("msg", "")
            refs = vuln.get("references", {})

            yield Finding(
                type="vuln",
                value=url,
                severity=Severity.MEDIUM,
                title=f"Nikto: {msg[:80]}",
                description=msg,
                evidence={"references": refs},
                source=self.id,
                metadata={"tool": "nikto"},
            )

        self.info("Nikto scan complete")
