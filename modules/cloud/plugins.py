"""
SROF · Cloud & Container Plugins
CDK, cf, pacu, kube-hunter
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


# ─── CDK (Container Escape) ──────────────────────────────────────────────────
@register
class CDKPlugin(SROFPlugin):
    id          = "cloud.cdk"
    name        = "CDK"
    category    = PluginCategory.CLOUD
    description = "Container escape and K8s attack toolkit"
    tags        = ["docker", "container", "escape", "k8s"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("cdk"):
            self.warn("CDK not installed.\n"
                      "Download: https://github.com/cdk-team/CDK/releases")
            return

        self.info("CDK: evaluating container environment")
        cmd = ["cdk", "evaluate", "--full"]
        rc, out, err = _run(cmd, timeout=60)
        if rc == -2:
            self.warn("cdk not found")
            return

        for line in out.splitlines():
            if any(k in line.lower() for k in ["escape", "privilege", "cap_sys", "docker.sock"]):
                yield Finding(
                    type="vuln",
                    value=line.strip(),
                    severity=Severity.HIGH,
                    title=f"CDK: {line.strip()[:100]}",
                    source=self.id,
                    metadata={"tool": "cdk"},
                )
            elif line.strip():
                yield Finding(
                    type="asset",
                    value=line.strip(),
                    severity=Severity.INFO,
                    title=line.strip()[:100],
                    source=self.id,
                    metadata={"tool": "cdk"},
                )

        self.info("CDK evaluation complete")


# ─── KUBE-HUNTER ─────────────────────────────────────────────────────────────
@register
class KubeHunterPlugin(SROFPlugin):
    id          = "cloud.kube_hunter"
    name        = "kube-hunter"
    category    = PluginCategory.CLOUD
    description = "Kubernetes cluster security scanning"
    tags        = ["k8s", "kubernetes", "cluster", "rbac"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("kube-hunter"):
            self.warn("kube-hunter not installed.\n"
                      "Install: pip install kube-hunter")
            return

        target = config.target
        self.info(f"kube-hunter scanning {target}")

        cmd = ["kube-hunter", "--remote", target, "--report", "json"]
        rc, out, err = _run(cmd, timeout=300)
        if rc == -2:
            self.warn("kube-hunter not found")
            return

        try:
            data = json.loads(out)
        except Exception:
            data = {}

        for vuln in data.get("vulnerabilities", []):
            yield Finding(
                type="vuln",
                value=vuln.get("location", target),
                severity=Severity.HIGH,
                title=vuln.get("vulnerability", "K8s Vulnerability"),
                description=vuln.get("description", ""),
                evidence={"category": vuln.get("category", "")},
                source=self.id,
                metadata={"tool": "kube-hunter"},
            )

        self.info("kube-hunter scan complete")
