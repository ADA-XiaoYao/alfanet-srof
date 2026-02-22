"""
SROF · Recon Plugins
All recon plugins wrap external tools via subprocess
and parse their output into Finding objects.
"""
import subprocess, shutil, json, re, socket
from typing import Generator
from core.plugin import SROFPlugin, PluginConfig, Finding, register, PluginCategory, Severity


def _which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run(cmd: list, timeout: int = 60) -> tuple[int, str, str]:
    """Run subprocess, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


# ─── SUBFINDER ───────────────────────────────────────────────────────────────
@register
class SubfinderPlugin(SROFPlugin):
    id          = "recon.subfinder"
    name        = "Subfinder"
    category    = PluginCategory.RECON
    description = "Passive subdomain enumeration via 50+ sources"
    tags        = ["subdomain", "passive", "osint"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("subfinder"):
            self.warn("subfinder not installed. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            return

        target = re.sub(r"https?://", "", config.target).rstrip("/").split("/")[0]
        self.info(f"Starting subfinder on {target}")

        cmd = ["subfinder", "-d", target, "-silent", "-json"]
        if config.proxy:
            cmd += ["-proxy", config.proxy]
        if config.timeout:
            cmd += ["-timeout", str(config.timeout)]

        rc, out, err = _run(cmd, timeout=300)
        if rc == -2:
            self.warn("subfinder binary not found")
            return
        if rc < 0:
            self.error(f"subfinder failed: {err}")
            return

        count = 0
        for line in out.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", line)
            except json.JSONDecodeError:
                host = line

            yield Finding(
                type="asset",
                value=host,
                severity=Severity.INFO,
                title=f"Subdomain: {host}",
                source=self.id,
                metadata={"asset_type": "subdomain", "tool": "subfinder"},
            )
            count += 1

        self.info(f"subfinder found {count} subdomains")


# ─── HTTPX PROBE ─────────────────────────────────────────────────────────────
@register
class HttpxPlugin(SROFPlugin):
    id          = "recon.httpx"
    name        = "httpx Probe"
    category    = PluginCategory.RECON
    description = "HTTP/HTTPS probing with tech fingerprinting"
    tags        = ["http", "fingerprint", "cdn"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("httpx"):
            self.warn("httpx not installed. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
            return

        target = config.target
        self.info(f"httpx probing {target}")

        cmd = [
            "httpx", "-u", target,
            "-title", "-tech-detect", "-status-code",
            "-content-length", "-cdn", "-json", "-silent",
        ]
        if config.timeout:
            cmd += ["-timeout", str(config.timeout)]

        rc, out, err = _run(cmd, timeout=120)
        if rc == -2:
            self.warn("httpx binary not found")
            return

        for line in out.strip().splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue

            url    = d.get("url", target)
            title  = d.get("title", "")
            status = d.get("status_code", 0)
            techs  = d.get("tech", [])
            is_cdn = d.get("cdn", False)
            cl     = d.get("content_length", 0)

            yield Finding(
                type="asset",
                value=url,
                severity=Severity.INFO,
                title=f"[{status}] {title or url}",
                description=f"Technologies: {', '.join(techs) if techs else 'unknown'}",
                source=self.id,
                metadata={
                    "asset_type": "url",
                    "status_code": status,
                    "title": title,
                    "technologies": techs,
                    "is_cdn": is_cdn,
                    "content_length": cl,
                    "tool": "httpx",
                },
            )

        self.info("httpx probe complete")


# ─── NMAP ────────────────────────────────────────────────────────────────────
@register
class NmapPlugin(SROFPlugin):
    id          = "recon.nmap"
    name        = "Nmap"
    category    = PluginCategory.RECON
    description = "Port scan + service detection (--min-rate 5000)"
    tags        = ["port-scan", "service", "nse"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("nmap"):
            self.warn("nmap not installed. Install: https://nmap.org")
            return

        target = re.sub(r"https?://", "", config.target).split("/")[0]
        ports  = config.get("ports", "1-65535")
        rate   = config.get("min_rate", 5000)
        self.info(f"nmap scanning {target} ports {ports}")

        cmd = [
            "nmap", "-sV", "-sC",
            f"--min-rate={rate}",
            "-p", str(ports),
            "-oX", "-",       # XML to stdout
            target
        ]

        rc, out, err = _run(cmd, timeout=600)
        if rc == -2:
            self.warn("nmap not found")
            return

        # Parse XML output
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(out)
        except ET.ParseError:
            self.error("Failed to parse nmap XML")
            return

        for host_el in root.findall("host"):
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid  = port_el.get("portid", "?")
                proto   = port_el.get("protocol", "tcp")
                svc_el  = port_el.find("service")
                svc     = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""

                label = f"{svc} {product} {version}".strip()

                yield Finding(
                    type="asset",
                    value=f"{target}:{portid}",
                    severity=Severity.INFO,
                    title=f"Open Port {portid}/{proto}: {label}",
                    source=self.id,
                    metadata={
                        "asset_type": "service",
                        "port": int(portid),
                        "protocol": proto,
                        "service": svc,
                        "product": product,
                        "version": version,
                        "tool": "nmap",
                    },
                )

        self.info("nmap scan complete")


# ─── FFUF DIRECTORY ──────────────────────────────────────────────────────────
@register
class FfufPlugin(SROFPlugin):
    id          = "recon.ffuf"
    name        = "ffuf Directory Bruteforce"
    category    = PluginCategory.RECON
    description = "Fast web fuzzing for directories and endpoints"
    tags        = ["directory", "fuzzing", "bruteforce"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("ffuf"):
            self.warn("ffuf not installed. Install: go install github.com/ffuf/ffuf/v2@latest")
            return

        import tempfile, os
        wordlist = config.get("wordlist",
                              "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt")
        target = config.target.rstrip("/") + "/FUZZ"
        self.info(f"ffuf fuzzing {target}")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_file = tmp.name

        cmd = [
            "ffuf", "-u", target,
            "-w", wordlist,
            "-mc", "200,201,204,301,302,307,401,403",
            "-o", out_file, "-of", "json",
            "-t", str(config.threads),
            "-timeout", str(config.timeout),
            "-s",   # silent
        ]
        if config.proxy:
            cmd += ["-x", config.proxy]

        rc, _, err = _run(cmd, timeout=600)
        if rc == -2:
            self.warn("ffuf not found")
            os.unlink(out_file)
            return

        try:
            with open(out_file) as f:
                data = json.load(f)
            os.unlink(out_file)
        except Exception:
            self.error("ffuf output parse failed")
            return

        for result in data.get("results", []):
            url    = result.get("url", "")
            status = result.get("status", 0)
            length = result.get("length", 0)

            yield Finding(
                type="asset",
                value=url,
                severity=Severity.INFO,
                title=f"[{status}] {url}",
                source=self.id,
                metadata={
                    "asset_type": "url",
                    "status_code": status,
                    "content_length": length,
                    "tool": "ffuf",
                },
            )

        self.info(f"ffuf found {len(data.get('results', []))} paths")


# ─── TRUFFLEHOG ──────────────────────────────────────────────────────────────
@register
class TrufflehogPlugin(SROFPlugin):
    id          = "recon.trufflehog"
    name        = "TruffleHog Secret Scanner"
    category    = PluginCategory.RECON
    description = "Scan git repos / URLs for leaked secrets (700+ rules)"
    tags        = ["secrets", "leak", "git", "api-key"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        if not _which("trufflehog"):
            self.warn("trufflehog not installed. Install: https://github.com/trufflesecurity/trufflehog")
            return

        target = config.target
        self.info(f"TruffleHog scanning {target}")

        cmd = ["trufflehog", "git", target, "--json", "--only-verified"]
        rc, out, err = _run(cmd, timeout=300)
        if rc == -2:
            self.warn("trufflehog not found")
            return

        for line in out.strip().splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue

            det_type = d.get("DetectorName", "Unknown")
            raw      = d.get("Raw", "")[:80]
            source   = d.get("SourceMetadata", {})

            yield Finding(
                type="vuln",
                value=raw,
                severity=Severity.HIGH,
                title=f"Leaked Secret: {det_type}",
                description=f"Verified secret found via {det_type}",
                evidence={"raw": raw, "source_meta": source},
                source=self.id,
                metadata={"tool": "trufflehog", "detector": det_type},
            )

        self.info("TruffleHog scan complete")


# ─── DNS RESOLVER (pure Python, no external tool needed) ─────────────────────
@register
class DnsResolvePlugin(SROFPlugin):
    id          = "recon.dns_resolve"
    name        = "DNS Resolver"
    category    = PluginCategory.RECON
    description = "Resolve A/AAAA records for a list of subdomains"
    tags        = ["dns", "resolve", "pure-python"]
    author      = "XiaoYao @ Alfanet"

    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        hosts = config.get("hosts", [config.target])
        self.info(f"Resolving {len(hosts)} hosts")

        for host in hosts:
            host = re.sub(r"https?://", "", host).split("/")[0]
            try:
                addrs = socket.getaddrinfo(host, None)
                ips   = list({a[4][0] for a in addrs})
                for ip in ips:
                    yield Finding(
                        type="asset",
                        value=f"{host} → {ip}",
                        severity=Severity.INFO,
                        title=f"DNS: {host} → {ip}",
                        source=self.id,
                        metadata={"asset_type": "dns", "host": host, "ip": ip},
                    )
            except Exception as e:
                self.debug(f"Cannot resolve {host}: {e}")

        self.info("DNS resolution complete")
