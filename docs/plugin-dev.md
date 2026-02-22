# SROF · Plugin Development Guide

## Overview

SROF uses a plugin architecture where every tool is a `SROFPlugin` subclass.
Plugins are auto-discovered at startup and appear as cards in the GUI.

## Minimal Plugin

```python
from core.plugin import SROFPlugin, PluginConfig, Finding, register, PluginCategory, Severity

@register
class MyPlugin(SROFPlugin):
    id          = "recon.mytool"          # unique dotted ID
    name        = "My Tool"              # display name in GUI
    category    = PluginCategory.RECON   # category tab
    description = "Does something useful"
    tags        = ["custom", "example"]

    def run(self, config: PluginConfig):
        """Must be a generator — yield Finding objects."""
        import subprocess
        out = subprocess.check_output(
            ["mytool", "-d", config.target], text=True
        )
        for line in out.splitlines():
            yield Finding(
                type="asset",
                value=line,
                severity=Severity.INFO,
                source=self.id,
            )
```

## PluginConfig Fields

| Field | Type | Description |
|-------|------|-------------|
| `target` | `str` | Primary target (host / URL / IP range) |
| `workspace_id` | `int` | Active workspace ID |
| `job_id` | `int` | Current job ID (set by engine) |
| `timeout` | `int` | Per-request timeout in seconds |
| `threads` | `int` | Concurrency level |
| `rate_limit` | `int` | Requests per second |
| `proxy` | `str` | HTTP proxy URL (optional) |
| `output_dir` | `Path` | Output directory |
| `extra` | `dict` | Plugin-specific parameters |

Access extra params via `config.get("key", default)`.

## Finding Types

| `type` | Use for |
|--------|---------|
| `"asset"` | Subdomains, URLs, open ports, services |
| `"vuln"` | Vulnerabilities, misconfigurations |
| `"info"` | General information |
| `"chain_step"` | Attack chain steps |

## Severity Levels

`Severity.CRITICAL` > `Severity.HIGH` > `Severity.MEDIUM` > `Severity.LOW` > `Severity.INFO`

## Plugin Categories

| Category | Enum | Description |
|----------|------|-------------|
| Recon | `PluginCategory.RECON` | Information gathering |
| Scan | `PluginCategory.SCAN` | Vulnerability scanning |
| Exploit | `PluginCategory.EXPLOIT` | Exploitation |
| Post | `PluginCategory.POST` | Post-exploitation |
| CTF | `PluginCategory.CTF` | CTF challenges |
| Cloud | `PluginCategory.CLOUD` | Cloud & container |
| Mobile | `PluginCategory.MOBILE` | Mobile security |
| Crack | `PluginCategory.CRACK` | Password cracking |
| Util | `PluginCategory.UTIL` | Utilities |

## Logging

Use the built-in logger (output goes to DB and live UI):

```python
self.info("Starting scan...")
self.warn("Tool not found")
self.error("Unexpected error", detail="traceback here")
self.debug("Raw output", raw=output[:200])
```

## Where to Place Plugins

Place new plugin files in the appropriate `modules/<category>/` directory.
They are auto-imported at startup via `main.py`.

```
modules/
├── recon/plugins.py      ← add recon plugins here
├── scan/plugins.py       ← add scan plugins here
├── exploit/plugins.py
├── post/plugins.py
├── ctf/plugins.py
├── cloud/plugins.py
└── mobile/plugins.py
```

## Running Tests

```bash
pytest tests/ -v
```
