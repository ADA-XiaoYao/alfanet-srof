"""
SROF · Plugin System
每个插件实现 SROFPlugin 接口，注册后由引擎调度
"""
import importlib, inspect, pkgutil, json, time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Generator
from pathlib import Path
from enum import Enum


# ─── ENUMS ───────────────────────────────────────────────────────────────────
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class PluginCategory(str, Enum):
    RECON   = "recon"
    SCAN    = "scan"
    EXPLOIT = "exploit"
    POST    = "post"
    CTF     = "ctf"
    CLOUD   = "cloud"
    MOBILE  = "mobile"
    CRACK   = "crack"
    UTIL    = "util"


# ─── RESULT TYPES ────────────────────────────────────────────────────────────
@dataclass
class Finding:
    """A single result emitted by a plugin."""
    type: str                    # asset | vuln | info | chain_step
    value: str                   # the main value (URL, hash, subdomain, etc.)
    severity: str = Severity.INFO
    title: str = ""
    description: str = ""
    evidence: dict = field(default_factory=dict)
    cve: str = ""
    cvss: float = 0.0
    metadata: dict = field(default_factory=dict)
    source: str = ""             # plugin id
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "type":        self.type,
            "value":       self.value,
            "severity":    self.severity,
            "title":       self.title,
            "description": self.description,
            "evidence":    self.evidence,
            "cve":         self.cve,
            "cvss":        self.cvss,
            "metadata":    self.metadata,
            "source":      self.source,
            "ts":          self.ts,
        }


@dataclass
class PluginConfig:
    """Runtime config passed to every plugin."""
    target: str                  # primary target (host / URL / IP range)
    workspace_id: int = 1
    job_id: int = 0
    timeout: int = 30
    threads: int = 10
    rate_limit: int = 100        # req/s
    proxy: Optional[str] = None  # http://127.0.0.1:8080
    output_dir: Path = Path("./data/output")
    extra: dict = field(default_factory=dict)  # plugin-specific params

    def get(self, key: str, default=None):
        return self.extra.get(key, default)


# ─── BASE PLUGIN ─────────────────────────────────────────────────────────────
class SROFPlugin(ABC):
    """
    All plugins inherit this class.

    Required class attributes:
        id          str   unique snake_case identifier
        name        str   display name
        category    str   PluginCategory value
        description str   one-line description
        tags        list  free-form labels

    Optional:
        author      str
        version     str
        requires    list  other plugin ids this depends on
        severity    str   default finding severity
    """
    id: str          = ""
    name: str        = ""
    category: str    = PluginCategory.UTIL
    description: str = ""
    tags: list       = []
    author: str      = "XiaoYao @ Alfanet"
    version: str     = "1.0.0"
    requires: list   = []
    enabled: bool    = True

    def __init__(self):
        self._log_cb = None    # injected by engine

    def set_logger(self, cb):
        self._log_cb = cb

    def log(self, msg: str, level: str = "info", data: dict = None):
        if self._log_cb:
            self._log_cb(self.id, msg, level, data or {})

    def info(self, msg: str, **kw):  self.log(msg, "info", kw or None)
    def warn(self, msg: str, **kw):  self.log(msg, "warn", kw or None)
    def error(self, msg: str, **kw): self.log(msg, "error", kw or None)
    def debug(self, msg: str, **kw): self.log(msg, "debug", kw or None)

    @abstractmethod
    def run(self, config: PluginConfig) -> Generator[Finding, None, None]:
        """
        Yield Finding objects as they are discovered.
        Must be a generator – allows streaming results to UI/DB.
        """
        ...

    def validate_config(self, config: PluginConfig) -> Optional[str]:
        """Return error string if config is invalid, else None."""
        return None

    @classmethod
    def meta(cls) -> dict:
        return {
            "id":          cls.id,
            "name":        cls.name,
            "category":    cls.category,
            "description": cls.description,
            "tags":        cls.tags,
            "author":      cls.author,
            "version":     cls.version,
            "requires":    cls.requires,
            "enabled":     cls.enabled,
        }


# ─── PLUGIN REGISTRY ─────────────────────────────────────────────────────────
class PluginRegistry:
    _plugins: Dict[str, type] = {}

    @classmethod
    def register(cls, plugin_cls: type) -> type:
        """Decorator to register a plugin."""
        if not plugin_cls.id:
            raise ValueError(f"Plugin {plugin_cls.__name__} has no id")
        cls._plugins[plugin_cls.id] = plugin_cls
        return plugin_cls

    @classmethod
    def get(cls, plugin_id: str) -> Optional[type]:
        return cls._plugins.get(plugin_id)

    @classmethod
    def all(cls) -> Dict[str, type]:
        return dict(cls._plugins)

    @classmethod
    def by_category(cls, category: str) -> List[type]:
        return [p for p in cls._plugins.values()
                if p.category == category and p.enabled]

    @classmethod
    def list_meta(cls) -> List[dict]:
        return [p.meta() for p in cls._plugins.values()]

    @classmethod
    def load_directory(cls, directory: Path):
        """Auto-discover and load all plugins in a directory."""
        import sys
        sys.path.insert(0, str(directory.parent))
        for finder, name, ispkg in pkgutil.walk_packages(
                [str(directory)], prefix=directory.name + "."):
            try:
                mod = importlib.import_module(name)
                for _, obj in inspect.getmembers(mod, inspect.isclass):
                    if (issubclass(obj, SROFPlugin)
                            and obj is not SROFPlugin
                            and obj.id
                            and obj.id not in cls._plugins):
                        cls._plugins[obj.id] = obj
            except Exception as e:
                print(f"[PluginLoader] Failed to load {name}: {e}")

    @classmethod
    def count(cls) -> int:
        return len(cls._plugins)


# ─── DECORATOR SHORTHAND ─────────────────────────────────────────────────────
def register(plugin_cls):
    """Shorthand decorator."""
    return PluginRegistry.register(plugin_cls)
