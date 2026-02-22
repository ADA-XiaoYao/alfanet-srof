"""
SROF · Core Unit Tests
Tests for plugin system, database layer, and engine.
Run: pytest tests/ -v
"""
import os, sys, pytest, tempfile
from pathlib import Path

# Ensure project root is on sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Use a temporary DB for all tests
os.environ["SROF_DB"] = str(Path(tempfile.gettempdir()) / "srof_test.db")


# ─── Plugin System ────────────────────────────────────────────────────────────
class TestPluginSystem:
    def test_import_plugin_module(self):
        from core.plugin import SROFPlugin, PluginRegistry, PluginConfig, Finding
        assert SROFPlugin is not None
        assert PluginRegistry is not None

    def test_register_plugin(self):
        from core.plugin import SROFPlugin, PluginRegistry, PluginConfig, Finding, register, PluginCategory

        @register
        class DummyPlugin(SROFPlugin):
            id          = "test.dummy"
            name        = "Dummy"
            category    = PluginCategory.UTIL
            description = "Test plugin"
            tags        = ["test"]

            def run(self, config: PluginConfig):
                yield Finding(type="asset", value="test_value", source=self.id)

        assert PluginRegistry.get("test.dummy") is not None

    def test_plugin_run_yields_finding(self):
        from core.plugin import PluginRegistry, PluginConfig

        cls = PluginRegistry.get("test.dummy")
        assert cls is not None

        plugin = cls()
        config = PluginConfig(target="example.com")
        findings = list(plugin.run(config))
        assert len(findings) == 1
        assert findings[0].value == "test_value"

    def test_finding_to_dict(self):
        from core.plugin import Finding, Severity
        f = Finding(
            type="vuln",
            value="http://example.com",
            severity=Severity.HIGH,
            title="Test Vuln",
            source="test.plugin",
        )
        d = f.to_dict()
        assert d["type"] == "vuln"
        assert d["severity"] == Severity.HIGH
        assert d["source"] == "test.plugin"

    def test_plugin_category_enum(self):
        from core.plugin import PluginCategory
        assert PluginCategory.RECON == "recon"
        assert PluginCategory.SCAN  == "scan"

    def test_plugin_count(self):
        from core.plugin import PluginRegistry
        # At least the dummy plugin registered above
        assert PluginRegistry.count() >= 1


# ─── Database Layer ───────────────────────────────────────────────────────────
class TestDatabase:
    def test_init_db(self):
        from core.database import init_db
        result = init_db()
        assert result is True

    def test_workspace_create_and_get(self):
        from core.database import WorkspaceRepo
        ws_id = WorkspaceRepo.create("test_workspace", "A test workspace")
        assert isinstance(ws_id, int)
        ws = WorkspaceRepo.get(ws_id)
        assert ws is not None
        assert ws["name"] == "test_workspace"

    def test_workspace_list_all(self):
        from core.database import WorkspaceRepo
        WorkspaceRepo.create("list_test_ws")
        all_ws = WorkspaceRepo.list_all()
        assert isinstance(all_ws, list)
        assert len(all_ws) >= 1

    def test_target_add_and_list(self):
        from core.database import WorkspaceRepo, TargetRepo, Target
        ws_id = WorkspaceRepo.create("target_test_ws")
        t = Target(host="192.168.1.1", workspace_id=ws_id, port=80)
        tid = TargetRepo.add(t)
        assert isinstance(tid, int)

        targets = TargetRepo.list_by_workspace(ws_id)
        assert len(targets) >= 1
        assert targets[0]["host"] == "192.168.1.1"

    def test_asset_add_and_list(self):
        from core.database import WorkspaceRepo, TargetRepo, AssetRepo, Target, Asset
        ws_id = WorkspaceRepo.create("asset_test_ws")
        tid   = TargetRepo.add(Target(host="10.0.0.1", workspace_id=ws_id))
        aid   = AssetRepo.add(Asset(
            target_id=tid, type="subdomain",
            value="sub.example.com", source="test"
        ))
        assert isinstance(aid, int)

        assets = AssetRepo.list_by_target(tid)
        assert len(assets) >= 1
        assert assets[0]["value"] == "sub.example.com"

    def test_vuln_add_and_stats(self):
        from core.database import WorkspaceRepo, TargetRepo, VulnRepo, Target, Vulnerability
        ws_id = WorkspaceRepo.create("vuln_test_ws")
        tid   = TargetRepo.add(Target(host="vuln.example.com", workspace_id=ws_id))
        VulnRepo.add(Vulnerability(
            target_id=tid,
            plugin_id="test.scanner",
            name="Test XSS",
            severity="high",
            description="Cross-site scripting",
        ))
        stats = VulnRepo.stats_by_workspace(ws_id)
        assert stats.get("high", 0) >= 1

    def test_job_lifecycle(self):
        from core.database import WorkspaceRepo, JobRepo
        ws_id  = WorkspaceRepo.create("job_test_ws")
        job_id = JobRepo.create(ws_id, "recon", {"target": "example.com"})
        assert isinstance(job_id, int)
        JobRepo.start(job_id)
        JobRepo.finish(job_id, result_count=5)
        JobRepo.log(job_id, "test.plugin", "Test log message", "info")


# ─── Module Imports ───────────────────────────────────────────────────────────
class TestModuleImports:
    def test_recon_plugins_import(self):
        import modules.recon.plugins
        assert modules.recon.plugins is not None

    def test_scan_plugins_import(self):
        import modules.scan.plugins
        assert modules.scan.plugins is not None

    def test_exploit_plugins_import(self):
        import modules.exploit.plugins
        assert modules.exploit.plugins is not None

    def test_post_plugins_import(self):
        import modules.post.plugins
        assert modules.post.plugins is not None

    def test_ctf_plugins_import(self):
        import modules.ctf.plugins
        assert modules.ctf.plugins is not None

    def test_cloud_plugins_import(self):
        import modules.cloud.plugins
        assert modules.cloud.plugins is not None

    def test_mobile_plugins_import(self):
        import modules.mobile.plugins
        assert modules.mobile.plugins is not None

    def test_reports_generator_import(self):
        import reports.generator
        assert reports.generator is not None


# ─── Engine ───────────────────────────────────────────────────────────────────
class TestEngine:
    def test_engine_instantiation(self):
        from core.engine import Engine
        engine = Engine(max_workers=2)
        assert engine is not None

    def test_get_engine_singleton(self):
        from core.engine import get_engine
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2

    def test_engine_event_callback(self):
        from core.engine import Engine
        events = []
        engine = Engine(max_workers=1)
        engine.on_event(lambda evt, data: events.append(evt))
        # Just verify callback registration doesn't crash
        assert engine is not None
