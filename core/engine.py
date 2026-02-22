"""
SROF · Execution Engine
Schedules plugins, streams findings to DB and UI callbacks.
"""
import threading, queue, time, traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Dict, Any

from .plugin   import SROFPlugin, PluginRegistry, PluginConfig, Finding
from .database import (AssetRepo, VulnRepo, JobRepo, Asset, Vulnerability,
                       TargetRepo)


# ─── EVENTS ──────────────────────────────────────────────────────────────────
class EngineEvent:
    JOB_START    = "job_start"
    JOB_DONE     = "job_done"
    JOB_ERROR    = "job_error"
    FINDING      = "finding"
    PLUGIN_START = "plugin_start"
    PLUGIN_DONE  = "plugin_done"
    LOG          = "log"


# ─── ENGINE ──────────────────────────────────────────────────────────────────
class Engine:
    """
    Runs one or more plugins against a target.
    Streams findings through callbacks (for live UI updates).
    Persists everything to DB.
    """

    def __init__(self, max_workers: int = 8):
        self._max_workers = max_workers
        self._callbacks: List[Callable] = []
        self._active_jobs: Dict[int, threading.Event] = {}
        self._lock = threading.Lock()

    # ── CALLBACK ─────────────────────────────────────────────────────────────
    def on_event(self, cb: Callable):
        """Register a callback: cb(event_type: str, data: dict)"""
        self._callbacks.append(cb)
        return self

    def _emit(self, event_type: str, data: dict):
        for cb in self._callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

    # ── RUN ──────────────────────────────────────────────────────────────────
    def run(self,
            workspace_id: int,
            target_id: int,
            plugin_ids: List[str],
            config: PluginConfig,
            blocking: bool = True) -> int:
        """
        Dispatch a job.
        Returns job_id immediately; if blocking=True waits for completion.
        """
        job_id = JobRepo.create(workspace_id, "mixed",
                                {"plugins": plugin_ids, "target": config.target})
        config.workspace_id = workspace_id
        config.job_id = job_id

        cancel_evt = threading.Event()
        with self._lock:
            self._active_jobs[job_id] = cancel_evt

        def _worker():
            JobRepo.start(job_id)
            self._emit(EngineEvent.JOB_START, {"job_id": job_id, "target": config.target})
            total = 0

            plugins = []
            for pid in plugin_ids:
                cls = PluginRegistry.get(pid)
                if cls is None:
                    self._emit(EngineEvent.LOG, {
                        "job_id": job_id, "level": "warn",
                        "message": f"Plugin not found: {pid}"
                    })
                    continue
                plugins.append(cls())

            with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                futs = {
                    pool.submit(self._run_plugin, p, config, job_id,
                                cancel_evt, target_id): p
                    for p in plugins
                }
                for fut in as_completed(futs):
                    plugin = futs[fut]
                    try:
                        count = fut.result()
                        total += count
                        self._emit(EngineEvent.PLUGIN_DONE,
                                   {"job_id": job_id, "plugin": plugin.id,
                                    "findings": count})
                    except Exception as e:
                        self._emit(EngineEvent.LOG, {
                            "job_id": job_id, "level": "error",
                            "message": f"{plugin.id} crashed: {e}",
                            "traceback": traceback.format_exc()
                        })

            JobRepo.finish(job_id, total)
            self._emit(EngineEvent.JOB_DONE,
                       {"job_id": job_id, "total_findings": total})
            with self._lock:
                self._active_jobs.pop(job_id, None)

        t = threading.Thread(target=_worker, daemon=True, name=f"srof-job-{job_id}")
        t.start()
        if blocking:
            t.join()
        return job_id

    # ── SINGLE PLUGIN ────────────────────────────────────────────────────────
    def _run_plugin(self, plugin: SROFPlugin, config: PluginConfig,
                    job_id: int, cancel_evt: threading.Event,
                    target_id: int) -> int:
        """Run one plugin, persist findings, return count."""
        def _log_cb(plugin_id, msg, level, data):
            JobRepo.log(job_id, plugin_id, msg, level, data)
            self._emit(EngineEvent.LOG,
                       {"job_id": job_id, "plugin": plugin_id,
                        "level": level, "message": msg})

        plugin.set_logger(_log_cb)

        err = plugin.validate_config(config)
        if err:
            plugin.error(f"Config invalid: {err}")
            return 0

        self._emit(EngineEvent.PLUGIN_START,
                   {"job_id": job_id, "plugin": plugin.id})
        count = 0

        try:
            for finding in plugin.run(config):
                if cancel_evt.is_set():
                    plugin.warn("Job cancelled")
                    break

                count += 1
                self._persist_finding(finding, target_id, job_id)
                self._emit(EngineEvent.FINDING,
                           {"job_id": job_id, "plugin": plugin.id,
                            "finding": finding.to_dict()})
        except Exception as e:
            plugin.error(f"Runtime error: {e}")
            raise

        return count

    # ── PERSIST ──────────────────────────────────────────────────────────────
    def _persist_finding(self, f: Finding, target_id: int, job_id: int):
        asset_id = None

        if f.type == "asset":
            a = Asset(
                target_id=target_id,
                type=f.metadata.get("asset_type", "url"),
                value=f.value,
                source=f.source,
                metadata=f.metadata,
            )
            asset_id = AssetRepo.add(a)

        elif f.type == "vuln":
            v = Vulnerability(
                target_id=target_id,
                plugin_id=f.source,
                name=f.title or f.value,
                severity=f.severity,
                description=f.description,
                evidence=f.evidence,
                cve=f.cve,
                cvss=f.cvss,
                asset_id=asset_id,
            )
            VulnRepo.add(v)

    # ── CANCEL ───────────────────────────────────────────────────────────────
    def cancel(self, job_id: int):
        with self._lock:
            evt = self._active_jobs.get(job_id)
            if evt:
                evt.set()
                JobRepo.fail(job_id, "Cancelled by user")

    # ── CONVENIENCE ──────────────────────────────────────────────────────────
    def run_recon(self, workspace_id, target_id, config, blocking=True):
        from .plugin import PluginCategory
        pids = [p.id for p in PluginRegistry.by_category(PluginCategory.RECON)]
        return self.run(workspace_id, target_id, pids, config, blocking)

    def run_scan(self, workspace_id, target_id, config, blocking=True):
        from .plugin import PluginCategory
        pids = [p.id for p in PluginRegistry.by_category(PluginCategory.SCAN)]
        return self.run(workspace_id, target_id, pids, config, blocking)

    def run_single(self, workspace_id, target_id, plugin_id, config, blocking=True):
        return self.run(workspace_id, target_id, [plugin_id], config, blocking)


# ─── SINGLETON ───────────────────────────────────────────────────────────────
_engine: Optional[Engine] = None

def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = Engine()
    return _engine
