# SROF · Architecture

## Component Overview

```
┌─────────────────────────────────────────────────────────┐
│                   toolbox.py  (GUI)                      │
│   72+ tool cards · category tabs · embedded console      │
└────────────────────────┬────────────────────────────────┘
                         │ imports
┌────────────────────────▼────────────────────────────────┐
│                    main.py  (Entry)                      │
│   starts backend thread → launches Toolbox.mainloop()   │
└──────────┬─────────────────────────────┬────────────────┘
           │                             │
┌──────────▼──────────┐    ┌─────────────▼──────────────┐
│   core/engine.py    │    │   core/plugin.py            │
│   ThreadPoolExecutor│◄───│   SROFPlugin (ABC)          │
│   job scheduling    │    │   PluginRegistry            │
│   event callbacks   │    │   Finding / PluginConfig    │
└──────────┬──────────┘    └─────────────────────────────┘
           │
┌──────────▼──────────┐    ┌─────────────────────────────┐
│  core/database.py   │    │   modules/*/plugins.py      │
│  SQLite WAL         │    │   recon / scan / exploit    │
│  WorkspaceRepo      │    │   post / ctf / cloud        │
│  TargetRepo         │    │   mobile                    │
│  AssetRepo          │    └─────────────────────────────┘
│  VulnRepo           │
│  JobRepo            │    ┌─────────────────────────────┐
└─────────────────────┘    │   reports/generator.py      │
                           │   Markdown + HTML reports   │
                           └─────────────────────────────┘
```

## Data Flow

1. User clicks a tool card in `toolbox.py`
2. GUI calls `Engine.run_single(workspace_id, target_id, plugin_id, config)`
3. Engine creates a `scan_job` record, spawns a thread
4. Plugin's `run(config)` generator yields `Finding` objects
5. Engine persists each Finding to DB (`AssetRepo` or `VulnRepo`)
6. Engine emits events → GUI updates live console output
7. User clicks "Generate Report" → `reports/generator.py` reads DB → writes `.md` + `.html`

## Database Schema

```
workspaces ──< targets ──< assets
                       ──< vulnerabilities
           ──< scan_jobs ──< plugin_logs
           ──< attack_chains
```

## Threading Model

- GUI runs on the **main thread** (tkinter requirement)
- `_init_backend()` runs on a **daemon thread** (loads plugins, inits DB)
- Each scan job runs on a **daemon thread** via `Engine`
- Plugin tasks run in a **ThreadPoolExecutor** (default 8 workers)
- Results are passed back to GUI via thread-safe `queue.Queue`
