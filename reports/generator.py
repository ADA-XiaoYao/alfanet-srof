"""
SROF · Report Generator
Produces Markdown + HTML pentest reports from DB data.
No external deps (pure stdlib).
"""
import json, html, sys
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

SEV_COLOR = {
    "critical": "#ff3a6e",
    "high":     "#ff6b35",
    "medium":   "#ffb800",
    "low":      "#00c8ff",
    "info":     "#4e7a9e",
}


def generate(workspace_id: int = 1,
             output_dir: Path = Path("./reports"),
             fmt: str = "both") -> dict:
    """
    Generate report for a workspace.
    fmt: 'md' | 'html' | 'both'
    Returns dict of output file paths.
    """
    from core.database import (WorkspaceRepo, TargetRepo,
                                AssetRepo, VulnRepo)

    ws      = WorkspaceRepo.get(workspace_id) or {"name": "default", "id": workspace_id}
    targets = TargetRepo.list_by_workspace(workspace_id)
    vulns   = VulnRepo.list_by_workspace(workspace_id)
    stats   = VulnRepo.stats_by_workspace(workspace_id)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    name  = ws["name"].replace(" ", "_")
    paths = {}

    if fmt in ("md", "both"):
        md_path = output_dir / f"SROF_Report_{name}_{ts}.md"
        md_path.write_text(_markdown(ws, targets, vulns, stats), encoding="utf-8")
        paths["md"] = md_path

    if fmt in ("html", "both"):
        html_path = output_dir / f"SROF_Report_{name}_{ts}.html"
        html_path.write_text(_html_report(ws, targets, vulns, stats), encoding="utf-8")
        paths["html"] = html_path

    return paths


# ── MARKDOWN ─────────────────────────────────────────────────────────────────
def _markdown(ws, targets, vulns, stats) -> str:
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(vulns)
    lines = [
        f"# 渗透测试报告 · SROF",
        f"",
        f"| 字段 | 内容 |",
        f"|------|------|",
        f"| 工作空间 | {ws['name']} |",
        f"| 生成时间 | {now} |",
        f"| 目标数量 | {len(targets)} |",
        f"| 发现漏洞 | {total} |",
        f"| 工具 | ALFANET SROF 2026 · XiaoYao @ Alfanet |",
        f"",
        f"---",
        f"",
        f"## 漏洞统计",
        f"",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt = stats.get(sev, 0)
        bar = "█" * min(cnt, 30)
        lines.append(f"- {SEV_EMOJI[sev]} **{sev.upper()}**: {cnt}  `{bar}`")

    lines += ["", "---", "", "## 目标列表", ""]
    lines.append("| Host | Port | Status | Tags |")
    lines.append("|------|------|--------|------|")
    for t in targets:
        port = str(t.get("port") or "—")
        tags = ", ".join(t.get("tags") or [])
        lines.append(f"| {t['host']} | {port} | {t['status']} | {tags} |")

    lines += ["", "---", "", "## 漏洞详情", ""]

    grouped = {}
    for v in vulns:
        grouped.setdefault(v["severity"], []).append(v)

    for sev in ("critical", "high", "medium", "low", "info"):
        vs = grouped.get(sev, [])
        if not vs:
            continue
        lines.append(f"### {SEV_EMOJI[sev]} {sev.upper()} ({len(vs)})")
        lines.append("")
        for v in vs:
            lines += [
                f"#### {v['name']}",
                f"",
                f"- **目标**: `{v['host']}:{v.get('port') or ''}`",
                f"- **CVE**: {v.get('cve') or '—'}",
                f"- **CVSS**: {v.get('cvss') or '—'}",
                f"- **插件**: `{v['plugin_id']}`",
                f"",
                f"{v.get('description') or '无描述'}",
                f"",
            ]
            ev = v.get("evidence") or {}
            if ev.get("request"):
                lines += [
                    "```http",
                    str(ev["request"])[:800],
                    "```",
                    "",
                ]

    lines += [
        "---",
        "",
        f"*报告由 ALFANET SROF 2026 自动生成 · XiaoYao @ Alfanet*",
        f"*github.com/ADA-XiaoYao*",
    ]
    return "\n".join(lines)


# ── HTML ─────────────────────────────────────────────────────────────────────
def _html_report(ws, targets, vulns, stats) -> str:
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(vulns)

    def e(s): return html.escape(str(s or ""))

    # Stat cards
    stat_cards = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt   = stats.get(sev, 0)
        color = SEV_COLOR[sev]
        stat_cards += f"""
        <div class="stat-card" style="border-top:3px solid {color}">
          <div class="stat-label">{sev.upper()}</div>
          <div class="stat-val" style="color:{color}">{cnt}</div>
        </div>"""

    # Target rows
    target_rows = ""
    for t in targets:
        port = t.get("port") or "—"
        tags = ", ".join(t.get("tags") or [])
        target_rows += f"""
        <tr>
          <td><code>{e(t['host'])}</code></td>
          <td>{e(port)}</td>
          <td><span class="badge">{e(t['status'])}</span></td>
          <td>{e(tags)}</td>
        </tr>"""

    # Vuln cards
    vuln_cards = ""
    for v in vulns:
        sev   = v.get("severity", "info")
        color = SEV_COLOR.get(sev, "#4e7a9e")
        ev    = v.get("evidence") or {}
        req   = e(str(ev.get("request", ""))[:600]) if ev.get("request") else ""
        req_block = f'<pre class="code">{req}</pre>' if req else ""
        cve = v.get("cve") or "—"
        vuln_cards += f"""
        <div class="vuln-card" style="border-left:4px solid {color}">
          <div class="vuln-header">
            <span class="sev-badge" style="background:{color}">{sev.upper()}</span>
            <span class="vuln-name">{e(v['name'])}</span>
            {f'<span class="cve">{e(cve)}</span>' if cve != '—' else ''}
          </div>
          <div class="vuln-meta">
            Target: <code>{e(v.get('host',''))}:{e(v.get('port',''))}</code>
            &nbsp;·&nbsp; Plugin: <code>{e(v['plugin_id'])}</code>
            &nbsp;·&nbsp; CVSS: {e(v.get('cvss') or '—')}
          </div>
          <p class="vuln-desc">{e(v.get('description',''))}</p>
          {req_block}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SROF Report · {e(ws['name'])}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#040710;color:#c2dff5;font-family:'Segoe UI',Ubuntu,sans-serif;
     font-size:14px;line-height:1.7;padding:32px}}
h1{{font-family:monospace;color:#00c8ff;font-size:22px;letter-spacing:4px;margin-bottom:6px}}
h2{{font-family:monospace;color:#00c8ff;font-size:14px;letter-spacing:3px;
     margin:32px 0 12px;padding-bottom:6px;border-bottom:1px solid #1a3050}}
h3{{color:#4e7a9e;font-size:13px;margin:20px 0 8px}}
.meta{{color:#4e7a9e;font-size:12px;font-family:monospace;margin-bottom:28px}}
.meta span{{margin-right:24px}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.stat-card{{background:#0e1f3c;padding:14px 20px;min-width:120px;border-radius:2px}}
.stat-label{{font-family:monospace;font-size:9px;letter-spacing:2px;color:#4e7a9e;margin-bottom:4px}}
.stat-val{{font-family:monospace;font-size:26px;font-weight:900}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:24px}}
th{{background:#0e1f3c;color:#4e7a9e;font-family:monospace;font-size:10px;
     letter-spacing:2px;padding:10px 12px;text-align:left}}
td{{padding:9px 12px;border-bottom:1px solid #0e1f3c;vertical-align:top}}
code{{background:#0c1830;color:#00c8ff;padding:1px 5px;font-size:12px;font-family:monospace}}
.badge{{background:#0e1f3c;color:#4e7a9e;padding:2px 8px;font-size:11px;font-family:monospace}}
.vuln-card{{background:#0e1f3c;padding:16px 18px;margin-bottom:12px;border-radius:2px}}
.vuln-header{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.sev-badge{{font-family:monospace;font-size:9px;letter-spacing:1px;
             padding:2px 7px;color:#040710;font-weight:bold;border-radius:2px}}
.vuln-name{{color:#c2dff5;font-weight:600;font-size:14px}}
.cve{{font-family:monospace;font-size:10px;color:#ffb800;background:#1a1000;
       padding:1px 6px;border-radius:2px}}
.vuln-meta{{font-size:11px;color:#4e7a9e;margin-bottom:6px;font-family:monospace}}
.vuln-desc{{color:#7a9ebb;font-size:13px;margin-bottom:8px}}
.code{{background:#020507;color:#00ff9f;font-family:monospace;font-size:11px;
        padding:10px 14px;overflow-x:auto;white-space:pre-wrap;max-height:200px;
        overflow-y:auto;border:1px solid #0e2a40;margin-top:8px}}
footer{{margin-top:40px;font-family:monospace;font-size:10px;color:#1e3a56;
         border-top:1px solid #0e1f3c;padding-top:14px}}
</style>
</head>
<body>
<h1>▣ PENTEST REPORT · SROF</h1>
<div class="meta">
  <span>Workspace: {e(ws['name'])}</span>
  <span>Generated: {e(now)}</span>
  <span>Targets: {len(targets)}</span>
  <span>Total Findings: {total}</span>
</div>

<h2>// VULNERABILITY SUMMARY</h2>
<div class="stats">{stat_cards}</div>

<h2>// TARGETS</h2>
<table>
  <tr><th>HOST</th><th>PORT</th><th>STATUS</th><th>TAGS</th></tr>
  {target_rows}
</table>

<h2>// VULNERABILITY DETAILS</h2>
{vuln_cards if vuln_cards else '<p style="color:#1e3a56">No vulnerabilities recorded yet.</p>'}

<footer>
  Generated by ALFANET SROF 2026 · XiaoYao @ Alfanet · github.com/ADA-XiaoYao<br>
  ⚠️ 本报告仅供授权安全测试参考，请勿用于非法用途。
</footer>
</body>
</html>"""


if __name__ == "__main__":
    paths = generate(workspace_id=1, fmt="both")
    for fmt, path in paths.items():
        print(f"✓ {fmt.upper()}: {path}")
