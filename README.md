<div align="center">

```
 █████╗  ██╗         ███████╗  █████╗  ███╗     ██╗ ███████╗████████╗
██╔══██╗██║         ██╔════╝ ██╔══██╗████╗   ██║ ██╔════╝╚══██╔══╝
███████║██║         █████╗    ███████║██╔██╗  ██║ █████╗        ██║
██╔══██║██║         ██╔══╝    ██╔══██║██║╚██╗██║ ██╔══╝        ██║
██║   ██║ ███████╗██║         ██║   ██║██║  ╚████║ ███████╗     ██║
╚═╝   ╚═╝╚══════╝╚═╝         ╚═╝    ╚═╝╚═╝    ╚═══╝╚══════╝     ╚═╝
    XiaoYao @ Alfanet · Security Research Operating Framework · 2026
```

[![Release](https://img.shields.io/github/v/release/ADA-XiaoYao/alfanet-srof?style=flat-square&color=00c8ff)](https://github.com/ADA-XiaoYao/alfanet-srof/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/ADA-XiaoYao/alfanet-srof/build.yml?style=flat-square&label=Build+Win%2FmacOS%2FLinux)](https://github.com/ADA-XiaoYao/alfanet-srof/actions/workflows/build.yml)
[![CI](https://img.shields.io/github/actions/workflow/status/ADA-XiaoYao/alfanet-srof/ci.yml?style=flat-square&label=CI)](https://github.com/ADA-XiaoYao/alfanet-srof/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.8%2B-a259ff?style=flat-square)](https://python.org)
[![Tools](https://img.shields.io/badge/Tools-72%2B-ff6b35?style=flat-square)](#工具分类)
[![License](https://img.shields.io/badge/License-MIT-ffb800?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/ADA-XiaoYao/alfanet-srof?style=flat-square&color=ff3a6e)](https://github.com/ADA-XiaoYao/alfanet-srof/stargazers)

**跨平台安全研究框架 · GUI工具箱 + 自动化引擎 · 零依赖**

**Cross-platform Security Research Framework · GUI Toolbox + Automation Engine · Zero deps**

[📦 **Download**](https://github.com/ADA-XiaoYao/alfanet-srof/releases/latest) · [📖 **Wiki**](https://github.com/ADA-XiaoYao/alfanet-srof/wiki) · [🐛 **Issues**](https://github.com/ADA-XiaoYao/alfanet-srof/issues)

</div>

---

## 架构 / Architecture

SROF 把工具箱前端和自动化后端合并在一个仓库：

```
toolbox.py   ←  GUI 前端，72+ 工具，点击启动
    ↕
main.py      ←  统一入口，启动 GUI + 初始化引擎
    ↕
core/        ←  引擎层：插件调度 · SQLite持久化 · 流式输出
    ↕
modules/     ←  插件层：每个工具对应一个 SROFPlugin 实现
    ↕
reports/     ←  报告层：自动生成 Markdown + HTML
```

---

## 快速开始 / Quick Start

### 直接运行

```bash
git clone https://github.com/ADA-XiaoYao/alfanet-srof
cd alfanet-srof
python main.py
```

> 唯一要求：**Python 3.8+**，GUI 用 stdlib tkinter，DB 用 stdlib sqlite3，**零 pip 依赖**。

### 下载预编译版

| 平台 | 文件 | 运行 |
|------|------|------|
| 🪟 Windows | `SROF-Win.exe` | 双击运行 |
| 🍎 macOS | `SROF-macOS.zip` | 解压打开 .app |
| 🐧 Linux | `SROF-Linux` | `chmod +x && ./SROF-Linux` |

👉 [Releases](https://github.com/ADA-XiaoYao/alfanet-srof/releases/latest)

### 自行打包

```bash
pip install pyinstaller
python build/build.py
```

---

## 工具分类 / Tools (72+)

| 分类 | 数量 | 代表工具 |
|------|------|---------|
| 🔍 信息收集 | 14 | Subfinder · Nmap · httpx · Katana · FOFA · EHole |
| 🛡️ 漏洞扫描 | 8  | Nuclei v3 · Xray · Afrog · fscan · Goby |
| 🌐 Web 攻击 | 10 | Burp Suite · Caido · sqlmap · Dalfox · Jawd⭐ |
| 🎯 后渗透·C2 | 10 | Sliver · Havoc · BloodHound · Impacket · ligolo-ng |
| 🔑 密码破解 | 4  | Hashcat · Hydra · John · Pydictor |
| 🏆 CTF 专项 | 12 | pwntools · Ghidra · CyberChef · SageMath · Volatility3 |
| ☁️ 云&容器 | 4  | CDK · cf · pacu · kube-hunter |
| 📱 移动安全 | 4  | jadx · Frida · objection · MobSF |
| 🔥 APT | 6  | Cobalt Strike · Sliver · Empire · Donut |

---

## 插件开发 / Write a Plugin

```python
from core.plugin import SROFPlugin, PluginConfig, Finding, register, PluginCategory

@register
class MyPlugin(SROFPlugin):
    id          = "recon.mytool"
    name        = "My Tool"
    category    = PluginCategory.RECON
    description = "Does something useful"
    tags        = ["custom"]

    def run(self, config: PluginConfig):
        import subprocess
        out = subprocess.check_output(["mytool", "-d", config.target], text=True)
        for line in out.splitlines():
            yield Finding(type="asset", value=line, source=self.id)
```

插件 `@register` 后自动出现在 GUI 工具卡片，引擎自动调度，结果自动入库。

---

## 仓库结构 / Repository

```
alfanet-srof/
├── main.py                    ← 统一入口
├── toolbox.py                 ← GUI（72+ 工具卡片）
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── core/
│   ├── database.py            ← SQLite 数据层
│   ├── plugin.py              ← 插件基类 + 注册中心
│   └── engine.py              ← 调度引擎
│
├── modules/
│   ├── recon/plugins.py       ← 信息收集插件
│   ├── scan/plugins.py        ← 漏洞扫描插件
│   └── .../                   ← exploit / post / ctf / cloud / mobile
│
├── reports/
│   └── generator.py           ← Markdown + HTML 报告
│
├── build/
│   └── build.py               ← 跨平台打包
│
├── docs/                      ← Wiki 文档
└── .github/workflows/
    ├── build.yml              ← 三平台构建 + Release
    └── ci.yml                 ← 语法 + 测试
```

---

## 免责声明 / Disclaimer

本项目仅供**授权渗透测试、CTF竞赛、安全研究**使用。禁止用于未经授权目标。

For authorized penetration testing, CTF, and security research only.

---

<div align="center">

© 2026 **XiaoYao @ Alfanet** · 觉得有用请 ⭐

</div>
