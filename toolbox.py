#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║   ALFANET · XiaoYao  TOOLBOX  2026                      ║
║   点击即启动 · 弹窗终端 + 内嵌控制台 双模式              ║
║   Win / macOS / Linux  跨平台                           ║
╚══════════════════════════════════════════════════════════╝
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess, threading, queue, shutil, os, sys
import platform, webbrowser, time
from datetime import datetime

OS   = platform.system()          # Windows | Darwin | Linux
ARCH = platform.machine()

# ── Fonts ────────────────────────────────────────────────
if OS == "Windows":
    F_MONO, F_UI, F_TITLE = "Consolas", "Segoe UI", "Consolas"
    SZ = 10
elif OS == "Darwin":
    F_MONO, F_UI, F_TITLE = "Menlo", "SF Pro Display", "Menlo"
    SZ = 11
else:
    F_MONO, F_UI, F_TITLE = "DejaVu Sans Mono", "Ubuntu", "DejaVu Sans Mono"
    SZ = 10

# ── Palette ──────────────────────────────────────────────
C = {
    "bg0":    "#030912",   # deepest bg
    "bg1":    "#060f1c",   # sidebar
    "bg2":    "#091525",   # panel
    "bg3":    "#0d1e35",   # card
    "bg4":    "#112240",   # hover
    "border": "#14304f",
    "b2":     "#0a4060",
    "acc":    "#00c8ff",   # cyan  - primary
    "acc2":   "#ff3a6e",   # red   - danger/exploit
    "acc3":   "#00ff9f",   # green - ok/recon
    "acc4":   "#a259ff",   # purple- post/c2
    "acc5":   "#ffb800",   # amber - crack/ctf
    "acc6":   "#ff6b35",   # orange- scan
    "acc7":   "#f48fb1",   # pink  - mobile
    "acc8":   "#4dd0e1",   # teal  - cloud
    "txt":    "#cce4f7",
    "txt2":   "#4d7a9e",
    "txt3":   "#1c3a58",
    "ok":     "#00ff9f",
    "err":    "#ff3a6e",
    "warn":   "#ffb800",
}

# ══════════════════════════════════════════════════════════
#  TOOL DATABASE
# ══════════════════════════════════════════════════════════
TOOLS = {

"🔍 信息收集": [
  {"name":"Subfinder",    "color":C["acc3"], "badge":"FREE",
   "desc":"被动子域枚举 · 50+数据源",
   "tags":["子域名","被动","OSINT"],
   "cmd":"subfinder -d {target} -silent",
   "install":"go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
   "url":"https://github.com/projectdiscovery/subfinder"},

  {"name":"Amass",        "color":C["acc3"], "badge":"FREE",
   "desc":"OWASP子域枚举 · 主动+被动",
   "tags":["子域名","OWASP","ASN"],
   "cmd":"amass enum -d {target} -passive",
   "install":"go install github.com/owasp-amass/amass/v4/...@master",
   "url":"https://github.com/owasp-amass/amass"},

  {"name":"OneForAll",    "color":C["acc3"], "badge":"FREE",
   "desc":"国产子域神器 · 接管检测",
   "tags":["子域名","国产","接管"],
   "cmd":"python3 oneforall.py --target {target} run",
   "install":"git clone https://github.com/shmilylty/OneForAll",
   "url":"https://github.com/shmilylty/OneForAll"},

  {"name":"Nmap",         "color":C["acc"],  "badge":"FREE",
   "desc":"端口扫描之王 · 服务识别 · NSE",
   "tags":["端口","服务","NSE"],
   "cmd":"nmap -sV -sC --min-rate 5000 -p- {target}",
   "install":"https://nmap.org/download.html",
   "url":"https://nmap.org"},

  {"name":"Masscan",      "color":C["acc"],  "badge":"FREE",
   "desc":"全球最快端口扫描 · 百万pps",
   "tags":["端口","C段","超快"],
   "cmd":"masscan {target} -p1-65535 --rate=10000",
   "install":"apt install masscan",
   "url":"https://github.com/robertdavidgraham/masscan"},

  {"name":"RustScan",     "color":C["acc"],  "badge":"FREE",
   "desc":"Rust编写超快端口扫描 · 自动调用Nmap",
   "tags":["端口","Rust","快速"],
   "cmd":"rustscan -a {target} -- -sV -sC",
   "install":"https://github.com/RustScan/RustScan/releases",
   "url":"https://github.com/RustScan/RustScan"},

  {"name":"httpx",        "color":C["acc3"], "badge":"FREE",
   "desc":"HTTP探测 · 技术栈 · CDN识别",
   "tags":["指纹","HTTP","CDN"],
   "cmd":"httpx -u {target} -title -tech-detect -status-code -cdn",
   "install":"go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
   "url":"https://github.com/projectdiscovery/httpx"},

  {"name":"EHole 棱洞",   "color":C["acc3"], "badge":"FREE",
   "desc":"国产指纹识别 · 国内框架全覆盖",
   "tags":["指纹","国产","OA"],
   "cmd":"ehole finger -l {input}",
   "install":"https://github.com/EdgeSecurityTeam/EHole/releases",
   "url":"https://github.com/EdgeSecurityTeam/EHole"},

  {"name":"Katana",       "color":C["acc3"], "badge":"FREE ★2026",
   "desc":"新一代爬虫 · JS渲染 · 端点发现",
   "tags":["爬虫","JS","端点"],
   "cmd":"katana -u {target} -d 3 -jc -ef png,jpg,gif,css",
   "install":"go install github.com/projectdiscovery/katana/cmd/katana@latest",
   "url":"https://github.com/projectdiscovery/katana"},

  {"name":"ffuf",         "color":C["acc4"], "badge":"FREE",
   "desc":"最快Web模糊测试 · 目录/参数/VHost",
   "tags":["目录","Fuzz","参数"],
   "cmd":"ffuf -u {target}/FUZZ -w wordlist.txt -mc 200,301,302,403",
   "install":"go install github.com/ffuf/ffuf/v2@latest",
   "url":"https://github.com/ffuf/ffuf"},

  {"name":"dirsearch",    "color":C["acc4"], "badge":"FREE",
   "desc":"目录扫描 · 内置字典 · 新手友好",
   "tags":["目录","Python"],
   "cmd":"python3 dirsearch.py -u {target} -e php,asp,aspx,jsp",
   "install":"git clone https://github.com/maurosoria/dirsearch",
   "url":"https://github.com/maurosoria/dirsearch"},

  {"name":"truffleHog",   "color":C["acc2"], "badge":"FREE",
   "desc":"Git密钥泄露扫描 · 700+规则",
   "tags":["泄露","AK","Git"],
   "cmd":"trufflehog git {target} --only-verified",
   "install":"go install github.com/trufflesecurity/trufflehog/v3@latest",
   "url":"https://github.com/trufflesecurity/trufflehog"},

  {"name":"FOFA CLI",     "color":C["acc5"], "badge":"FREE",
   "desc":"网络空间测绘 · FOFA命令行",
   "tags":["FOFA","空间测绘","资产"],
   "cmd":'fofa-cli search -q \'title="{target}"\' -size 100',
   "install":"https://github.com/FofaInfo/Awesome-FOFA",
   "url":"https://github.com/FofaInfo/Awesome-FOFA"},

  {"name":"dnsx",         "color":C["acc3"], "badge":"FREE",
   "desc":"高速DNS解析 · 多记录类型 · 泛解析过滤",
   "tags":["DNS","解析","高速"],
   "cmd":"dnsx -l subdomains.txt -a -resp",
   "install":"go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
   "url":"https://github.com/projectdiscovery/dnsx"},
],

"🛡️ 漏洞扫描": [
  {"name":"Nuclei v3",    "color":C["acc3"], "badge":"FREE ★必装",
   "desc":"9000+模板 · 多协议 · OOB · 2026最强",
   "tags":["POC","模板","OAST"],
   "cmd":"nuclei -u {target} -severity critical,high -o nuclei_out.txt",
   "install":"go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
   "url":"https://github.com/projectdiscovery/nuclei"},

  {"name":"Xray",         "color":C["acc3"], "badge":"FREE",
   "desc":"长亭被动扫描 · OWASP Top10全覆盖",
   "tags":["被动","长亭","OWASP"],
   "cmd":"xray webscan --basic-crawler {target} --html-output xray.html",
   "install":"https://github.com/chaitin/xray/releases",
   "url":"https://github.com/chaitin/xray"},

  {"name":"Afrog",        "color":C["acc3"], "badge":"FREE",
   "desc":"高性能国产漏洞扫描 · 规则持续更新",
   "tags":["漏扫","国产","高性能"],
   "cmd":"afrog -t {target} -o afrog.html",
   "install":"https://github.com/zan8in/afrog/releases",
   "url":"https://github.com/zan8in/afrog"},

  {"name":"fscan",        "color":C["acc6"], "badge":"FREE ★护网",
   "desc":"内网综合扫描 · 弱口令 · PoC · 护网必备",
   "tags":["内网","弱口令","护网"],
   "cmd":"fscan -h {target} -o fscan_out.txt",
   "install":"https://github.com/shadow1ng/fscan/releases",
   "url":"https://github.com/shadow1ng/fscan"},

  {"name":"Goby",         "color":C["acc6"], "badge":"FREE+",
   "desc":"攻击面测绘 · PoC验证 · GUI操作",
   "tags":["攻击面","PoC","GUI"],
   "cmd":"goby",
   "install":"https://gobysec.net",
   "url":"https://gobysec.net"},

  {"name":"ARL 资产灯",   "color":C["acc"],  "badge":"FREE",
   "desc":"子域+端口+漏洞全流程自动化",
   "tags":["资产","自动化","SRC"],
   "cmd":"docker-compose up -d",
   "install":"https://github.com/TophantTechnology/ARL",
   "url":"https://github.com/TophantTechnology/ARL"},

  {"name":"Nikto",        "color":C["acc3"], "badge":"FREE",
   "desc":"Web服务器扫描 · 危险文件 · 配置",
   "tags":["Web","配置","经典"],
   "cmd":"nikto -h {target}",
   "install":"apt install nikto",
   "url":"https://github.com/sullo/nikto"},

  {"name":"Poc-bomber",   "color":C["acc2"], "badge":"FREE",
   "desc":"批量PoC检测 · 插件丰富 · 护网批打",
   "tags":["批量","PoC","护网"],
   "cmd":"python3 poc_bomber.py -u {target}",
   "install":"https://github.com/tr0uble-mAker/POC-bomber",
   "url":"https://github.com/tr0uble-mAker/POC-bomber"},
],

"🌐 Web攻击": [
  {"name":"Burp Suite Pro","color":C["acc6"], "badge":"PAID ★必装",
   "desc":"Web安全测试之王 · 拦截改包 · 扫描",
   "tags":["代理","拦截","扫描"],
   "cmd":"java -jar burpsuite_pro.jar",
   "install":"https://portswigger.net/burp/releases",
   "url":"https://portswigger.net/burp"},

  {"name":"Caido",        "color":C["acc6"], "badge":"FREE ★2026",
   "desc":"Rust现代代理 · 2026 Burp最强竞品",
   "tags":["代理","Rust","现代"],
   "cmd":"caido",
   "install":"https://caido.io/download",
   "url":"https://caido.io"},

  {"name":"Yakit",        "color":C["acc4"], "badge":"FREE",
   "desc":"国产集成平台 · Yak语言 · 持续更新",
   "tags":["集成","国产","Yak"],
   "cmd":"yakit",
   "install":"https://github.com/yaklang/yakit/releases",
   "url":"https://github.com/yaklang/yakit"},

  {"name":"sqlmap",       "color":C["acc2"], "badge":"FREE ★必装",
   "desc":"SQL注入神器 · 全数据库 · tamper绕WAF",
   "tags":["SQLi","WAF绕过","全库"],
   "cmd":'sqlmap -u "{target}" --dbs --level 3 --risk 3 --batch',
   "install":"git clone https://github.com/sqlmapproject/sqlmap",
   "url":"https://github.com/sqlmapproject/sqlmap"},

  {"name":"Dalfox",       "color":C["acc2"], "badge":"FREE",
   "desc":"最强XSS扫描 · DOM/Reflect/Stored",
   "tags":["XSS","DOM","WAF"],
   "cmd":"dalfox url {target}",
   "install":"go install github.com/hahwul/dalfox/v2@latest",
   "url":"https://github.com/hahwul/dalfox"},

  {"name":"Interactsh",   "color":C["acc3"], "badge":"FREE",
   "desc":"OOB回显检测 · SSRF/XXE/Log4Shell",
   "tags":["SSRF","OOB","DNS回显"],
   "cmd":"interactsh-client -v",
   "install":"go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
   "url":"https://github.com/projectdiscovery/interactsh"},

  {"name":"tplmap",       "color":C["acc2"], "badge":"FREE",
   "desc":"SSTI检测利用 · 多引擎 · RCE",
   "tags":["SSTI","模板注入","RCE"],
   "cmd":"python3 tplmap.py -u {target}",
   "install":"git clone https://github.com/epinna/tplmap",
   "url":"https://github.com/epinna/tplmap"},

  {"name":"Jawd ⭐",       "color":C["acc6"], "badge":"FREE ★推荐",
   "desc":"Alphabug师傅 · 一键Jar反编译重打包",
   "tags":["Jar","反编译","Java"],
   "cmd":"java -jar Jawd.jar",
   "install":"https://github.com/AlphabugX/Jawd  (推荐Java8)",
   "url":"https://github.com/AlphabugX/Jawd"},

  {"name":"ysoserial",    "color":C["acc2"], "badge":"FREE",
   "desc":"Java反序列化Payload生成",
   "tags":["反序列化","Java","Payload"],
   "cmd":"java -jar ysoserial.jar CommonsCollections6 'id'",
   "install":"https://github.com/frohoff/ysoserial/releases",
   "url":"https://github.com/frohoff/ysoserial"},

  {"name":"Metasploit",   "color":C["acc2"], "badge":"FREE ★必装",
   "desc":"渗透框架之王 · 2000+模块 · Meterpreter",
   "tags":["利用","2000+","Meterpreter"],
   "cmd":"msfconsole",
   "install":"https://github.com/rapid7/metasploit-framework",
   "url":"https://github.com/rapid7/metasploit-framework"},
],

"🎯 后渗透·C2": [
  {"name":"Sliver C2",    "color":C["acc4"], "badge":"FREE ★2026",
   "desc":"2026开源C2首选 · mTLS/WireGuard · 强免杀",
   "tags":["C2","免杀","开源"],
   "cmd":"sliver-client",
   "install":"https://github.com/BishopFox/sliver/releases",
   "url":"https://github.com/BishopFox/sliver"},

  {"name":"Havoc C2",     "color":C["acc4"], "badge":"FREE",
   "desc":"现代C2 · 强免杀 · Teamserver协作",
   "tags":["C2","免杀","协作"],
   "cmd":"havoc teamserver start --profile ./profiles/default.yaotl",
   "install":"https://github.com/HavocFramework/Havoc/releases",
   "url":"https://github.com/HavocFramework/Havoc"},

  {"name":"Cobalt Strike", "color":C["acc5"],"badge":"PAID",
   "desc":"商业红队标准 · 功能最成熟",
   "tags":["C2","商业","红队"],
   "cmd":"./cobaltstrike",
   "install":"https://www.cobaltstrike.com",
   "url":"https://www.cobaltstrike.com"},

  {"name":"BloodHound",   "color":C["acc6"], "badge":"FREE ★必装",
   "desc":"AD域攻击路径可视化 · 找最短提权路线",
   "tags":["AD","域","路径分析"],
   "cmd":"bloodhound",
   "install":"https://github.com/BloodHoundAD/BloodHound/releases",
   "url":"https://github.com/BloodHoundAD/BloodHound"},

  {"name":"Impacket",     "color":C["acc2"], "badge":"FREE",
   "desc":"内网协议瑞士军刀 · psexec/wmiexec/域攻击",
   "tags":["内网","域","协议"],
   "cmd":"impacket-psexec domain/user:pass@{target}",
   "install":"pip install impacket",
   "url":"https://github.com/fortra/impacket"},

  {"name":"mimikatz",     "color":C["acc2"], "badge":"FREE",
   "desc":"Windows密码提取 · Lsass · 域Hash",
   "tags":["密码","Lsass","Windows"],
   "cmd":"mimikatz.exe",
   "install":"https://github.com/gentilkiwi/mimikatz/releases",
   "url":"https://github.com/gentilkiwi/mimikatz"},

  {"name":"CrackMapExec", "color":C["acc2"], "badge":"FREE",
   "desc":"内网批量爆破/命令执行 · SMB/WinRM",
   "tags":["内网","SMB","批量"],
   "cmd":"cme smb {target} -u user.txt -p pass.txt",
   "install":"pip install crackmapexec",
   "url":"https://github.com/byt3bl33d3r/CrackMapExec"},

  {"name":"ligolo-ng",    "color":C["acc"],  "badge":"FREE ★2026",
   "desc":"现代内网穿透 · TUN路由 · 无需proxychains",
   "tags":["穿透","TUN","隧道"],
   "cmd":"ligolo-ng -selfcert -listen 0.0.0.0:11601",
   "install":"https://github.com/nicocha30/ligolo-ng/releases",
   "url":"https://github.com/nicocha30/ligolo-ng"},

  {"name":"frp",          "color":C["acc"],  "badge":"FREE",
   "desc":"老牌内网穿透 · TCP/UDP/HTTP多协议",
   "tags":["穿透","反向代理","Go"],
   "cmd":"frpc -c frpc.ini",
   "install":"https://github.com/fatedier/frp/releases",
   "url":"https://github.com/fatedier/frp"},

  {"name":"nps",          "color":C["acc"],  "badge":"FREE",
   "desc":"国产内网穿透 · Web管理面板",
   "tags":["穿透","国产","WebUI"],
   "cmd":"npc -server={target} -vkey=xxx -type=tcp",
   "install":"https://github.com/ehang-io/nps/releases",
   "url":"https://github.com/ehang-io/nps"},
],

"🔑 密码破解": [
  {"name":"Hashcat",      "color":C["acc5"], "badge":"FREE ★必装",
   "desc":"GPU Hash破解之王 · 300+类型",
   "tags":["Hash","GPU","破解"],
   "cmd":"hashcat -a 0 -m 0 hash.txt rockyou.txt --force",
   "install":"https://hashcat.net/hashcat",
   "url":"https://hashcat.net"},

  {"name":"John the Ripper","color":C["acc5"],"badge":"FREE",
   "desc":"CPU密码破解 · 多格式",
   "tags":["Hash","CPU","多格式"],
   "cmd":"john hash.txt --wordlist=rockyou.txt",
   "install":"apt install john",
   "url":"https://github.com/openwall/john"},

  {"name":"Hydra",        "color":C["acc5"], "badge":"FREE",
   "desc":"在线爆破 · 50+协议 · SSH/FTP/RDP",
   "tags":["爆破","协议","在线"],
   "cmd":"hydra -l admin -P rockyou.txt {target} ssh",
   "install":"apt install hydra",
   "url":"https://github.com/vanhauser-thc/thc-hydra"},

  {"name":"Pydictor",     "color":C["acc5"], "badge":"FREE",
   "desc":"智能字典生成 · 社工定制",
   "tags":["字典","社工","生成"],
   "cmd":"python3 pydictor.py -extend {target}",
   "install":"git clone https://github.com/LandGrey/pydictor",
   "url":"https://github.com/LandGrey/pydictor"},
],

"🏆 CTF专项": [
  {"name":"pwntools",     "color":C["acc"],  "badge":"FREE ★必装",
   "desc":"Pwn必备框架 · ROP · shellcode",
   "tags":["Pwn","ROP","shellcode"],
   "cmd":"python3 -c 'from pwn import *; context.arch=\"amd64\"'",
   "install":"pip install pwntools",
   "url":"https://github.com/Gallopsled/pwntools"},

  {"name":"pwndbg",       "color":C["acc"],  "badge":"FREE ★必装",
   "desc":"GDB增强 · heap可视化 · Pwn调试",
   "tags":["Pwn","GDB","heap"],
   "cmd":"gdb ./target",
   "install":"git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh",
   "url":"https://github.com/pwndbg/pwndbg"},

  {"name":"ROPgadget",    "color":C["acc"],  "badge":"FREE",
   "desc":"ROP链搜索 · 从二进制提取gadget",
   "tags":["Pwn","ROP","gadget"],
   "cmd":"ROPgadget --binary {binary} --rop",
   "install":"pip install ROPgadget",
   "url":"https://github.com/JonathanSalwan/ROPgadget"},

  {"name":"Ghidra",       "color":C["acc4"], "badge":"FREE ★必装",
   "desc":"NSA逆向神器 · 媲美IDA · 免费",
   "tags":["Reverse","反编译","NSA"],
   "cmd":"ghidraRun",
   "install":"https://ghidra-sre.org",
   "url":"https://ghidra-sre.org"},

  {"name":"IDA Pro",      "color":C["acc4"], "badge":"PAID",
   "desc":"工业级逆向 · 调试器 · 插件生态",
   "tags":["Reverse","调试","工业级"],
   "cmd":"ida64",
   "install":"https://hex-rays.com/ida-pro",
   "url":"https://hex-rays.com"},

  {"name":"x64dbg",       "color":C["acc4"], "badge":"FREE",
   "desc":"Windows动态调试 · 反混淆 · 插件丰富",
   "tags":["Reverse","调试","Windows"],
   "cmd":"x64dbg.exe",
   "install":"https://x64dbg.com",
   "url":"https://x64dbg.com"},

  {"name":"CyberChef",    "color":C["acc5"], "badge":"FREE ★必装",
   "desc":"密码学瑞士军刀 · 400+运算",
   "tags":["Crypto","Misc","400+"],
   "cmd":"open https://gchq.github.io/CyberChef" if OS=="Darwin" else ("start https://gchq.github.io/CyberChef" if OS=="Windows" else "xdg-open https://gchq.github.io/CyberChef"),
   "install":"浏览器访问，无需安装",
   "url":"https://gchq.github.io/CyberChef"},

  {"name":"SageMath",     "color":C["acc5"], "badge":"FREE",
   "desc":"数学计算 · RSA/ECC攻击必备",
   "tags":["Crypto","RSA","ECC"],
   "cmd":"sage",
   "install":"https://www.sagemath.org/download.html",
   "url":"https://www.sagemath.org"},

  {"name":"RsaCtfTool",   "color":C["acc5"], "badge":"FREE",
   "desc":"RSA攻击自动化 · 30+攻击方式",
   "tags":["Crypto","RSA","自动"],
   "cmd":"python3 RsaCtfTool.py --publickey key.pub --uncipherfile enc",
   "install":"git clone https://github.com/RsaCtfTool/RsaCtfTool",
   "url":"https://github.com/RsaCtfTool/RsaCtfTool"},

  {"name":"Binwalk",      "color":C["acc3"], "badge":"FREE",
   "desc":"固件/隐写分析 · 文件提取 · CTF Misc",
   "tags":["Misc","隐写","固件"],
   "cmd":"binwalk -e {file}",
   "install":"pip install binwalk",
   "url":"https://github.com/ReFirmLabs/binwalk"},

  {"name":"Volatility3",  "color":C["acc3"], "badge":"FREE",
   "desc":"内存取证 · 进程/密码提取",
   "tags":["Misc","取证","内存"],
   "cmd":"python3 vol.py -f memory.dmp windows.pslist",
   "install":"pip install volatility3",
   "url":"https://github.com/volatilityfoundation/volatility3"},

  {"name":"Wireshark",    "color":C["acc"],  "badge":"FREE ★必装",
   "desc":"流量分析王者 · 协议解析 · CTF流量题",
   "tags":["流量","协议","分析"],
   "cmd":"wireshark",
   "install":"https://www.wireshark.org/download.html",
   "url":"https://www.wireshark.org"},
],

"☁️ 云&容器": [
  {"name":"CDK",          "color":C["acc8"], "badge":"FREE ★必装",
   "desc":"容器渗透 · Docker/K8s逃逸",
   "tags":["容器","K8s","逃逸"],
   "cmd":"cdk evaluate --full",
   "install":"https://github.com/cdk-team/CDK/releases",
   "url":"https://github.com/cdk-team/CDK"},

  {"name":"cf 云框架",    "color":C["acc8"], "badge":"FREE ★国产",
   "desc":"AK/SK泄露利用 · 阿里/腾讯/AWS",
   "tags":["AK","云横向","多云"],
   "cmd":"cf alicloud ls",
   "install":"https://github.com/teamssix/cf/releases",
   "url":"https://github.com/teamssix/cf"},

  {"name":"pacu",         "color":C["acc8"], "badge":"FREE",
   "desc":"AWS专项渗透 · 权限枚举+利用",
   "tags":["AWS","权限","云"],
   "cmd":"python3 cli.py",
   "install":"pip install pacu",
   "url":"https://github.com/RhinoSecurityLabs/pacu"},

  {"name":"kube-hunter",  "color":C["acc8"], "badge":"FREE",
   "desc":"K8s集群安全测试 · 自动发现错配",
   "tags":["K8s","集群","错配"],
   "cmd":"python3 kube_hunter.py --remote {target}",
   "install":"pip install kube-hunter",
   "url":"https://github.com/aquasecurity/kube-hunter"},
],

"📱 移动安全": [
  {"name":"jadx",         "color":C["acc7"], "badge":"FREE ★必装",
   "desc":"APK反编译神器 · GUI+CLI",
   "tags":["APK","反编译","Java"],
   "cmd":"jadx-gui",
   "install":"https://github.com/skylot/jadx/releases",
   "url":"https://github.com/skylot/jadx"},

  {"name":"Frida",        "color":C["acc7"], "badge":"FREE ★必装",
   "desc":"动态插桩 · Hook · SSL Pinning绕过",
   "tags":["Hook","插桩","SSL"],
   "cmd":"frida -U -l hook.js {package}",
   "install":"pip install frida-tools",
   "url":"https://frida.re"},

  {"name":"objection",    "color":C["acc7"], "badge":"FREE",
   "desc":"Frida封装 · 一键绕过SSL/Root",
   "tags":["Frida","SSL","Root"],
   "cmd":"objection -g {package} explore",
   "install":"pip install objection",
   "url":"https://github.com/sensepost/objection"},

  {"name":"MobSF",        "color":C["acc7"], "badge":"FREE",
   "desc":"移动安全一体化平台 · 静态+动态",
   "tags":["静态","动态","一体化"],
   "cmd":"docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf",
   "install":"pip install mobsf",
   "url":"https://github.com/MobSF/Mobile-Security-Framework-MobSF"},
],

"🔥 APT 高级威胁": [
  {"name":"Cobalt Strike", "color":C["acc2"],"badge":"PAID ★APT",
   "desc":"APT模拟标配 · Malleable C2 · 完整攻击链",
   "tags":["APT","C2","商业"],
   "cmd":"./cobaltstrike",
   "install":"https://www.cobaltstrike.com",
   "url":"https://www.cobaltstrike.com"},

  {"name":"Sliver C2",    "color":C["acc4"], "badge":"FREE ★APT",
   "desc":"开源APT级C2 · mTLS · WireGuard · HTTP3",
   "tags":["APT","C2","免杀"],
   "cmd":"sliver-client",
   "install":"https://github.com/BishopFox/sliver/releases",
   "url":"https://github.com/BishopFox/sliver"},

  {"name":"Empire",       "color":C["acc2"], "badge":"FREE",
   "desc":"PowerShell/Python C2 · 模块丰富",
   "tags":["APT","PowerShell","后渗透"],
   "cmd":"python3 empire",
   "install":"https://github.com/BC-SECURITY/Empire",
   "url":"https://github.com/BC-SECURITY/Empire"},

  {"name":"Donut",        "color":C["acc2"], "badge":"FREE",
   "desc":"Shellcode生成 · 内存执行 · 免杀必备",
   "tags":["免杀","Shellcode","内存"],
   "cmd":"donut -f {binary} -o shellcode.bin",
   "install":"https://github.com/TheWover/donut/releases",
   "url":"https://github.com/TheWover/donut"},

  {"name":"Veil Framework","color":C["acc2"],"badge":"FREE",
   "desc":"免杀Payload生成 · 多语言输出",
   "tags":["免杀","Payload","多语言"],
   "cmd":"python3 Veil.py",
   "install":"https://github.com/Veil-Framework/Veil",
   "url":"https://github.com/Veil-Framework/Veil"},

  {"name":"PsExec",       "color":C["acc2"], "badge":"FREE",
   "desc":"横向移动经典工具 · 远程命令执行",
   "tags":["横向","SMB","命令执行"],
   "cmd":"psexec \\\\{target} -u admin -p pass cmd",
   "install":"https://learn.microsoft.com/sysinternals",
   "url":"https://learn.microsoft.com/sysinternals"},
],
}

# ══════════════════════════════════════════════════════════
#  LAUNCH ENGINE
# ══════════════════════════════════════════════════════════
def _launch_in_new_terminal(cmd: str) -> bool:
    """Open a brand-new terminal window and run the command."""
    try:
        if OS == "Windows":
            subprocess.Popen(["cmd.exe", "/c", f"start cmd.exe /k {cmd}"],
                             creationflags=subprocess.CREATE_NEW_CONSOLE)
        elif OS == "Darwin":
            script = f'tell application "Terminal" to do script "{cmd}"'
            subprocess.Popen(["osascript", "-e", script])
        else:
            launched = False
            for term, args in [
                ("gnome-terminal", ["--", "bash", "-c", f"{cmd}; exec bash"]),
                ("xfce4-terminal", ["-e", f"bash -c '{cmd}; exec bash'"]),
                ("konsole",        ["--noclose", "-e", "bash", "-c", cmd]),
                ("xterm",          ["-e", f"bash -c '{cmd}; exec bash'"]),
            ]:
                if shutil.which(term):
                    subprocess.Popen([term] + args)
                    launched = True
                    break
            if not launched:
                return False
        return True
    except Exception:
        return False


def _run_embedded(cmd: str, output_cb, done_cb):
    """Run command and stream output to callback."""
    def _worker():
        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in proc.stdout:
                output_cb(line.rstrip())
            proc.wait()
            done_cb(proc.returncode)
        except Exception as e:
            output_cb(f"Error: {e}")
            done_cb(-1)
    threading.Thread(target=_worker, daemon=True).start()


# ══════════════════════════════════════════════════════════
#  MAIN APP
# ══════════════════════════════════════════════════════════
class Toolbox(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ALFANET · XiaoYao Toolbox 2026")
        self.geometry("1380x880")
        self.minsize(1100, 700)
        self.configure(bg=C["bg0"])

        self._cur_cat   = list(TOOLS.keys())[0]
        self._cat_btns  = {}
        self._cards     = []
        self._target    = tk.StringVar(value="https://target.com")
        self._search    = tk.StringVar()
        self._log_q     = queue.Queue()
        self._proc_cnt  = 0

        ttk.Style(self).configure(
            "Vertical.TScrollbar",
            background=C["bg2"], troughcolor=C["bg1"],
            arrowcolor=C["txt2"], borderwidth=0,
        )

        self._build()
        self._clock_tick()
        self._poll()

    # ──────────────────────────────────────────────────────
    #  BUILD
    # ──────────────────────────────────────────────────────
    def _build(self):
        self._build_topbar()
        self._build_nav()
        self._build_body()

    # ── TOP BAR ───────────────────────────────────────────
    def _build_topbar(self):
        bar = tk.Frame(self, bg=C["bg1"], height=54)
        bar.pack(fill=tk.X)
        bar.pack_propagate(False)

        # Logo
        tk.Label(bar, text="▣", fg=C["acc"], bg=C["bg1"],
                 font=(F_TITLE, 18, "bold")).pack(side=tk.LEFT, padx=(16, 4), pady=10)
        lf = tk.Frame(bar, bg=C["bg1"])
        lf.pack(side=tk.LEFT, pady=8)
        tk.Label(lf, text="ALFANET · XiaoYao Toolbox",
                 fg=C["txt"], bg=C["bg1"],
                 font=(F_TITLE, 13, "bold")).pack(anchor="w")
        tk.Label(lf, text="2026  ·  Win / macOS / Linux",
                 fg=C["txt2"], bg=C["bg1"],
                 font=(F_MONO, 7)).pack(anchor="w")

        # Target input (shared)
        tf = tk.Frame(bar, bg=C["bg1"])
        tf.pack(side=tk.LEFT, padx=30, fill=tk.Y, pady=10)
        tk.Label(tf, text="TARGET", fg=C["acc"], bg=C["bg1"],
                 font=(F_MONO, 7)).pack(anchor="w")
        te = tk.Entry(tf, textvariable=self._target,
                      bg=C["bg3"], fg=C["txt"],
                      insertbackground=C["acc"],
                      font=(F_MONO, 10), relief=tk.FLAT, bd=0,
                      width=36)
        te.pack(ipady=5, pady=(2, 0))

        # Search
        sf = tk.Frame(bar, bg=C["bg1"])
        sf.pack(side=tk.LEFT, fill=tk.Y, pady=10)
        tk.Label(sf, text="SEARCH", fg=C["acc"], bg=C["bg1"],
                 font=(F_MONO, 7)).pack(anchor="w")
        se = tk.Entry(sf, textvariable=self._search,
                      bg=C["bg3"], fg=C["txt"],
                      insertbackground=C["acc"],
                      font=(F_MONO, 10), relief=tk.FLAT, bd=0,
                      width=20)
        se.pack(ipady=5, pady=(2, 0))
        self._search.trace("w", lambda *_: self._filter())

        # Right: clock + platform
        rf = tk.Frame(bar, bg=C["bg1"])
        rf.pack(side=tk.RIGHT, padx=16, fill=tk.Y, pady=8)
        self._clk_lbl = tk.Label(rf, text="", fg=C["txt2"], bg=C["bg1"],
                                  font=(F_MONO, 9))
        self._clk_lbl.pack(anchor="e")
        tk.Label(rf, text=f"{OS}  {ARCH}",
                 fg=C["txt3"], bg=C["bg1"],
                 font=(F_MONO, 7)).pack(anchor="e")

        tk.Frame(self, bg=C["b2"], height=1).pack(fill=tk.X)

    # ── NAV ───────────────────────────────────────────────
    def _build_nav(self):
        nav = tk.Frame(self, bg=C["bg1"])
        nav.pack(fill=tk.X)

        for cat in TOOLS:
            b = tk.Button(nav, text=cat,
                          fg=C["txt2"], bg=C["bg1"],
                          activeforeground=C["acc"],
                          activebackground=C["bg2"],
                          font=(F_UI, SZ, "bold"),
                          relief=tk.FLAT, bd=0,
                          padx=14, pady=9,
                          cursor="hand2",
                          command=lambda c=cat: self._select(c))
            b.pack(side=tk.LEFT)
            self._cat_btns[cat] = b

        # Extra buttons right
        for label, cmd in [
            ("📦 武器库",  self._show_resources),
            ("🔄 流程图",  self._show_flow),
            ("⚙️  关于",   self._show_about),
        ]:
            tk.Button(nav, text=label,
                      fg=C["txt2"], bg=C["bg1"],
                      activeforeground=C["acc5"],
                      activebackground=C["bg2"],
                      font=(F_UI, SZ),
                      relief=tk.FLAT, bd=0,
                      padx=10, pady=9,
                      cursor="hand2",
                      command=cmd).pack(side=tk.RIGHT)

        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X)

    # ── BODY ──────────────────────────────────────────────
    def _build_body(self):
        body = tk.Frame(self, bg=C["bg0"])
        body.pack(fill=tk.BOTH, expand=True)

        # Cards pane
        cards_outer = tk.Frame(body, bg=C["bg0"])
        cards_outer.pack(fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(cards_outer, bg=C["bg0"],
                                  highlightthickness=0)
        sb = ttk.Scrollbar(cards_outer, orient=tk.VERTICAL,
                            command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas.pack(fill=tk.BOTH, expand=True)

        self._inner = tk.Frame(self._canvas, bg=C["bg0"])
        self._cwin  = self._canvas.create_window(
            (0, 0), window=self._inner, anchor="nw")

        self._inner.bind("<Configure>",
            lambda e: self._canvas.configure(
                scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>",
            lambda e: self._canvas.itemconfig(self._cwin, width=e.width))
        for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._canvas.bind_all(ev, self._scroll)

        # Console
        tk.Frame(body, bg=C["b2"], height=1).pack(fill=tk.X)
        self._build_console(body)

        # First category
        self._select(self._cur_cat)

    # ── CONSOLE ───────────────────────────────────────────
    def _build_console(self, parent):
        cf = tk.Frame(parent, bg=C["bg1"])
        cf.pack(fill=tk.X)

        hdr = tk.Frame(cf, bg=C["bg1"])
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="// OUTPUT",
                 fg=C["txt2"], bg=C["bg1"],
                 font=(F_MONO, 8), padx=10).pack(side=tk.LEFT, pady=4)

        self._proc_lbl = tk.Label(hdr, text="● IDLE",
                                   fg=C["acc3"], bg=C["bg1"],
                                   font=(F_MONO, 8))
        self._proc_lbl.pack(side=tk.LEFT, padx=10)

        tk.Button(hdr, text="CLEAR",
                  fg=C["txt2"], bg=C["bg1"],
                  activeforeground=C["acc2"],
                  font=(F_MONO, 7), relief=tk.FLAT, bd=0,
                  cursor="hand2",
                  command=self._clear_console).pack(side=tk.RIGHT, padx=10, pady=4)

        self._console = scrolledtext.ScrolledText(
            cf,
            bg="#01080f", fg=C["acc3"],
            font=(F_MONO, 9),
            relief=tk.FLAT, bd=0,
            state=tk.DISABLED,
            height=9,
        )
        self._console.pack(fill=tk.X)

        # Tags
        for tag, color in [
            ("info",    C["acc3"]),  ("warn",  C["warn"]),
            ("err",     C["err"]),   ("dim",   C["txt2"]),
            ("finding", C["acc"]),   ("cmd",   C["acc5"]),
        ]:
            self._console.tag_config(tag, foreground=color)

        self._log("✦ ALFANET XiaoYao Toolbox 2026 · Click any tool to launch", "info")
        self._log(f"✦ Platform: {OS} {ARCH}  ·  Python {sys.version.split()[0]}", "dim")
        self._log("─" * 72, "dim")

    # ──────────────────────────────────────────────────────
    #  CATEGORY SELECT
    # ──────────────────────────────────────────────────────
    def _select(self, cat):
        self._cur_cat = cat
        for c, b in self._cat_btns.items():
            b.configure(fg=C["acc"] if c==cat else C["txt2"],
                        bg=C["bg2"] if c==cat else C["bg1"])
        self._render(TOOLS[cat])
        self._search.set("")
        self._canvas.yview_moveto(0)

    # ──────────────────────────────────────────────────────
    #  RENDER CARDS
    # ──────────────────────────────────────────────────────
    def _render(self, tools):
        for w in self._inner.winfo_children():
            w.destroy()
        self._cards.clear()

        COLS = 3
        for i in range(COLS):
            self._inner.columnconfigure(i, weight=1)

        for i, t in enumerate(tools):
            card = self._make_card(self._inner, t)
            card.grid(row=i//COLS, column=i%COLS,
                      padx=10, pady=8, sticky="nsew")
            self._cards.append((t, card))

    # ── SINGLE CARD ───────────────────────────────────────
    def _make_card(self, parent, t):
        color   = t.get("color", C["acc"])
        name    = t["name"]
        desc    = t["desc"]
        badge   = t.get("badge", "FREE")
        tags    = t.get("tags", [])
        url     = t.get("url", "")
        cmd_raw = t.get("cmd", "")

        # Badge color
        if "PAID" in badge:     bc = C["acc5"]
        elif "必装" in badge:   bc = C["acc3"]
        elif "★" in badge:      bc = C["acc"]
        else:                   bc = C["txt2"]

        # ── outer frame with 1px border ──────────────────
        outer = tk.Frame(parent, bg=C["border"])
        inner = tk.Frame(outer, bg=C["bg3"])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        # Color accent bar (left)
        tk.Frame(inner, bg=color, width=4).pack(side=tk.LEFT, fill=tk.Y)

        body = tk.Frame(inner, bg=C["bg3"])
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        # Row 1: name + badge
        r1 = tk.Frame(body, bg=C["bg3"])
        r1.pack(fill=tk.X)
        tk.Label(r1, text=name,
                 fg=C["txt"], bg=C["bg3"],
                 font=(F_MONO, 11, "bold"),
                 anchor="w").pack(side=tk.LEFT)
        tk.Label(r1, text=badge,
                 fg=bc, bg=C["bg2"],
                 font=(F_MONO, 7),
                 padx=5, pady=1).pack(side=tk.RIGHT)

        # Description
        tk.Label(body, text=desc,
                 fg=C["txt2"], bg=C["bg3"],
                 font=(F_UI, SZ),
                 anchor="w", wraplength=300,
                 justify=tk.LEFT).pack(fill=tk.X, pady=(4, 4))

        # Tags
        tf = tk.Frame(body, bg=C["bg3"])
        tf.pack(fill=tk.X, pady=(0, 4))
        for tag in tags:
            tk.Label(tf, text=tag,
                     fg=C["txt2"], bg=C["bg2"],
                     font=(F_MONO, 7),
                     padx=4, pady=1).pack(side=tk.LEFT, padx=2)

        # Command preview
        preview = cmd_raw[:56] + ("…" if len(cmd_raw) > 56 else "")
        tk.Label(body, text=preview,
                 fg=C["txt3"], bg=C["bg3"],
                 font=(F_MONO, 8),
                 anchor="w").pack(fill=tk.X, pady=(0, 8))

        # ── BUTTON ROW ───────────────────────────────────
        br = tk.Frame(body, bg=C["bg3"])
        br.pack(fill=tk.X)

        # ▶ TERMINAL  (弹出新终端)
        tk.Button(br, text="▶ 终端",
                  fg=C["bg0"], bg=color,
                  activeforeground=C["bg0"],
                  font=(F_MONO, 8, "bold"),
                  relief=tk.FLAT, bd=0,
                  padx=10, pady=4,
                  cursor="hand2",
                  command=lambda t=t: self._launch_terminal(t)
                  ).pack(side=tk.LEFT, padx=(0, 6))

        # ⬛ RUN  (内嵌控制台)
        tk.Button(br, text="⬛ 内嵌",
                  fg=C["txt"], bg=C["bg2"],
                  activeforeground=C["acc"],
                  font=(F_MONO, 8),
                  relief=tk.FLAT, bd=0,
                  padx=8, pady=4,
                  cursor="hand2",
                  command=lambda t=t: self._launch_embedded(t)
                  ).pack(side=tk.LEFT, padx=(0, 6))

        # ⎘ CMD
        tk.Button(br, text="⎘",
                  fg=C["txt2"], bg=C["bg2"],
                  activeforeground=C["acc"],
                  font=(F_MONO, 9),
                  relief=tk.FLAT, bd=0,
                  padx=6, pady=4,
                  cursor="hand2",
                  command=lambda c=cmd_raw: self._copy_cmd(c)
                  ).pack(side=tk.LEFT, padx=(0, 6))

        # ↗ URL
        if url:
            tk.Button(br, text="↗",
                      fg=color, bg=C["bg3"],
                      activeforeground=C["txt"],
                      font=(F_MONO, 9),
                      relief=tk.FLAT, bd=0,
                      padx=4, pady=4,
                      cursor="hand2",
                      command=lambda u=url: webbrowser.open(u)
                      ).pack(side=tk.LEFT)

        # Hover effect
        for widget in [outer, inner, body]:
            widget.bind("<Enter>",
                lambda e, o=outer, i=inner, b=body: [
                    o.configure(bg=color),
                    i.configure(bg=C["bg4"]),
                    b.configure(bg=C["bg4"]),
                ])
            widget.bind("<Leave>",
                lambda e, o=outer, i=inner, b=body, col=color: [
                    o.configure(bg=C["border"]),
                    i.configure(bg=C["bg3"]),
                    b.configure(bg=C["bg3"]),
                ])

        return outer

    # ──────────────────────────────────────────────────────
    #  LAUNCH ACTIONS
    # ──────────────────────────────────────────────────────
    def _resolve_cmd(self, t: dict) -> str:
        target = self._target.get().strip() or "target"
        cmd = t.get("cmd", "")
        return (cmd
                .replace("{target}", target)
                .replace("{input}", "targets.txt")
                .replace("{binary}", "target_binary")
                .replace("{file}", "target_file")
                .replace("{package}", "com.target.app")
                .replace("{hash}", "hash.txt")
                )

    def _launch_terminal(self, t: dict):
        """弹出新终端窗口运行"""
        cmd = self._resolve_cmd(t)
        self._log(f"[▶ TERM] {t['name']}", "cmd")
        self._log(f"  $ {cmd}", "dim")
        ok = _launch_in_new_terminal(cmd)
        if not ok:
            self._log("  ✗ No terminal emulator found.", "err")
        else:
            self._log("  ✓ Terminal opened", "info")

    def _launch_embedded(self, t: dict):
        """内嵌控制台运行"""
        cmd = self._resolve_cmd(t)
        self._log(f"[⬛ RUN] {t['name']}", "cmd")
        self._log(f"  $ {cmd}", "dim")

        self._proc_cnt += 1
        self._proc_lbl.configure(
            text=f"● RUNNING ({self._proc_cnt})", fg=C["acc6"])

        def _out(line):
            self._log_q.put(("out", f"  {line}"))

        def _done(rc):
            self._proc_cnt = max(0, self._proc_cnt - 1)
            status = "✓ Done" if rc == 0 else f"✗ Exit {rc}"
            color  = C["acc3"] if rc == 0 else C["err"]
            self._log_q.put(("done", (t["name"], rc, color)))
            if self._proc_cnt == 0:
                self._log_q.put(("idle", None))

        _run_embedded(cmd, _out, _done)

    def _copy_cmd(self, cmd: str):
        target = self._target.get().strip() or "target"
        cmd = cmd.replace("{target}", target)
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self._log(f"✓ Copied: {cmd}", "dim")

    # ──────────────────────────────────────────────────────
    #  FILTER / SEARCH
    # ──────────────────────────────────────────────────────
    def _filter(self):
        q = self._search.get().lower().strip()
        for tool, card in self._cards:
            text = (tool["name"] + " " + tool["desc"] + " " +
                    " ".join(tool.get("tags", []))).lower()
            if not q or q in text:
                card.grid()
            else:
                card.grid_remove()

    # ──────────────────────────────────────────────────────
    #  LOG / CONSOLE
    # ──────────────────────────────────────────────────────
    def _log(self, msg: str, tag: str = "info"):
        self._log_q.put(("log", (msg, tag)))

    def _poll(self):
        try:
            while True:
                item = self._log_q.get_nowait()
                kind, data = item
                if kind == "log":
                    self._write(data[0], data[1])
                elif kind == "out":
                    self._write(data, "dim")
                elif kind == "done":
                    name, rc, color = data
                    self._write(
                        f"  [{name}] {'✓ Done' if rc==0 else f'✗ Exit {rc}'}",
                        "info" if rc == 0 else "err")
                    self._proc_lbl.configure(
                        text=f"● RUNNING ({self._proc_cnt})"
                        if self._proc_cnt > 0 else "● IDLE",
                        fg=C["acc6"] if self._proc_cnt > 0 else C["acc3"])
                elif kind == "idle":
                    self._proc_lbl.configure(text="● IDLE", fg=C["acc3"])
        except queue.Empty:
            pass
        self.after(60, self._poll)

    def _write(self, msg: str, tag: str = "info"):
        self._console.configure(state=tk.NORMAL)
        ts = datetime.now().strftime("%H:%M:%S")
        self._console.insert(tk.END, f"[{ts}] ", "dim")
        self._console.insert(tk.END, msg + "\n", tag)
        self._console.see(tk.END)
        self._console.configure(state=tk.DISABLED)

    def _clear_console(self):
        self._console.configure(state=tk.NORMAL)
        self._console.delete("1.0", tk.END)
        self._console.configure(state=tk.DISABLED)

    # ──────────────────────────────────────────────────────
    #  UTILITY
    # ──────────────────────────────────────────────────────
    def _scroll(self, e):
        if   e.num == 4: self._canvas.yview_scroll(-1, "units")
        elif e.num == 5: self._canvas.yview_scroll(1,  "units")
        else: self._canvas.yview_scroll(int(-1*(e.delta/120)), "units")

    def _clock_tick(self):
        self._clk_lbl.configure(
            text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._clock_tick)

    # ──────────────────────────────────────────────────────
    #  POPUP WINDOWS
    # ──────────────────────────────────────────────────────
    def _show_resources(self):
        w = self._popup("武器库资源", 700, 540)
        t = scrolledtext.ScrolledText(w, bg=C["bg2"], fg=C["txt"],
                                       font=(F_MONO, 10), relief=tk.FLAT, bd=0)
        t.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0,16))
        t.insert(tk.END, """
★ 矛·盾武器库 v3.2  (arch3rpro)
  VMware:      pan.baidu.com/s/1L8-9jhvvMp6jJ4evTTqezQ  pwd: jdkd
  Parallels:   pan.baidu.com/s/1iVvDj0-RAV9xX8Ttd2o_PA  pwd: e26n
  Fusion Mac:  pan.baidu.com/s/1zX4VapfYvm2j3Jga1oLdCA  pwd: fr26
  Proxmox:     pan.baidu.com/s/1iTCPkbPqiM9rrpzCf8EBVw  pwd: 4kgb
  Hyper-V:     pan.baidu.com/s/1iLYh7n1PCeUOOWofeKEOvA  pwd: 7qty
  官网:        arch3rpro.github.io/download

──────────────────────────────────────────────────

★ 天狐渗透工具箱  (One-Fox-Security-Team)
  GitHub:  github.com/One-Fox-Security-Team/One-Fox-T00ls
  网盘:    pan.baidu.com/s/1BiLFnoOV4c2fJMpwsOGCcA  pwd: ofox

──────────────────────────────────────────────────

★ Jawd  (Alphabug师傅)  ——  一键Jar反编译重打包
  github.com/AlphabugX/Jawd
  Java8:   java -jar Jawd.jar
  Java11+: java --module-path /path/javafx/lib \\
               --add-modules javafx.controls,javafx.fxml,javafx.graphics \\
               -jar Jawd.jar

★ JavaFX 下载:  gluonhq.com/products/javafx

──────────────────────────────────────────────────

★ 字典资源
  SecLists:             github.com/danielmiessler/SecLists
  PayloadsAllTheThings: github.com/swisskyrepo/PayloadsAllTheThings
  fuzzDicts:            github.com/TheKingOfDuck/fuzzDicts
  HackTricks:           book.hacktricks.xyz
  GTFOBins:             gtfobins.github.io
  LOLBAS:               lolbas-project.github.io
""")
        t.configure(state=tk.DISABLED)

    def _show_flow(self):
        w = self._popup("渗透测试全流程", 780, 500)
        t = scrolledtext.ScrolledText(w, bg="#01080f", fg=C["acc3"],
                                       font=(F_MONO, 9), relief=tk.FLAT, bd=0)
        t.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0,16))
        t.insert(tk.END, """
┌─────────────────────────────────────────────────────────────────────────────┐
│              ALFANET SROF · Pentest Full Flow 2026                          │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────────────────┤
│ Phase 1  │ Phase 2  │ Phase 3  │ Phase 4  │ Phase 5  │      Phase 6         │
│ 信息收集  │ 漏洞扫描  │ 漏洞利用  │ 权限提升  │ 横向移动  │    权限维持          │
├──────────┼──────────┼──────────┼──────────┼──────────┼──────────────────────┤
│Subfinder │Nuclei v3 │Metasploit│LinPEAS   │Impacket  │Sliver C2            │
│httpx     │Xray      │sqlmap    │WinPEAS   │BloodHound│Havoc C2             │
│FOFA      │Afrog     │Burp Suite│Rubeus    │CrackMapEx│ligolo-ng            │
│Nmap      │fscan     │Yakit     │mimikatz  │nps/frp   │计划任务/注册表        │
│katana    │goby/nikto│Poc-bomber│JuicyPot  │Empire    │服务项持久化           │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────────────────┘

━━━ HVV 护网攻击队 SOP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
D-1 资产收集:   subfinder -d target.com | httpx -title -tech-detect
D-0 批量扫描:   nuclei -l assets.txt -severity critical,high -c 50
    内网扫描:   fscan -h 192.168.1.0/24 -o fscan.txt
    AD分析:     bloodhound-python -d domain.local -c All
    建立C2:     sliver-client → generate beacon → deploy

━━━ BugBounty SRC ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
收集 → subfinder | httpx | katana爬取 | gau历史URL
扫描 → nuclei全量 + xray被动 + dalfox XSS
挖掘 → Burp/Caido手工 + ffuf参数Fuzz + sqlmap注入
提交 → PoC截图 + 完整请求响应 + 影响说明

━━━ APT 全链路 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
初始访问 → 鱼叉邮件/供应链/0day/水坑
立足据点 → Cobalt Strike Beacon / Sliver implant
提权     → PrintSpoofer / JuicyPotato / CVE
横向     → Pass-the-Hash / Kerberoasting / BloodHound路径
信息收集 → mimikatz dump / DPAPI / 文件收割
数据外传 → DNS隧道 / HTTPS隐蔽信道 / 合法云服务
""")
        t.configure(state=tk.DISABLED)

    def _show_about(self):
        w = self._popup("关于 SROF", 520, 320)
        t = scrolledtext.ScrolledText(w, bg=C["bg1"], fg=C["txt"],
                                       font=(F_MONO, 10), relief=tk.FLAT, bd=0)
        t.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0,16))
        t.insert(tk.END, f"""
  ▣ ALFANET · XiaoYao Toolbox 2026
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Author  :  XiaoYao @ Alfanet
  GitHub  :  github.com/ADA-XiaoYao
  Platform:  {OS} {ARCH}
  Python  :  {sys.version.split()[0]}

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  按钮说明:
  ▶ 终端  — 弹出系统终端新窗口运行
  ⬛ 内嵌  — 在软件内嵌控制台运行并显示输出
  ⎘      — 复制命令到剪贴板
  ↗      — 打开工具 GitHub 页面

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠️  免责声明
  本工具仅供授权渗透测试、CTF竞赛、安全研究使用。
  禁止用于未经授权目标，违者自负法律责任。
""")
        t.configure(state=tk.DISABLED)

    def _popup(self, title: str, w: int, h: int) -> tk.Toplevel:
        win = tk.Toplevel(self)
        win.title(title)
        win.geometry(f"{w}x{h}")
        win.configure(bg=C["bg1"])
        tk.Label(win, text=f"// {title.upper()}",
                 fg=C["acc"], bg=C["bg1"],
                 font=(F_MONO, 11, "bold")).pack(pady=(14, 8), padx=16, anchor="w")
        return win


# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = Toolbox()
    app.mainloop()
