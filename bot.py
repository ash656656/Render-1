import os
import re
import socket
import ipaddress
import asyncio
import time
import concurrent.futures
import aiohttp
import urllib3
import ssl

from pyrogram import Client, filters
from pyrogram.types import ReplyKeyboardMarkup, KeyboardButton, Message
from pyrogram.errors import FloodWait

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# CONFIGURATION & REBRANDING
# ==========================================
API_ID = 32731964   
API_HASH = "9f64201dc6989052769606f55db6f55c"
BOT_TOKEN = "8805238994:AAEOt2ULzylCXsq-qGcB2E9qOGLWYM19CMc"

# Optional: Add your ProjectDiscovery Cloud Platform (PDCP) API key here for Chaos
PDCP_API_KEY = "e22b13f0-57a0-4662-b036-5065aa7528f3" 

app = Client("mxd_personal_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

USER_STATE = {}
DOWNLOAD_DIR = "./Mxd_Bot_Results"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

DNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=300)

# Global stats counter
SYSTEM_STATS = {
    "start_time": time.time(),
    "tasks_executed": 0,
    "total_hits": 0
}

def get_main_keyboard():
    keyboard = [
        [KeyboardButton("🌐 Host Scanner"), KeyboardButton("🗺️ CIDR Mapper")],
        [KeyboardButton("🕷️ Domain Extractor"), KeyboardButton("📡 Multi-CIDR Recon")],
        [KeyboardButton("🔌 Port Scanner"), KeyboardButton("🎯 Subdomain Hunter")],
        [KeyboardButton("🗂️ Bulk Subdomains"), KeyboardButton("✂️ Payload Splitter")],
        [KeyboardButton("🔄 Reverse DNS"), KeyboardButton("🧹 List Sanitizer")],
        [KeyboardButton("ℹ️ Node Interrogation"), KeyboardButton("📡 SNI Intelligence")],
        [KeyboardButton("📊 System Info"), KeyboardButton("❌ Abort Operation")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True, placeholder="Mxd Control Panel")

class ProgressTracker:
    def __init__(self, total):
        self.total = total
        self.scanned = 0
        self.hits = 0
        self.last_update = 0
        self.is_stopped = False

STATUS_MAP = {
    101: "101 Switching Protocols",
    200: "200 OK",
    301: "301 Moved Permanently",
    302: "302 Found",
    303: "303 See Other",
    307: "307 Temporary Redirect",
    400: "400 Bad Request",
    401: "401 Unauthorized",
    403: "403 Forbidden",
    404: "404 Not Found",
    426: "426 Upgrade Required",
    500: "500 Internal Server Error",
    502: "502 Bad Gateway",
    503: "503 Service Unavailable",
    522: "522 Connection Timed Out"
}

# ==========================================
# SAFE TELEGRAM SENDING (ANTI-FLOOD / NO BADMSG)
# ==========================================
async def safe_edit_text(message: Message, text: str, reply_markup=None):
    try:
        await message.edit_text(text, reply_markup=reply_markup)
    except FloodWait as e:
        await asyncio.sleep(e.value + 2)
        try: await message.edit_text(text, reply_markup=reply_markup)
        except Exception: pass
    except Exception:
        pass

async def safe_reply_text(message: Message, text: str, reply_markup=None):
    try:
        return await message.reply_text(text, reply_markup=reply_markup)
    except FloodWait as e:
        await asyncio.sleep(e.value + 2)
        try: return await message.reply_text(text, reply_markup=reply_markup)
        except Exception: pass
    except Exception:
        pass

# ==========================================
# ASYNCHRONOUS NETWORK UTILITIES
# ==========================================
async def async_gethostbyname(domain: str) -> str:
    loop = asyncio.get_running_loop()
    try: return await loop.run_in_executor(DNS_EXECUTOR, socket.gethostbyname, domain)
    except Exception: return "N/A"

async def async_getallips(domain: str) -> list:
    loop = asyncio.get_running_loop()
    try: 
        _, _, ips = await loop.run_in_executor(DNS_EXECUTOR, socket.gethostbyname_ex, domain)
        return ips
    except Exception: return ["N/A"]

async def update_live_status(status_msg: Message, tracker: ProgressTracker, prefix_text: str):
    now = time.time()
    # Changed internal check to 30.0 seconds to prevent rate limits
    if now - tracker.last_update > 30.0 or tracker.scanned >= tracker.total:
        tracker.last_update = now
        percentage = (tracker.scanned / tracker.total) * 100 if tracker.total > 0 else 0
        live_text = (
            f"{prefix_text}\n\n"
            f"📈 **Execution Progress:** {percentage:.1f}%\n"
            f"🔄 **Nodes Processed:** `{tracker.scanned}/{tracker.total}`\n"
            f"🎯 **Valid Hits:** `{tracker.hits}`\n\n"
            f"⚠️ *Type 'stop' to gracefully abort the operation.*"
        )
        await safe_edit_text(status_msg, live_text)

# ==========================================
# SUBDOMAIN INTEL SCRAPERS
# ==========================================
async def fetch_subdomains_for_domain(session: aiohttp.ClientSession, domain: str) -> set:
    found_subs = set()
    domain = domain.strip().lower()
    if not domain: return found_subs

    # 1. HackerTarget
    try:
        async with session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=6.0) as r:
            if r.status == 200:
                text_data = await r.text()
                for line in text_data.strip().split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub.endswith(domain): found_subs.add(sub)
    except Exception: pass

    # 2. RapidDNS
    try:
        async with session.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=8.0) as r:
            if r.status == 200:
                html = await r.text()
                subs = re.findall(r'<td>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>', html)
                for sub in subs: found_subs.add(sub.lower())
    except Exception: pass

    # 3. ProjectDiscovery Chaos API
    try:
        headers = {}
        if PDCP_API_KEY:
            headers["Authorization"] = PDCP_API_KEY
        async with session.get(f"https://dns.projectdiscovery.io/dns/{domain}", headers=headers, timeout=8.0) as r:
            if r.status == 200:
                data = await r.json()
                if "subdomains" in data and data["subdomains"]:
                    for sub_part in data["subdomains"]:
                        found_subs.add(f"{sub_part}.{domain}".lower())
    except Exception: pass

    return found_subs

# ==========================================
# QUEUE WORKERS
# ==========================================
async def worker_cidr(queue: asyncio.Queue, session: aiohttp.ClientSession, res_file: str, tracker: ProgressTracker):
    while True:
        item = await queue.get()
        if tracker.is_stopped:
            queue.task_done()
            continue
        ip, port = item
        try:
            url = f"http://{ip}:{port}"
            custom_timeout = aiohttp.ClientTimeout(total=4.0, connect=2.0)
            headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
            async with session.get(url, timeout=custom_timeout, allow_redirects=False, ssl=False, headers=headers) as resp:
                status = resp.status
                server = resp.headers.get('Server', 'Unknown')
                location = resp.headers.get('Location', '').lower()
                if not (status == 302 and any(x in location for x in ["jio", "airtel", "captive"])):
                    with open(res_file, "a") as f: f.write(f"{status} | {server} | {ip}:{port}\n")
                    tracker.hits += 1
                    SYSTEM_STATS["total_hits"] += 1
        except Exception: pass
        finally:
            tracker.scanned += 1
            queue.task_done()

async def worker_host(queue: asyncio.Queue, session: aiohttp.ClientSession, res_file: str, tracker: ProgressTracker):
    while True:
        item = await queue.get()
        if tracker.is_stopped:
            queue.task_done()
            continue
        domain, port = item
        try:
            url = f"https://{domain}" if str(port) == "443" else f"http://{domain}:{port}"
            ip = await async_gethostbyname(domain)
            custom_timeout = aiohttp.ClientTimeout(total=5.0, connect=2.5)
            headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
            async with session.get(url, timeout=custom_timeout, allow_redirects=False, ssl=False, headers=headers) as resp:
                status = resp.status
                server = resp.headers.get("Server", "Unknown")
                location = resp.headers.get("Location", "").lower()
                if not (status == 302 and any(x in location for x in ["jio.com", "airtel", "captive"])):
                    with open(res_file, "a") as f: f.write(f"{status} | {server} | {ip} | {domain}:{port}\n")
                    tracker.hits += 1
                    SYSTEM_STATS["total_hits"] += 1
        except Exception: pass
        finally:
            tracker.scanned += 1
            queue.task_done()

# ==========================================
# COMMAND ROUTERS & PRIVATE LOGIC
# ==========================================

@app.on_message(filters.command("start") & filters.private)
async def start_cmd(client: Client, message: Message):
    text = (
        "**███╗   ███╗██╗  ██╗██████╗ \n"
        "████╗ ████║╚██╗██╔╝██╔══██╗\n"
        "██╔████╔██║ ╚███╔╝ ██║  ██║\n"
        "██║╚██╔╝██║ ██╔██╗ ██║  ██║\n"
        "██║ ╚═╝ ██║██╔╝ ██╗██████╔╝\n"
        "╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ **\n"
        "             **N E T W O R K**\n\n"
        "**System:** MxdNetwork Engine v14.0 (Enhanced Edition)\n"
        "**Status:** Operational\n\n"
        "Select an infrastructure module below:"
    )
    await safe_reply_text(message, text, reply_markup=get_main_keyboard())

@app.on_message(filters.text & filters.private)
async def process_inputs(client: Client, message: Message):
    user_id = message.from_user.id
    text = message.text.strip()

    if user_id in USER_STATE and "tracker" in USER_STATE[user_id]:
        if text.lower() == "stop":
            tracker = USER_STATE[user_id]["tracker"]
            tracker.is_stopped = True
            await safe_reply_text(message, "🛑 **Interrupt signal received. Safely terminating your threads...**")
            return

    if text == "❌ Abort Operation":
        USER_STATE.pop(user_id, None)
        await safe_reply_text(message, "🔄 Action reset. Control panel re-initialized.", reply_markup=get_main_keyboard())
        return

    if text == "🌐 Host Scanner":
        USER_STATE[user_id] = {"action": "tool_host"}
        await safe_reply_text(message, "**[Mxd Host Scanner]**\n\nPlease upload your target domain list (.txt format).")
        return
    elif text == "🗺️ CIDR Mapper":
        USER_STATE[user_id] = {"action": "tool_cidr"}
        await safe_reply_text(message, "**[Mxd CIDR Network Mapper]**\n\nEnter the target CIDR block (e.g., `104.16.0.0/24`):")
        return
    elif text == "🕷️ Domain Extractor":
        USER_STATE[user_id] = {"action": "tool_extract"}
        await safe_reply_text(message, "**[Mxd Domain Extractor]**\n\nUpload raw text or paste data content below:")
        return
    elif text == "📡 Multi-CIDR Recon":
        USER_STATE[user_id] = {"action": "tool_mcidr"}
        await safe_reply_text(message, "**[Mxd Multi-CIDR Recon]**\n\nUpload a file containing multiple CIDR blocks (.txt format):")
        return
    elif text == "🔌 Port Scanner":
        USER_STATE[user_id] = {"action": "tool_port"}
        await safe_reply_text(message, "**[Mxd Deep Port Scanner]**\n\nEnter the target Hostname or IP address:")
        return
    elif text == "🎯 Subdomain Hunter":
        USER_STATE[user_id] = {"action": "tool_sub"}
        await safe_reply_text(message, "**[Mxd Subdomain Hunter]**\n\nEnter the root domain to analyze:")
        return
    elif text == "🗂️ Bulk Subdomains":
        USER_STATE[user_id] = {"action": "tool_bulk_sub"}
        await safe_reply_text(message, "**[Mxd Bulk Subdomain Hunter]**\n\nPlease upload a `.txt` file containing your list of root domains (one per line).")
        return
    elif text == "✂️ Payload Splitter":
        USER_STATE[user_id] = {"action": "tool_split"}
        await safe_reply_text(message, "**[Mxd Payload Splitter]**\n\nUpload the large dataset file to split (.txt format):")
        return
    elif text == "🔄 Reverse DNS":
        USER_STATE[user_id] = {"action": "tool_rdns"}
        await safe_reply_text(message, "**[Mxd Reverse DNS Mapper]**\n\nEnter the target IP or Domain for reverse lookup:")
        return
    elif text == "🧹 List Sanitizer":
        USER_STATE[user_id] = {"action": "tool_clean"}
        await safe_reply_text(message, "**[Mxd Dataset Sanitizer]**\n\nUpload the domain list to remove duplicates (.txt):")
        return
    elif text == "ℹ️ Node Interrogation":
        USER_STATE[user_id] = {"action": "tool_node"}
        await safe_reply_text(message, "**[Mxd Node Interrogation]**\n\nEnter the target Domain or IP address:")
        return
    elif text == "📡 SNI Intelligence":
        USER_STATE[user_id] = {"action": "tool_sni"}
        await safe_reply_text(message, "**[Mxd SNI Intelligence]**\n\nEnter target SNI Hostname for deep analysis (e.g., `facebook.com`):")
        return
    elif text == "📊 System Info":
        uptime = time.strftime("%Hh %Mm %Ss", time.gmtime(time.time() - SYSTEM_STATS["start_time"]))
        info_text = (
            "⚙️ **MXDNETWORK ENGINE STATUS**\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"⏱️ **Uptime:** `{uptime}`\n"
            f"🔄 **Tasks Dispatched:** `{SYSTEM_STATS['tasks_executed']}`\n"
            f"🎯 **Total Hits Saved:** `{SYSTEM_STATS['total_hits']}`\n"
            "🧠 **Protocol Core:** Async Queue-Driven\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )
        await safe_reply_text(message, info_text, reply_markup=get_main_keyboard())
        return

    # Text operations handling
    if user_id in USER_STATE and "action" in USER_STATE[user_id]:
        state = USER_STATE[user_id]["action"]
        SYSTEM_STATS["tasks_executed"] += 1
        
        if state == "tool_sni":
            status_msg = await safe_reply_text(message, "📡 **Analyzing SNI Framework & Tunnel Profiles...**")
            sni_host = text.replace("http://", "").replace("https://", "").split("/")[0].strip()
            try:
                ips = await async_getallips(sni_host)
                if "N/A" in ips and len(ips) == 1:
                    await safe_edit_text(status_msg, "❌ **Resolution Failure:** Hostname did not return valid A records.")
                    USER_STATE.pop(user_id, None)
                    return
                ip_display = "\n".join([f"   ↳ `{ip}`" for ip in ips])
                target_ip = ips[0]
                
                open_ports = []
                check_ports_list = [80, 443, 8080, 8880, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 3389]
                async def sni_check_port(port):
                    try:
                        conn = asyncio.open_connection(target_ip, port)
                        _, writer = await asyncio.wait_for(conn, timeout=1.5)
                        open_ports.append(port)
                        writer.close()
                        await writer.wait_closed()
                    except Exception: pass
                await asyncio.gather(*[sni_check_port(p) for p in check_ports_list])
                open_ports.sort()
                ports_display = ", ".join(map(str, open_ports)) if open_ports else "80, 443"

                server_header = "Unknown"
                http_status_display = "Connection Error"
                supports_ws = "False"
                location_url = "None"
                
                req_headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
                
                async with aiohttp.ClientSession(headers=req_headers) as session:
                    fetch_success = False
                    for scheme in ["https", "http"]:
                        if fetch_success: break
                        try:
                            async with session.get(f"{scheme}://{sni_host}", timeout=4.0, allow_redirects=False, ssl=False) as r:
                                http_status_display = STATUS_MAP.get(r.status, f"{r.status} Status Code")
                                server_header = r.headers.get("Server", "Unknown")
                                location_url = r.headers.get("Location", "None")
                                fetch_success = True
                        except Exception: pass
                    
                    try:
                        ws_headers = {"Connection": "Upgrade", "Upgrade": "websocket", "Host": sni_host, "Sec-WebSocket-Key": "x3JJHMbDL1EzLkh9GBhXDw==", "Sec-WebSocket-Version": "13"}
                        async with session.get(f"https://{sni_host}", headers=ws_headers, timeout=4.0, allow_redirects=False, ssl=False) as ws_r:
                            if ws_r.status in [101, 400, 426] or "websocket" in ws_r.headers.get("Connection", "").lower():
                                supports_ws = f"True ({STATUS_MAP.get(ws_r.status, str(ws_r.status))})"
                    except Exception: pass
                    
                if "cloudflare" in server_header.lower() and supports_ws == "False":
                    supports_ws = "True (Cloudflare Edge)"

                report = (
                    f"📡 **ADVANCED SNI & VPN INTELLIGENCE REPORT**\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"🎯 **Target Node:** `{sni_host}`\n"
                    f"📌 **Resolved IPv4:**\n{ip_display}\n\n"
                    f"ℹ️ **HTTP Status:** `{http_status_display}`\n"
                    f"⚙️ **Server Daemon:** `{server_header}`\n"
                    f"🌐 **Redirect Path:** `{location_url}`\n"
                    f"🔌 **WebSocket (WS):** `{supports_ws}`\n"
                    f"🔓 **Exposed Ports:** `{ports_display}`\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                )
                await safe_edit_text(status_msg, report)
            except Exception as e: await safe_edit_text(status_msg, f"❌ **Diagnostics Error:** {str(e)}")
            finally: USER_STATE.pop(user_id, None)
            return

        elif state == "tool_sub":
            status_msg = await safe_reply_text(message, "🔎 **Subdomain Hunter active...**\n\n*Gathering via Chaos, HackerTarget & RapidDNS...*")
            domain = text.replace("http://", "").replace("https://", "").split("/")[0].strip()
            
            try:
                async with aiohttp.ClientSession() as session:
                    found_subs = await fetch_subdomains_for_domain(session, domain)
                    
                found_list = sorted(list(found_subs))
                if found_list:
                    res_file = os.path.join(DOWNLOAD_DIR, f"subs_{user_id}_{domain}.txt")
                    with open(res_file, "w") as f:
                        for s in found_list: f.write(s + "\n")
                    
                    display_subs = found_list[:20]
                    res_txt = f"🎯 **Subdomain Hunter Results:**\n🌐 Target: `{domain}`\n🔥 Found: `{len(found_list)}` records\n\n"
                    for f in display_subs: res_txt += f"  ↳ `{f}`\n"
                    
                    if len(found_list) > 20: 
                        res_txt += f"\n*...and {len(found_list)-20} more. File attached below!*"
                    
                    try: await message.reply_document(res_file, caption=res_txt)
                    except Exception: pass
                    os.remove(res_file)
                else: 
                    await safe_reply_text(message, f"❌ **No subdomains found for `{domain}`.**")
            except Exception as e: 
                await safe_reply_text(message, f"❌ **Error:** {str(e)}")
            finally: 
                try: await status_msg.delete()
                except: pass
                USER_STATE.pop(user_id, None)
            return

        elif state == "tool_cidr":
            res_file = os.path.join(DOWNLOAD_DIR, f"cidr_res_{user_id}.txt")
            open(res_file, 'w').close()
            status_msg = await safe_reply_text(message, "⏳ **Initializing Network Mapper...**")
            try:
                net = ipaddress.ip_network(text, strict=False)
                total_hosts = (net.num_addresses - 2) if net.num_addresses > 2 else 1
                ports = ["80", "443"]
                tracker = ProgressTracker(total_hosts * len(ports))
                USER_STATE[user_id]["tracker"] = tracker
                q = asyncio.Queue(maxsize=10000)
                
                async def producer():
                    for ip in net.hosts():
                        if tracker.is_stopped: break
                        for pt in ports:
                            if tracker.is_stopped: break
                            await q.put((str(ip), pt))
                            
                prod_task = asyncio.create_task(producer())
                async def updater():
                    while not tracker.is_stopped:
                        await update_live_status(status_msg, tracker, "⚡️ **Execution Engine: Active**")
                        await asyncio.sleep(30.0) # Changed from 4.0 to 30.0
                        
                upd_task = asyncio.create_task(updater())

                async with aiohttp.ClientSession() as session:
                    workers = [asyncio.create_task(worker_cidr(q, session, res_file, tracker)) for _ in range(100)]
                    await prod_task
                    await q.join()
                    for w in workers: w.cancel()
                    upd_task.cancel()

                if tracker.is_stopped: await update_live_status(status_msg, tracker, "🛑 **Execution Halted Manually.**")
                else: await update_live_status(status_msg, tracker, "⚡️ **Execution Completed.**")

                if os.path.getsize(res_file) > 0:
                    try: await message.reply_document(res_file, caption=f"📊 **CIDR Scan Complete:**\nScanned: {tracker.scanned}\nHits: {tracker.hits}")
                    except Exception: pass
                else: await safe_reply_text(message, "❌ No accessible nodes discovered.")
            except Exception as e: await safe_reply_text(message, f"❌ **Syntax Error:** {str(e)}")
            finally:
                if os.path.exists(res_file): os.remove(res_file)
                USER_STATE.pop(user_id, None)
            return

        elif state == "tool_port":
            status_msg = await safe_reply_text(message, "🔍 **Executing Deep Port Scan...**")
            try:
                ip_addr = await async_gethostbyname(text)
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
                open_ports = []
                async def check_port(port):
                    try:
                        conn = asyncio.open_connection(ip_addr, port)
                        _, writer = await asyncio.wait_for(conn, timeout=1.5)
                        open_ports.append(port)
                        writer.close()
                        await writer.wait_closed()
                    except Exception: pass
                await asyncio.gather(*[check_port(p) for p in ports])
                try: await status_msg.delete()
                except: pass
                if open_ports:
                    res_txt = f"📊 **Diagnostic for {text}:**\n\n"
                    for p in sorted(open_ports): res_txt += f"✅ Port `{p}` [OPEN]\n"
                    await safe_reply_text(message, res_txt)
                else: await safe_reply_text(message, "❌ All target ports are closed.")
            except Exception as e: await safe_reply_text(message, f"❌ **Error:** {str(e)}")
            finally: USER_STATE.pop(user_id, None)
            return

        elif state == "tool_node":
            try:
                ip = await async_gethostbyname(text)
                if ip != "N/A": await safe_reply_text(message, f"ℹ️ **Target:** `{text}`\n📌 **Resolved IPv4:** `{ip}`")
                else: await safe_reply_text(message, "❌ DNS Resolution failed.")
            except Exception as e: await safe_reply_text(message, f"❌ **Error:** {str(e)}")
            finally: USER_STATE.pop(user_id, None)
            return

        elif state == "tool_rdns":
            status_msg = await safe_reply_text(message, "🔄 **Querying Reverse DNS / IP Data...**")
            ip = text.strip()
            try:
                domains = set()
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10.0) as resp:
                        if resp.status == 200:
                            for line in (await resp.text()).strip().split('\n'):
                                if line and 'error' not in line.lower():
                                    domains.add(line.strip())
                if domains:
                    res_txt = f"🎯 **Reverse IP Domains for `{ip}`:**\n\n"
                    for d in list(domains)[:25]: res_txt += f"🌐 `{d}`\n"
                    await safe_edit_text(status_msg, res_txt)
                else:
                    await safe_edit_text(status_msg, "❌ **No domains found hosted on this target IP.**")
            except Exception as e: await safe_edit_text(status_msg, f"❌ **Error:** {str(e)}")
            finally: USER_STATE.pop(user_id, None)
            return

# ============ DOCUMENT INPUT ROUTER ============
@app.on_message(filters.document & filters.private)
async def process_documents(client: Client, message: Message):
    user_id = message.from_user.id
    if user_id not in USER_STATE or "action" not in USER_STATE[user_id]: return

    state = USER_STATE[user_id]["action"]
    status_msg = await safe_reply_text(message, "⏳ **Downloading and Authenticating Payload...**")
    SYSTEM_STATS["tasks_executed"] += 1

    try:
        if state == "tool_bulk_sub":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/bulk_in_{user_id}.txt")
            
            await safe_edit_text(status_msg, "🗂️ **Processing Root Domain Map...**")
            with open(file_path, 'r', errors='ignore') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            if not domains:
                await safe_edit_text(status_msg, "❌ **The uploaded file is empty.**")
                os.remove(file_path)
                USER_STATE.pop(user_id, None)
                return

            all_compiled_subs = set()
            tracker = ProgressTracker(len(domains))
            USER_STATE[user_id]["tracker"] = tracker
            
            await safe_edit_text(status_msg, f"⚡️ **Beginning Bulk Hunting on {len(domains)} target domains...**")
            
            async with aiohttp.ClientSession() as session:
                for idx, dom in enumerate(domains, 1):
                    if tracker.is_stopped:
                        break
                    
                    # Throttled the updates to avoid FloodWait crashes
                    if idx % 10 == 0 or idx == len(domains):
                        await safe_edit_text(status_msg, f"📡 **Hunting Status:**\n🔄 Mapping domain `{idx}/{len(domains)}`: `{dom}`\n🎯 Total Gathered: `{len(all_compiled_subs)}`")
                    
                    subs = await fetch_subdomains_for_domain(session, dom)
                    all_compiled_subs.update(subs)
                    tracker.scanned += 1
            
            final_file = os.path.join(DOWNLOAD_DIR, f"bulk_subs_output_{user_id}.txt")
            sorted_subs = sorted(list(all_compiled_subs))
            with open(final_file, 'w') as out_f:
                for sub in sorted_subs:
                    out_f.write(sub + "\n")
            
            if tracker.is_stopped:
                caption_txt = f"🛑 **Bulk Processing Halted Early.**\nParsed Domains: {tracker.scanned}\nTotal Subdomains Extracted: {len(sorted_subs)}"
            else:
                caption_txt = f"✅ **Bulk Subdomain Mapping Finalized!**\nDomains Run: {tracker.scanned}\nTotal Deduplicated Subdomains: {len(sorted_subs)}"
            
            if sorted_subs:
                try: await message.reply_document(final_file, caption=caption_txt)
                except Exception: pass
            else:
                await safe_reply_text(message, "❌ **No subdomains were pulled from the sources provided.**")
                
            if os.path.exists(final_file): os.remove(final_file)
            if os.path.exists(file_path): os.remove(file_path)
            try: await status_msg.delete()
            except: pass

        elif state == "tool_host":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_host_{user_id}.txt")
            res_file = os.path.join(DOWNLOAD_DIR, f"host_res_{user_id}.txt")
            open(res_file, 'w').close()
            
            await safe_edit_text(status_msg, "⏳ **Calculating Payload Memory Footprint...**")
            total_lines = sum(1 for line in open(file_path, 'r', errors='ignore') if line.strip())
            ports = ["80", "443", "8080"]
            tracker = ProgressTracker(total_lines * len(ports))
            USER_STATE[user_id]["tracker"] = tracker
            
            q = asyncio.Queue(maxsize=10000)

            async def producer():
                with open(file_path, 'r', errors='ignore') as f:
                    for line in f:
                        if tracker.is_stopped: break
                        d = line.strip()
                        if d:
                            for pt in ports:
                                if tracker.is_stopped: break
                                await q.put((d, pt))

            prod_task = asyncio.create_task(producer())
            async def updater():
                while not tracker.is_stopped:
                    await update_live_status(status_msg, tracker, "⚡️ **Mxd Host Engine: Active**")
                    await asyncio.sleep(30.0) # Changed from 4.0 to 30.0
            upd_task = asyncio.create_task(updater())

            async with aiohttp.ClientSession() as session:
                workers = [asyncio.create_task(worker_host(q, session, res_file, tracker)) for _ in range(120)]
                await prod_task
                await q.join()
                for w in workers: w.cancel()
                upd_task.cancel()

            if tracker.is_stopped: await update_live_status(status_msg, tracker, "🛑 **Operation Terminated.**")
            else: await update_live_status(status_msg, tracker, "⚡️ **Operation Completed.**")
            
            if os.path.getsize(res_file) > 0:
                try: await message.reply_document(res_file, caption=f"✅ **Host Scan Complete.**\nValid Logs: {tracker.hits}")
                except Exception: pass
            else: await safe_reply_text(message, "❌ No valid live configurations found.")
            if os.path.exists(file_path): os.remove(file_path)
            if os.path.exists(res_file): os.remove(res_file)

        elif state == "tool_mcidr":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_mcidr_{user_id}.txt")
            res_file = os.path.join(DOWNLOAD_DIR, f"multi_cidr_{user_id}.txt")
            open(res_file, 'w').close()
            
            await safe_edit_text(status_msg, "⏳ **Analyzing CIDR Architecture...**")
            valid_cidrs = []
            total_hosts = 0
            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    c = line.strip()
                    if c:
                        try:
                            net = ipaddress.ip_network(c, strict=False)
                            valid_cidrs.append(net)
                            total_hosts += (net.num_addresses - 2) if net.num_addresses > 2 else 1
                        except Exception: pass
                        
            tracker = ProgressTracker(total_hosts) 
            USER_STATE[user_id]["tracker"] = tracker
            q = asyncio.Queue(maxsize=10000)

            async def producer():
                for net in valid_cidrs:
                    if tracker.is_stopped: break
                    for ip in net.hosts():
                        if tracker.is_stopped: break
                        await q.put((str(ip), "80"))

            prod_task = asyncio.create_task(producer())
            async def updater():
                while not tracker.is_stopped:
                    await update_live_status(status_msg, tracker, "⚡️ **Mxd Mapping Engine: Active**")
                    await asyncio.sleep(30.0) # Changed from 4.0 to 30.0
            upd_task = asyncio.create_task(updater())

            async with aiohttp.ClientSession() as session:
                workers = [asyncio.create_task(worker_cidr(q, session, res_file, tracker)) for _ in range(120)]
                await prod_task
                await q.join()
                for w in workers: w.cancel()
                upd_task.cancel()

            if tracker.is_stopped: await update_live_status(status_msg, tracker, "🛑 **Operation Terminated.**")
            else: await update_live_status(status_msg, tracker, "⚡️ **Operation Completed.**")
            
            if os.path.getsize(res_file) > 0:
                try: await message.reply_document(res_file, caption=f"✅ **Recon Data Exported.**\nHits: {tracker.hits}")
                except Exception: pass
            else: await safe_reply_text(message, "❌ Network mapping returned zero results.")
            if os.path.exists(file_path): os.remove(file_path)
            if os.path.exists(res_file): os.remove(res_file)

        elif state == "tool_split":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_split_{user_id}.txt")
            with open(file_path, 'r', errors='ignore') as f: lines = f.readlines()
            lines_per_chunk = 1000
            num_chunks = (len(lines) + lines_per_chunk - 1) // lines_per_chunk
            for i in range(num_chunks):
                chunk_file = os.path.join(DOWNLOAD_DIR, f"chunk_{user_id}_{i+1}.txt")
                with open(chunk_file, 'w') as cf: cf.writelines(lines[i * lines_per_chunk : (i+1) * lines_per_chunk])
                try: await message.reply_document(chunk_file, caption=f"📦 Volume {i+1}/{num_chunks}")
                except Exception: pass
                if os.path.exists(chunk_file): os.remove(chunk_file)
            if os.path.exists(file_path): os.remove(file_path)
            try: await status_msg.delete()
            except: pass

        elif state == "tool_clean":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_clean_{user_id}.txt")
            with open(file_path, 'r', errors='ignore') as f: domains = [l.strip().lower() for l in f if l.strip()]
            uniq = sorted(set(domains))
            res_file = os.path.join(DOWNLOAD_DIR, f"clean_{user_id}.txt")
            with open(res_file, 'w') as f:
                for d in uniq: f.write(d + "\n")
            try: await message.reply_document(res_file, caption=f"🧹 **Dataset Sanitized.**\nRetained Unique: {len(uniq)}")
            except Exception: pass
            if os.path.exists(file_path): os.remove(file_path)
            if os.path.exists(res_file): os.remove(res_file)
            try: await status_msg.delete()
            except: pass

        elif state == "tool_extract":
            file_path = await message.download(file_name=f"{DOWNLOAD_DIR}/input_extract_{user_id}.txt")
            with open(file_path, 'r', errors='ignore') as f: text_content = f.read()
            if os.path.exists(file_path): os.remove(file_path)
            domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
            domains = set(domain_pattern.findall(text_content))
            filtered = sorted({d.lower() for d in domains if len(d) > 4 and not d.startswith("www.") and not d.endswith(".com.com")})
            res_file = os.path.join(DOWNLOAD_DIR, f"extracted_{user_id}.txt")
            with open(res_file, 'w') as f:
                for d in filtered: f.write(d + "\n")
            try: await message.reply_document(res_file, caption=f"🎯 **Extraction Complete.**\nValid Elements: {len(filtered)}")
            except Exception: pass
            if os.path.exists(res_file): os.remove(res_file)
            try: await status_msg.delete()
            except: pass

    except Exception as e: await safe_reply_text(message, f"❌ **System Integrity Error:** {str(e)}")
    finally:
        try: await status_msg.delete()
        except: pass
        USER_STATE.pop(user_id, None)

if __name__ == "__main__":
    print("MxdNetwork Engine is Launching...")
    app.run()
