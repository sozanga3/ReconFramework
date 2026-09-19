import requests
from config.api_keys import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

# =========================================================
# 🔔 NOTIFICATION SYSTEM (TELEGRAM)
# =========================================================

def send_notification(message):
    """
    Sends a message to the Telegram bot if configured.
    Silently and safely skips if token or chat_id is missing.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }

    try:
        response = requests.post(url, data=payload, timeout=8)
        if response.status_code != 200:
            return False
        return True
    except Exception:
        return False


def notify_scan_start(domain):
    return send_notification(
        f"🚀 <b>Recon session started</b>\n"
        f"🎯 Target: <code>{domain}</code>"
    )


def notify_vuln_found(domain, vuln_count):
    return send_notification(
        f"🔥 <b>Vulnerability Found!</b>\n"
        f"🎯 Target: <code>{domain}</code>\n"
        f"⚠️ Findings: <code>{vuln_count}</code>"
    )


def notify_scan_complete(domain, stats):
    msg = (
        f"✅ <b>Recon Complete</b>\n"
        f"🎯 Target: <code>{domain}</code>\n\n"
        f"🔹 Subdomains: <code>{stats.get('subdomains', 0)}</code>\n"
        f"🔹 Alive: <code>{stats.get('alive', 0)}</code>\n"
        f"🔹 Open Ports: <code>{stats.get('ports', 0)}</code>\n"
        f"🔹 JS Files: <code>{stats.get('js_files', 0)}</code>\n"
        f"🔹 Endpoints: <code>{stats.get('endpoints', 0)}</code>\n"
        f"🔹 Discovered Params: <code>{stats.get('params', 0)}</code>\n"
        f"🔹 Nuclei Findings: <code>{stats.get('nuclei', 0)}</code>\n"
        f"🔹 Secrets: <code>{stats.get('secrets', 0)}</code>\n"
        f"🔹 Cloud Assets: <code>{stats.get('cloud_assets', 0)}</code>"
    )
    return send_notification(msg)

