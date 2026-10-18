"""
BatchStealer Static Forensic Credential Analyzer & C2 Extraction Engine.
Specialized forensic heuristics for identifying and extracting artifacts from
BatchStealer malware specimens, Discord token harvesters, info-stealers,
and credential-grabbing batch scripts:
  1. Automated Discord webhook and Telegram bot API token & C2 URL extraction.
  2. Targeted browser credential inventory (Chrome, Firefox, Opera, Edge, Brave, Vivaldi).
  3. Discord client token storage extraction (%appdata%\\discord\\Local Storage\\leveldb).
  4. Gaming, launcher & crypto-wallet credential targeting (Steam, Minecraft, Growtopia, osu!).
  5. System reconnaissance and network exfiltration command mapping (SystemInfo, tasklist, net user).
  6. Persistence mechanisms and dropped staging artifacts (SchTasks, Run keys, VBS runners).
  7. Exfiltration transmission channel analysis (curl multipart POST, PowerShell REST).
  8. Automated MITRE ATT&CK technique mapping.
  9. Safe defanging and caret normalization mode for malware researchers.
  10. Cryptographic memory zeroization (zeroize_dict, zeroize_bytes).

Engineered by Maya Thorne.
"""

import re
from typing import Dict, List, Tuple, Any, Optional, Set
from .normalizers import strip_carets


def zeroize_dict(target: Dict[str, Any]) -> None:
    """Cryptographically sanitize dictionary buffers in memory."""
    if not isinstance(target, dict):
        return
    try:
        for key in list(target.keys()):
            val = target[key]
            if isinstance(val, dict):
                zeroize_dict(val)
            elif isinstance(val, list):
                for i in range(len(val)):
                    if isinstance(val[i], dict):
                        zeroize_dict(val[i])
                    val[i] = None
                val.clear()
            elif isinstance(val, (bytearray, memoryview)):
                for i in range(len(val)):
                    val[i] = 0
            target[key] = None
        target.clear()
    except Exception:
        pass


def zeroize_bytes(buffer: bytearray) -> None:
    """Cryptographically zeroize raw bytearray buffers in memory."""
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0


# MITRE ATT&CK Mapping Table for BatchStealer Techniques
MITRE_ATTACK_MAPPINGS = {
    "browser_harvesting": {"id": "T1555.003", "name": "Credentials from Web Browsers", "tactic": "Credential Access"},
    "discord_tokens": {"id": "T1552.001", "name": "Credentials in Files: Discord Local Storage", "tactic": "Credential Access"},
    "gaming_crypto_targeting": {"id": "T1552.001", "name": "Credentials in Files: Game & Crypto Configs", "tactic": "Credential Access"},
    "system_reconnaissance": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    "network_reconnaissance": {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery"},
    "task_persistence": {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
    "registry_persistence": {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactic": "Persistence"},
    "hidden_files": {"id": "T1564.001", "name": "Hidden Files and Directories", "tactic": "Defense Evasion"},
    "self_deletion": {"id": "T1070.004", "name": "File Deletion", "tactic": "Defense Evasion"},
    "webhook_c2": {"id": "T1071.001", "name": "Web Protocols: Discord/Telegram Webhook Exfiltration", "tactic": "Command and Control"},
    "stager_download": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "obfuscation_carets": {"id": "T1027", "name": "Obfuscated Files or Information: Caret Masking", "tactic": "Defense Evasion"},
}



def detect_batchstealer_signatures(script_text: str) -> Dict[str, Any]:
    """
    Scan script text for signatures and heuristic patterns characteristic of BatchStealer,
    Discord token grabbers, and credential harvesters.
    """
    indicators: List[str] = []
    confidence = 0.0
    details: Dict[str, Any] = {}

    if not script_text:
        return {
            "is_batchstealer": False,
            "confidence": 0.0,
            "indicators": [],
            "details": {},
        }

    # Normalize carets for reliable signature scanning
    normalized_for_scan = strip_carets(script_text)
    lower_norm = normalized_for_scan.lower()

    # 1. Discord Webhook Detection
    discord_matches = re.findall(
        r'https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/([0-9]{15,22})/([a-zA-Z0-9_\-]{30,80})',
        normalized_for_scan,
        re.IGNORECASE,
    )
    if discord_matches:
        indicators.append("discord_webhook_c2")
        confidence += 0.45
        details["discord_webhooks_found"] = len(discord_matches)
    elif "discord.com/api/webhooks" in lower_norm or "discordapp.com/api/webhooks" in lower_norm:
        indicators.append("discord_webhook_endpoint_reference")
        confidence += 0.35

    # 2. Telegram Bot API Detection
    tg_matches = re.findall(
        r'https?://api\.telegram\.org/bot([0-9]{8,12}:[a-zA-Z0-9_\-]{30,50})/(?:sendmessage|senddocument|sendphoto)',
        normalized_for_scan,
        re.IGNORECASE,
    )
    if tg_matches:
        indicators.append("telegram_bot_c2")
        confidence += 0.45
        details["telegram_bots_found"] = len(tg_matches)
    elif "api.telegram.org/bot" in lower_norm:
        indicators.append("telegram_bot_endpoint_reference")
        confidence += 0.35

    # 3. Browser Credential & Session Theft Targets
    browser_keywords = [
        "google\\chrome", "opera software", "vivaldi", "mozilla\\firefox",
        "bravesoftware", "microsoft\\edge", "yandex\\yandexbrowser"
    ]
    browser_files = ["cookies", "login data", "key4.db", "key3.db", "logins.json", "local state", "web data"]
    found_browsers = [b for b in browser_keywords if b in lower_norm]
    found_b_files = [f for f in browser_files if f in lower_norm]

    if found_browsers and found_b_files:
        indicators.append("browser_credential_harvesting")
        confidence += 0.35
        details["targeted_browsers"] = found_browsers
        details["targeted_browser_files"] = found_b_files
    elif len(found_b_files) >= 2:
        indicators.append("browser_storage_targets")
        confidence += 0.20

    # 4. Discord Token Database Targeting
    if "discord\\local storage\\leveldb" in lower_norm or "discordcanary\\local storage" in lower_norm or ".ldb" in lower_norm and "discord" in lower_norm:
        indicators.append("discord_token_harvesting")
        confidence += 0.35

    # 5. Gaming & Crypto Wallet Targeting
    gaming_crypto_hits = []
    if "steam" in lower_norm and ("loginusers.vdf" in lower_norm or "ssfn" in lower_norm):
        gaming_crypto_hits.append("steam")
    if ".minecraft\\launcher_profiles.json" in lower_norm or ".minecraft\\launcher_accounts.json" in lower_norm:
        gaming_crypto_hits.append("minecraft")
    if "growtopia\\save.dat" in lower_norm:
        gaming_crypto_hits.append("growtopia")
    if "osu!." in lower_norm and ".cfg" in lower_norm:
        gaming_crypto_hits.append("osu")
    if any(w in lower_norm for w in ["exodus", "metamask", "atomic", "electrum", "binance"]):
        gaming_crypto_hits.append("crypto_wallets")

    if gaming_crypto_hits:
        indicators.append("gaming_crypto_targeting")
        confidence += 0.25
        details["gaming_crypto_targets"] = gaming_crypto_hits

    # 6. System Reconnaissance Exfiltration
    recon_commands = []
    for cmd in ["systeminfo", "tasklist", "net user", "quser", "ipconfig /all", "cmdkey /list", "api.ipify.org"]:
        if cmd in lower_norm:
            recon_commands.append(cmd)
    if len(recon_commands) >= 1:
        indicators.append("system_reconnaissance")
        confidence += 0.20
        details["recon_commands"] = recon_commands

    # 7. Persistence & Dropper Mechanics
    persistence_hits = []
    if "schtasks" in lower_norm and "/create" in lower_norm:
        persistence_hits.append("scheduled_task")
    if "currentversion\\run" in lower_norm and ("reg " in lower_norm or "reg.exe" in lower_norm):
        persistence_hits.append("registry_run_key")
    if "wscript.shell" in lower_norm and "run" in lower_norm:
        persistence_hits.append("vbs_hidden_runner")
    if persistence_hits:
        indicators.append("persistence_installation")
        confidence += 0.20
        details["persistence_methods"] = persistence_hits

    # 8. Defense Evasion & Self-Deletion
    evasion_hits = []
    if "attrib" in lower_norm and "+h" in lower_norm:
        evasion_hits.append("hidden_attributes")
    if re.search(r'del\s+["\']?(?:%~f0|%0)["\']?', normalized_for_scan, re.IGNORECASE):
        evasion_hits.append("self_deletion")
    if "goto remove_this_if_you_agree" in lower_norm or "the author is not responsible" in lower_norm:
        evasion_hits.append("fake_disclaimer_anti_triage")
    if evasion_hits:
        indicators.append("defense_evasion")
        confidence += 0.15
        details["evasion_methods"] = evasion_hits

    # 9. Caret Escaping On Commands
    caret_pattern = re.search(r'\b(?:c\^u\^r\^l|t\^a\^s\^k\^l\^i\^s\^t|w\^e\^b\^h\^o\^o\^k|d\^i\^s\^c\^o\^r\^d)\b', script_text, re.IGNORECASE)
    if caret_pattern:
        indicators.append("stealer_caret_masking")
        confidence += 0.20

    # Clamp confidence
    confidence = min(round(confidence, 3), 1.0)
    is_batchstealer = (confidence >= 0.35) or (len(indicators) >= 2 and confidence >= 0.25)

    return {
        "is_batchstealer": is_batchstealer,
        "confidence": confidence,
        "indicators": indicators,
        "details": details,
    }


def extract_c2_endpoints(script_text: str) -> Dict[str, Any]:
    """
    Extract Discord Webhooks, Telegram Bot APIs, payload download links,
    and external C2 server URLs from script text.
    """
    normalized = strip_carets(script_text)
    endpoints: Dict[str, Any] = {
        "discord_webhooks": [],
        "telegram_bots": [],
        "download_urls": [],
        "recon_services": [],
        "generic_c2": [],
    }

    # 1. Discord Webhooks
    for m in re.finditer(
        r'https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/([0-9]{15,22})/([a-zA-Z0-9_\-]{30,80})',
        normalized,
        re.IGNORECASE,
    ):
        full_url = m.group(0)
        wh_id = m.group(1)
        wh_token = m.group(2)
        defanged = full_url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
        entry = {
            "url": full_url,
            "webhook_id": wh_id,
            "webhook_token": wh_token,
            "defanged_url": defanged,
        }
        if entry not in endpoints["discord_webhooks"]:
            endpoints["discord_webhooks"].append(entry)

    # 2. Telegram Bot Endpoints
    for m in re.finditer(
        r'https?://api\.telegram\.org/bot([0-9]{8,12}:[a-zA-Z0-9_\-]{30,50})/(?:sendmessage|senddocument|sendphoto)',
        normalized,
        re.IGNORECASE,
    ):
        full_url = m.group(0)
        bot_token = m.group(1)
        defanged = full_url.replace("https://", "hxxps://").replace(".", "[.]")
        entry = {
            "url": full_url,
            "bot_token": bot_token,
            "defanged_url": defanged,
        }
        if entry not in endpoints["telegram_bots"]:
            endpoints["telegram_bots"].append(entry)

    # 3. Payload and Drop Download URLs
    for m in re.finditer(
        r'https?://[^\s"\'\<\>\^]+\.(?:exe|dll|bat|vbs|ps1|zip|rar|tar|bin|dat)(?:\?[^\s"\'\<\>\^]*)?',
        normalized,
        re.IGNORECASE,
    ):
        url = m.group(0)
        if url not in endpoints["download_urls"]:
            endpoints["download_urls"].append(url)

    # Also detect updater URLs (e.g., set "updateurl=...")
    for m in re.finditer(r'set\s+["\']?updateurl=([^"\'\r\n\^]+)', normalized, re.IGNORECASE):
        u = m.group(1).strip()
        if u.startswith("http") and u not in endpoints["download_urls"]:
            endpoints["download_urls"].append(u)

    # 4. Recon Services
    recon_domains = ["api.ipify.org", "ipinfo.io", "checkip.amazonaws.com", "icanhazip.com", "wtfismyip.com"]
    for m in re.finditer(r'https?://(?:[a-zA-Z0-9_\-\.]+\.)?(?:ipify\.org|ipinfo\.io|amazonaws\.com|icanhazip\.com)[^\s"\'\<\>\^]*', normalized, re.IGNORECASE):
        url = m.group(0)
        if url not in endpoints["recon_services"]:
            endpoints["recon_services"].append(url)

    # Standalone command lookups (e.g. Invoke-RestMethod api.ipify.org)
    for rd in recon_domains:
        if rd in normalized.lower() and not any(rd in u for u in endpoints["recon_services"]):
            endpoints["recon_services"].append(f"http://{rd}")

    # 5. Generic External URLs in curl or powershell
    for m in re.finditer(r'https?://[a-zA-Z0-9_\-\.\:\@]+(?:/[^\s"\'\<\>\^]*)?', normalized):
        url = m.group(0)
        # Filter out already categorized
        if any(url in str(wh.get("url", "")) for wh in endpoints["discord_webhooks"]):
            continue
        if any(url in str(tg.get("url", "")) for tg in endpoints["telegram_bots"]):
            continue
        if url in endpoints["download_urls"] or url in endpoints["recon_services"]:
            continue
        if url not in endpoints["generic_c2"]:
            endpoints["generic_c2"].append(url)

    return endpoints


def inventory_targeted_credentials(script_text: str) -> Dict[str, Any]:
    """
    Perform a complete forensic inventory of all credentials, files, session databases,
    and system reconnaissance outputs targeted by the batch script.
    """
    normalized = strip_carets(script_text)
    lower_norm = normalized.lower()

    inventory: Dict[str, Any] = {
        "browsers": [],
        "messaging": [],
        "gaming": [],
        "crypto": [],
        "system_recon": [],
    }

    # Browser Artifacts
    browser_defs = [
        ("Google Chrome", r'(?:google\\chrome|chromium)[^\r\n"\'\^]*\\(?:cookies|login data|history|shortcuts|bookmarks|local state)'),
        ("Opera / Opera GX", r'opera software[^\r\n"\'\^]*\\(?:cookies|login data|history|shortcuts|bookmarks)'),
        ("Vivaldi", r'vivaldi[^\r\n"\'\^]*\\(?:cookies|login data|history|shortcuts|bookmarks)'),
        ("Mozilla Firefox", r'mozilla\\firefox[^\r\n"\'\^]*\\(?:key[34]\.db|logins\.json|cookies\.sqlite)'),
        ("Microsoft Edge", r'microsoft\\edge[^\r\n"\'\^]*\\(?:cookies|login data|history|local state)'),
        ("Brave", r'bravesoftware[^\r\n"\'\^]*\\(?:cookies|login data|history|local state)'),
    ]

    for bname, pat in browser_defs:
        matches = re.findall(pat, normalized, re.IGNORECASE)
        if matches:
            inventory["browsers"].append({
                "browser": bname,
                "targets": list(set(matches)),
            })

    # Messaging: Discord & Telegram
    if "discord\\local storage\\leveldb" in lower_norm or ".ldb" in lower_norm:
        inventory["messaging"].append({
            "client": "Discord",
            "target": "Local Storage leveldb (*.ldb tokens)",
            "paths": [r"%appdata%\discord\Local Storage\leveldb"],
        })
    if "discordcanary" in lower_norm:
        inventory["messaging"].append({
            "client": "Discord Canary",
            "target": "Local Storage leveldb (*.ldb tokens)",
            "paths": [r"%appdata%\discordcanary\Local Storage\leveldb"],
        })

    # Gaming targets
    if "steam" in lower_norm:
        steam_targets = []
        if "loginusers.vdf" in lower_norm:
            steam_targets.append("loginusers.vdf (Steam login user config)")
        if "ssfn" in lower_norm:
            steam_targets.append("ssfn* (Steam Guard 2FA auth files)")
        if steam_targets:
            inventory["gaming"].append({"platform": "Steam", "artifacts": steam_targets})

    if "minecraft" in lower_norm and ("launcher_profiles.json" in lower_norm or "launcher_accounts.json" in lower_norm):
        inventory["gaming"].append({
            "platform": "Minecraft",
            "artifacts": ["launcher_profiles.json", "launcher_accounts.json"],
        })

    if "growtopia\\save.dat" in lower_norm:
        inventory["gaming"].append({
            "platform": "Growtopia",
            "artifacts": ["save.dat (Account credentials & world data)"],
        })

    if "osu!" in lower_norm and ".cfg" in lower_norm:
        inventory["gaming"].append({
            "platform": "osu!",
            "artifacts": ["osu!.<username>.cfg (Player config & hashed credentials)"],
        })

    # System Recon Targets
    recon_patterns = [
        ("SystemInfo", r'systeminfo\s*>\s*["\']?([^"\'\r\n\^&]+)["\']?'),
        ("tasklist", r'tasklist\s*>\s*["\']?([^"\'\r\n\^&]+)["\']?'),
        ("net user", r'net\s+user\s*>\s*["\']?([^"\'\r\n\^&]+)["\']?'),
        ("quser", r'quser\s*>\s*["\']?([^"\'\r\n\^&]+)["\']?'),
        ("reg query startup", r'reg\s+query[^\r\n"\'\^&]*\\run\s*>>?\s*["\']?([^"\'\r\n\^&]+)["\']?'),
        ("cmdkey list", r'cmdkey\s+/list\s*>\s*["\']?([^"\'\r\n\^&]+)["\']?'),
        ("ipconfig all", r'ipconfig\s+/all\s*>\s*["\']?([^"\'\r\n\^&]+)["\']?'),
    ]

    for desc, pat in recon_patterns:
        m = re.search(pat, normalized, re.IGNORECASE)
        if m:
            inventory["system_recon"].append({
                "activity": desc,
                "staged_file": m.group(1).strip(),
            })
        elif desc.lower() in lower_norm:
            inventory["system_recon"].append({
                "activity": desc,
                "staged_file": "inline / console pipe",
            })

    return inventory


def extract_persistence_and_droppers(script_text: str) -> Dict[str, Any]:
    """
    Forensically identify persistence schedules, registry run keys,
    hidden VBS runners, and dropped secondary executables.
    """
    normalized = strip_carets(script_text)
    lower_norm = normalized.lower()

    persistence_info: Dict[str, Any] = {
        "scheduled_tasks": [],
        "registry_run_keys": [],
        "dropped_files": [],
        "vbs_runners": [],
        "self_deletion": False,
        "self_deletion_command": None,
    }

    # Collect simple set assignments for variable resolution
    local_vars: Dict[str, str] = {}
    for m in re.finditer(r'set\s+["\']?([a-zA-Z0-9_\-]+)=([^"\'\r\n\^]+)', normalized, re.IGNORECASE):
        vname = m.group(1).strip().lower()
        vval = m.group(2).strip()
        local_vars[vname] = vval

    # 1. Scheduled Tasks
    task_match = re.search(
        r'schtasks\s+/create\s+(?:/[a-zA-Z0-9_\-]+\s+)*(?:/tn\s+["\']?([^"\'\r\n\^]+)["\']?|/tr\s+["\']?([^"\'\r\n\^]+)["\']?|/sc\s+([a-zA-Z0-9_\-]+))+',
        normalized,
        re.IGNORECASE,
    )
    if task_match or "schtasks /create" in lower_norm:
        task_entry: Dict[str, Any] = {"detected": True}
        tn_m = re.search(r'/tn\s+["\']?([^"\'\r\n\^/]+)["\']?', normalized, re.IGNORECASE)
        tr_m = re.search(r'/tr\s+["\']?([^"\'\r\n\^/]+)["\']?', normalized, re.IGNORECASE)
        sc_m = re.search(r'/sc\s+([a-zA-Z0-9_\-%]+)', normalized, re.IGNORECASE)
        if tn_m:
            raw_tn = tn_m.group(1).strip().strip('"\'%')
            task_entry["task_name"] = local_vars.get(raw_tn.lower(), tn_m.group(1).strip().strip('"\''))
        if tr_m:
            raw_tr = tr_m.group(1).strip().strip('"\'')
            for vk, vv in local_vars.items():
                raw_tr = re.sub(rf'%{vk}%', lambda _: vv, raw_tr, flags=re.IGNORECASE)
            task_entry["task_target"] = raw_tr
        if sc_m:
            raw_sc = sc_m.group(1).strip().strip('"\'%')
            task_entry["frequency"] = local_vars.get(raw_sc.lower(), sc_m.group(1).strip().strip('"\''))
        persistence_info["scheduled_tasks"].append(task_entry)

    # 2. Registry Run Keys
    if "currentversion\\run" in lower_norm:
        persistence_info["registry_run_keys"].append({
            "key_path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "access": "query/add",
        })

    # 3. Dropped Files
    dropped_candidates = re.findall(
        r'(?:copy|echo[^\r\n>]*>|ren\s+[^\r\n]+\s+)(["\']?[a-zA-Z0-9_\-\.\:\%\\]+\.(?:bat|vbs|exe|png|txt|dat)["\']?)',
        normalized,
        re.IGNORECASE,
    )
    for c in dropped_candidates:
        clean_c = c.strip('"\' ')
        if clean_c and clean_c not in persistence_info["dropped_files"]:
            persistence_info["dropped_files"].append(clean_c)

    # 4. VBS Execution Wrappers
    if "wscript.shell" in lower_norm:
        persistence_info["vbs_runners"].append({
            "progid": "WScript.Shell",
            "hidden_window": ", 0, true" in lower_norm or ", 0, false" in lower_norm,
        })

    # 5. Self Deletion
    del_match = re.search(r'(?:start\s+/b\s+["\']?["\']?\s+cmd\s+/c\s+)?(?:2>NUL\s+)?del\s+["\']?(%~f0|%0)["\']?', normalized, re.IGNORECASE)
    if del_match:
        persistence_info["self_deletion"] = True
        persistence_info["self_deletion_command"] = del_match.group(0).strip()

    return persistence_info


def analyze_exfiltration_channels(script_text: str) -> List[Dict[str, Any]]:
    """
    Extract all exfiltration channels, HTTP method invocations,
    and mapped multi-part file attachments (e.g. curl -F tasks=@..., -F c=@...).
    """
    normalized = strip_carets(script_text)
    channels: List[Dict[str, Any]] = []

    # curl multipart uploads (-F field=@path)
    for m in re.finditer(r'curl[^\r\n&]*?-F\s+([a-zA-Z0-9_\-\.]+)=@["\']?([^"\'\r\n\s]+)["\']?(?:[^\r\n&]*?([%a-zA-Z0-9_\-\:\/\.\?]+))?', normalized, re.IGNORECASE):
        field_name = m.group(1)
        attached_path = m.group(2)
        target_dest = m.group(3) if m.group(3) else "%webhook%"
        channels.append({
            "tool": "curl",
            "method": "multipart/form-data POST",
            "form_field": field_name,
            "attached_file": attached_path,
            "target": target_dest,
        })

    # curl JSON POST (--data "{\"content\": ...}")
    for m in re.finditer(r'curl[^\r\n&]*?-X\s+POST[^\r\n&]*?--data\s+["\'](.*?)["\']\s+([%a-zA-Z0-9_\-\:\/\.\?]+)', normalized, re.IGNORECASE):
        json_body = m.group(1)
        target_dest = m.group(2)
        channels.append({
            "tool": "curl",
            "method": "application/json POST",
            "data_snippet": json_body[:60] + ("..." if len(json_body) > 60 else ""),
            "target": target_dest,
        })

    return channels


def extract_batchstealer_forensics(script_text: str) -> Dict[str, Any]:
    """
    Generate an exhaustive, structured forensic intelligence report for
    BatchStealer and related info-stealer malware samples.
    """
    sig = detect_batchstealer_signatures(script_text)
    endpoints = extract_c2_endpoints(script_text)
    inventory = inventory_targeted_credentials(script_text)
    persistence = extract_persistence_and_droppers(script_text)
    channels = analyze_exfiltration_channels(script_text)

    # MITRE ATT&CK Mapping
    mitre_list: List[Dict[str, str]] = []
    if inventory["browsers"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["browser_harvesting"]))
    if inventory["messaging"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["discord_tokens"]))
    if inventory["gaming"] or inventory["crypto"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["gaming_crypto_targeting"]))
    if inventory["system_recon"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["system_reconnaissance"]))
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["network_reconnaissance"]))
    if persistence["scheduled_tasks"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["task_persistence"]))
    if persistence["registry_run_keys"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["registry_persistence"]))
    if persistence.get("self_deletion"):
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["self_deletion"]))
    if endpoints["discord_webhooks"] or endpoints["telegram_bots"] or endpoints["generic_c2"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["webhook_c2"]))
    if endpoints["download_urls"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["stager_download"]))
    if "stealer_caret_masking" in sig["indicators"]:
        mitre_list.append(dict(MITRE_ATTACK_MAPPINGS["obfuscation_carets"]))

    # Unique MITRE list by ID
    seen_ids = set()
    unique_mitre = []
    for item in mitre_list:
        if item["id"] not in seen_ids:
            seen_ids.add(item["id"])
            unique_mitre.append(item)

    report = {
        "signatures": sig,
        "is_batchstealer": sig["is_batchstealer"],
        "confidence": sig["confidence"],
        "indicators": sig["indicators"],
        "endpoints": endpoints,
        "inventory": inventory,
        "persistence": persistence,
        "exfiltration_channels": channels,
        "mitre_attack": unique_mitre,
        "extracted_discord_webhooks_count": len(endpoints["discord_webhooks"]),
        "extracted_telegram_bots_count": len(endpoints["telegram_bots"]),
        "extracted_download_urls_count": len(endpoints["download_urls"]),
        "targeted_browsers_count": len(inventory["browsers"]),
        "targeted_gaming_platforms_count": len(inventory["gaming"]),
    }
    return report


def normalize_batchstealer(
    script_text: str,
    defang_c2: bool = False,
    custom_env: Optional[Dict[str, str]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Deobfuscate BatchStealer command chains, caret masking, and anti-triage headers.
    When defang_c2=True, active Discord/Telegram C2 endpoints are replaced with harmless
    defanged strings and annotated with forensic safety markers.
    """
    report = extract_batchstealer_forensics(script_text)
    if not report["is_batchstealer"] and not defang_c2:
        return script_text, report

    lines = script_text.splitlines()
    normalized_lines: List[str] = []

    for line in lines:
        stripped_line = line.strip()

        # 1. Neutralize anti-triage fake TOS disclaimer jumps
        if re.search(r'^goto\s+remove_this_if_you_agree_to_follow_the_TOS\b', stripped_line, re.IGNORECASE):
            normalized_lines.append(":: [NORMALIZED] Removed fake TOS anti-triage jump")
            continue
        if re.search(r'^:remove_this_if_you_agree_to_follow_the_TOS\b', stripped_line, re.IGNORECASE):
            normalized_lines.append(":: [NORMALIZED] Removed fake TOS trap label")
            continue

        # 2. Normalize Caret Masking on Commands
        norm_line = line
        if "^" in norm_line:
            # Preserve multiline line continuations (lines ending in ^ or =^)
            if not stripped_line.endswith("^"):
                norm_line = strip_carets(norm_line)

        # 3. Defang C2 Webhooks and Exfiltration if requested
        if defang_c2:
            # Defang Discord Webhooks
            norm_line = re.sub(
                r'https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/([0-9]{15,22})/([a-zA-Z0-9_\-]{30,80})',
                r'hxxps://discord[.]com/api/webhooks/\1/[DEFANGED_TOKEN]',
                norm_line,
                flags=re.IGNORECASE,
            )
            # Defang Telegram Bot APIs
            norm_line = re.sub(
                r'https?://api\.telegram\.org/bot([0-9]{8,12}:[a-zA-Z0-9_\-]{30,50})/',
                r'hxxps://api[.]telegram[.]org/bot[DEFANGED_BOT_TOKEN]/',
                norm_line,
                flags=re.IGNORECASE,
            )

        normalized_lines.append(norm_line)

    clean_script = "\n".join(normalized_lines)
    return clean_script, report


class BatchStealerNormalizer:
    """Object-oriented normalizer wrapper for BatchStealer static forensic analysis."""

    def __init__(self, defang_c2: bool = False, custom_env: Optional[Dict[str, str]] = None):
        self.defang_c2 = defang_c2
        self.custom_env = custom_env or {}
        self.last_report: Dict[str, Any] = {}

    def normalize(self, script_text: str) -> Tuple[str, Dict[str, Any]]:
        clean_text, report = normalize_batchstealer(
            script_text, defang_c2=self.defang_c2, custom_env=self.custom_env
        )
        self.last_report = report
        return clean_text, report

    def extract_report(self, script_text: str) -> Dict[str, Any]:
        return extract_batchstealer_forensics(script_text)

    def zeroize(self) -> None:
        """Wipe internal report caches and state from memory."""
        zeroize_dict(self.last_report)
        zeroize_dict(self.custom_env)
