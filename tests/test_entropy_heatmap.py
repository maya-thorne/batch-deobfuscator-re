"""
Unit Tests for Entropy Heatmap and Spatial Distribution Profiling.
Validates Shannon entropy calculations, sliding windows, line distribution,
color-gradient mapping, anomaly spike detection, and zeroize safety.
"""

import unittest
from deobfuscator.entropy_heatmap import (
    calculate_shannon_entropy,
    entropy_to_color,
    calculate_line_entropy,
    calculate_sliding_window_entropy,
    calculate_block_entropy,
    detect_entropy_anomalies,
    analyze_entropy_profile,
    zeroize_dict,
    zeroize_bytes,
)


class TestEntropyHeatmap(unittest.TestCase):
    def test_shannon_entropy_empty(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertEqual(calculate_shannon_entropy(b""), 0.0)
        self.assertEqual(calculate_shannon_entropy(bytearray()), 0.0)

    def test_shannon_entropy_uniform(self):
        self.assertEqual(calculate_shannon_entropy("AAAAAA"), 0.0)
        self.assertEqual(calculate_shannon_entropy(b"XXXXXXXX"), 0.0)

    def test_shannon_entropy_binary_alternating(self):
        # Two equally likely symbols has entropy exactly 1.0 bit
        ent = calculate_shannon_entropy("ABABABAB")
        self.assertEqual(ent, 1.0)

    def test_shannon_entropy_high_density(self):
        # Evenly distributed 64-symbol string has theoretical entropy of log2(64) = 6.0 bits
        high_entropy_str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/" * 4
        ent = calculate_shannon_entropy(high_entropy_str)
        self.assertEqual(ent, 6.0)
        self.assertGreater(ent, 5.0)

    def test_entropy_to_color_gradients(self):
        # Low entropy
        low = entropy_to_color(1.5)
        self.assertEqual(low["level"], "low")
        self.assertTrue(low["hex"].startswith("#"))
        self.assertIn("rgba", low)

        # Moderate entropy
        mod = entropy_to_color(3.5)
        self.assertEqual(mod["level"], "moderate")

        # High entropy
        high = entropy_to_color(4.8)
        self.assertEqual(high["level"], "high")

        # Critical entropy
        crit = entropy_to_color(5.8)
        self.assertEqual(crit["level"], "critical")

        # Clamping
        extreme = entropy_to_color(10.0, max_entropy=6.0)
        self.assertEqual(extreme["level"], "critical")
        self.assertEqual(extreme["ratio"], 1.0)

    def test_calculate_line_entropy(self):
        script = "@echo off\nset a=whoami\n%a%\necho done\n"
        lines = calculate_line_entropy(script)
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[0]["line"], 1)
        self.assertEqual(lines[0]["preview"], "@echo off")
        self.assertIn("entropy", lines[0])
        self.assertIn("hex", lines[0])
        self.assertIn("level", lines[0])

    def test_calculate_line_entropy_preview_truncation(self):
        long_line = "set " + "A" * 150 + "=val"
        lines = calculate_line_entropy(long_line, max_preview_len=50)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0]["preview"].endswith("..."))
        self.assertLessEqual(len(lines[0]["preview"]), 53)

    def test_calculate_sliding_window_entropy(self):
        text = "short"
        windows = calculate_sliding_window_entropy(text, window_size=32, step=16)
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]["offset"], 0)
        self.assertEqual(windows[0]["length"], 5)

        long_text = "A" * 50 + "B" * 50 + "C" * 50
        windows = calculate_sliding_window_entropy(long_text, window_size=32, step=16)
        self.assertGreater(len(windows), 5)
        self.assertEqual(windows[0]["offset"], 0)
        self.assertEqual(windows[1]["offset"], 16)

    def test_calculate_block_entropy(self):
        text = "echo test\n" * 20
        blocks = calculate_block_entropy(text, num_blocks=10)
        self.assertLessEqual(len(blocks), 10)
        self.assertGreater(len(blocks), 0)
        self.assertEqual(blocks[0]["start"], 0)
        self.assertEqual(blocks[-1]["end"], len(text))

    def test_detect_entropy_anomalies(self):
        # Normal low-entropy lines followed by an embedded high-entropy payload spike
        diverse_payload = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/" * 3
        script = (
            "@echo off\n"
            "echo starting\n"
            "set a=1\n"
            "set b=2\n"
            f"set payload={diverse_payload}\n"
            "echo finished\n"
        )
        line_entries = calculate_line_entropy(script)
        anomalies = detect_entropy_anomalies(line_entries, threshold_sigma=1.2)
        self.assertGreaterEqual(len(anomalies), 1)
        # Line 5 (payload) should be identified as anomaly
        payload_anomaly = [a for a in anomalies if a["line"] == 5]
        self.assertEqual(len(payload_anomaly), 1)
        self.assertIn("z_score", payload_anomaly[0])
        self.assertGreater(payload_anomaly[0]["entropy"], 5.0)

    def test_detect_entropy_anomalies_empty(self):
        self.assertEqual(detect_entropy_anomalies([]), [])

    def test_analyze_entropy_profile(self):
        raw = (
            "@echo off\n"
            "set a=c^m^d\n"
            "set b=/c w^h^o^a^m^i\n"
            "%a% %b%\n"
        )
        clean = "cmd /c whoami\n"
        profile = analyze_entropy_profile(raw, clean_script=clean, num_blocks=20)
        
        self.assertIn("global_entropy", profile)
        self.assertIn("lines", profile)
        self.assertIn("blocks", profile)
        self.assertIn("anomalies", profile)
        self.assertIn("clean_global_entropy", profile)
        self.assertIn("entropy_delta", profile)
        self.assertIn("entropy_reduction_pct", profile)
        self.assertEqual(profile["total_lines"], 4)
        self.assertEqual(profile["clean_total_lines"], 1)

    def test_zeroize_memory_primitives(self):
        buf = bytearray(b"super_secret_payload_key")
        zeroize_bytes(buf)
        self.assertEqual(buf, bytearray(len(buf)))

        nested = {
            "key": "sensitive",
            "buf": bytearray(b"another_secret"),
            "sub": {"deep_key": "deep_val"},
            "list": [{"item": "val"}, bytearray(b"list_buf")]
        }
        zeroize_dict(nested)
        self.assertEqual(len(nested), 0)

    def test_single_character_entropy(self):
        self.assertEqual(calculate_shannon_entropy("z"), 0.0)

    def test_spaces_only_entropy(self):
        self.assertEqual(calculate_shannon_entropy("     "), 0.0)

    def test_sliding_window_large_step(self):
        windows = calculate_sliding_window_entropy("short", window_size=10, step=20)
        self.assertEqual(len(windows), 1)

    def test_block_entropy_small_text(self):
        blocks = calculate_block_entropy("ab", num_blocks=50)
        self.assertGreater(len(blocks), 0)
        self.assertLessEqual(len(blocks), 2)

    def test_large_script_entropy_performance(self):
        large_script = ("@echo off\r\nset a=c^m^d\r\n%a% /c whoami\r\n" * 200)
        profile = analyze_entropy_profile(large_script, num_blocks=50)
        self.assertEqual(profile["total_lines"], 600)
        self.assertEqual(len(profile["blocks"]), 50)
        self.assertGreater(profile["global_entropy"], 2.0)

    def test_entropy_to_color_zero_max(self):
        res = entropy_to_color(3.0, max_entropy=0.0)
        self.assertEqual(res["level"], "low")
        self.assertEqual(res["ratio"], 0.0)

    def test_entropy_profile_without_clean_script(self):
        raw = "echo test\n"
        profile = analyze_entropy_profile(raw)
        self.assertNotIn("clean_global_entropy", profile)
        self.assertNotIn("entropy_delta", profile)
        self.assertEqual(profile["total_lines"], 1)


if __name__ == "__main__":
    unittest.main()
