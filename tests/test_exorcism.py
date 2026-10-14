#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit and Integration Tests for Exorcism Subroutine Label Jump & Control Flow Normalization Engine.
Tests cover signature detection, trampoline jump chain flattening, opaque predicates,
subroutine inlining, control flow graph linearization, dead block pruning, dispatch trace emulation,
in-memory buffer sanitization, and end-to-end BatchDeobfuscator pipeline convergence.

Engineered by Maya Thorne.
"""

import unittest
import json
import tempfile
import os
from pathlib import Path

from deobfuscator.exorcism import (
    ExorcismNormalizer,
    normalize_exorcism,
    detect_exorcism_signatures,
    flatten_jump_trampolines,
    normalize_opaque_predicates,
    inline_subroutines,
    linearize_control_flow,
    prune_unreachable_blocks,
    emulate_exorcism_dispatch,
    export_exorcism_trace,
    zeroize_dict,
    zeroize_bytes,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script
from deobfuscator.cli import main as cli_main


class TestExorcismEngine(unittest.TestCase):
    """Test suite for Exorcism control flow normalization and jump resolution engine."""

    def test_detect_exorcism_signatures_positive(self):
        script = (
            "@echo off\n"
            "goto :tramp1\n"
            ":tramp1\n"
            "goto :tramp2\n"
            ":tramp2\n"
            "goto :worker\n"
            ":worker\n"
            "if 1==1 (call :sub1 argA argB)\n"
            "goto :tramp1 & call :worker\n"
            ":sub1\n"
            "echo %~1\n"
            "exit /b\n"
        )
        sig = detect_exorcism_signatures(script)
        self.assertTrue(sig["is_exorcism"])
        self.assertGreaterEqual(sig["confidence"], 0.5)
        self.assertIn("trampoline_chains", sig["indicators"])
        self.assertIn("opaque_predicates", sig["indicators"])
        self.assertIn("subroutine_calls", sig["indicators"])
        self.assertGreaterEqual(sig["goto_count"], 3)

    def test_detect_exorcism_signatures_negative(self):
        clean_script = (
            "@echo off\n"
            "echo Building artifacts...\n"
            "set BUILD_DIR=dist\n"
            "mkdir %BUILD_DIR%\n"
            "echo Done\n"
        )
        sig = detect_exorcism_signatures(clean_script)
        self.assertFalse(sig["is_exorcism"])
        self.assertEqual(sig["confidence"], 0.0)
        self.assertEqual(len(sig["indicators"]), 0)

    def test_flatten_jump_trampolines_simple(self):
        script = (
            "@echo off\n"
            "goto :hop1\n"
            ":hop1\n"
            "goto :real_target\n"
            ":real_target\n"
            "echo Payload Executed\n"
        )
        flattened, meta = flatten_jump_trampolines(script)
        self.assertGreater(meta["trampolines_collapsed"], 0)
        self.assertIn("goto :real_target", flattened)
        self.assertEqual(meta["trampoline_map"].get("hop1"), "real_target")

    def test_flatten_jump_trampolines_multihop_chain(self):
        script = (
            "call :step1\n"
            "goto :step1\n"
            ":step1\n"
            "goto :step2\n"
            ":step2\n"
            "goto :step3\n"
            ":step3\n"
            "goto :destination\n"
            ":destination\n"
            "echo Finished Multi-hop\n"
        )
        flattened, meta = flatten_jump_trampolines(script)
        self.assertGreaterEqual(meta["trampolines_collapsed"], 2)
        self.assertIn("goto :destination", flattened)
        self.assertIn("call :destination", flattened)
        self.assertEqual(meta["trampoline_map"].get("step1"), "destination")

    def test_flatten_jump_trampolines_cycle_detection(self):
        script = (
            ":cycleA\n"
            "goto :cycleB\n"
            ":cycleB\n"
            "goto :cycleA\n"
            "echo Stuck\n"
        )
        flattened, meta = flatten_jump_trampolines(script)
        # Should terminate safely without recursion or hang
        self.assertIsInstance(flattened, str)

    def test_normalize_opaque_predicates_always_true(self):
        script = (
            "if 1==1 echo ConditionTrue\n"
            "if 1 EQU 1 (echo MathEqual)\n"
            "if 5 GTR 2 echo Greater\n"
        )
        normalized, meta = normalize_opaque_predicates(script)
        self.assertEqual(meta["predicates_normalized"], 3)
        self.assertIn("echo ConditionTrue", normalized)
        self.assertIn("echo MathEqual", normalized)
        self.assertIn("echo Greater", normalized)
        self.assertNotIn("if 1==1", normalized)

    def test_normalize_opaque_predicates_always_false(self):
        script = (
            "if 1==0 echo DeadCode1\n"
            "if 0 EQU 1 (echo DeadCode2)\n"
            "if not 1==1 echo DeadCode3\n"
            "echo AliveCode\n"
        )
        normalized, meta = normalize_opaque_predicates(script)
        self.assertEqual(meta["predicates_normalized"], 3)
        self.assertNotIn("DeadCode1", normalized)
        self.assertNotIn("DeadCode2", normalized)
        self.assertNotIn("DeadCode3", normalized)
        self.assertIn("echo AliveCode", normalized)

    def test_normalize_opaque_predicates_with_else(self):
        script = (
            "if 1==0 (echo FalseBranch) else (echo TrueBranch)\n"
            "if 1==1 echo Win else echo Lose\n"
        )
        normalized, meta = normalize_opaque_predicates(script)
        self.assertEqual(meta["predicates_normalized"], 2)
        self.assertIn("echo TrueBranch", normalized)
        self.assertNotIn("echo FalseBranch", normalized)
        self.assertIn("echo Win", normalized)
        self.assertNotIn("echo Lose", normalized)

    def test_normalize_opaque_predicates_identical_strings(self):
        script = 'if "%MY_VAR%"=="%MY_VAR%" echo StringEquivalence\n'
        normalized, meta = normalize_opaque_predicates(script)
        self.assertEqual(meta["predicates_normalized"], 1)
        self.assertIn("echo StringEquivalence", normalized)

    def test_normalize_opaque_predicates_case_insensitive(self):
        script = 'if /i "ALPHA"=="alpha" echo CaseMatched\n'
        normalized, meta = normalize_opaque_predicates(script)
        self.assertEqual(meta["predicates_normalized"], 1)
        self.assertIn("echo CaseMatched", normalized)

    def test_inline_subroutines_leaf(self):
        script = (
            '@echo off\n'
            'call :print_banner "System Diagnostic" 2026\n'
            'echo Main Done\n'
            'exit /b 0\n'
            ':print_banner\n'
            'echo Title: %~1\n'
            'echo Year: %2\n'
            'echo All: %*\n'
            'goto :eof\n'
        )
        inlined, meta = inline_subroutines(script)
        self.assertEqual(meta["subroutines_inlined_count"], 1)
        self.assertIn("print_banner", meta["inlined_subroutines"])
        self.assertIn("echo Title: System Diagnostic", inlined)
        self.assertIn("echo Year: 2026", inlined)
        self.assertNotIn("goto :eof", inlined.split("echo Main Done")[0])

    def test_inline_subroutines_non_leaf_preserved(self):
        script = (
            '@echo off\n'
            'call :outer_sub\n'
            'exit /b\n'
            ':outer_sub\n'
            'call :inner_sub\n'
            'goto :eof\n'
            ':inner_sub\n'
            'echo Inside Inner\n'
            'goto :eof\n'
        )
        inlined, meta = inline_subroutines(script)
        # :outer_sub calls another sub, so outer_sub is not a leaf and shouldn't be inlined blindly
        self.assertIn(":outer_sub", inlined)

    def test_linearize_control_flow(self):
        # Scrambled block order: entry jumps to :phase1, :phase1 jumps to :phase2, :phase2 exits
        script = (
            '@echo off\n'
            'goto :phase1\n'
            ':phase2\n'
            'echo Phase Two\n'
            'exit /b\n'
            ':phase1\n'
            'echo Phase One\n'
            'goto :phase2\n'
        )
        linearized, meta = linearize_control_flow(script)
        self.assertGreater(meta["blocks_reordered_count"], 0)
        self.assertGreaterEqual(meta["fallthrough_gotos_removed"], 1)
        # Phase One should appear BEFORE Phase Two in the linearized stream
        idx_p1 = linearized.find("echo Phase One")
        idx_p2 = linearized.find("echo Phase Two")
        self.assertNotEqual(idx_p1, -1)
        self.assertNotEqual(idx_p2, -1)
        self.assertLess(idx_p1, idx_p2)

    def test_prune_unreachable_blocks(self):
        script = (
            '@echo off\n'
            'goto :entry_job\n'
            ':dead_decoy\n'
            'echo Evil Chaff Decoy\n'
            'exit /b\n'
            ':entry_job\n'
            'echo Real Work Done\n'
            'exit /b\n'
        )
        pruned, meta = prune_unreachable_blocks(script)
        self.assertEqual(meta["pruned_blocks_count"], 1)
        self.assertIn("dead_decoy", meta["pruned_labels"])
        self.assertNotIn("Evil Chaff Decoy", pruned)
        self.assertIn("Real Work Done", pruned)

    def test_emulate_exorcism_dispatch(self):
        script = (
            'echo Starting & curl -s https://example.com/payload.bin -o out.bin && certutil -hashfile out.bin SHA256\n'
        )
        events = emulate_exorcism_dispatch(script)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["command"], "echo")
        self.assertIsNone(events[0]["operator"])
        self.assertEqual(events[1]["command"], "curl")
        self.assertEqual(events[1]["operator"], "&")
        self.assertEqual(events[2]["command"], "certutil")
        self.assertEqual(events[2]["operator"], "&&")

    def test_export_exorcism_trace(self):
        events = [
            {"dispatch_id": 1, "operator": None, "command": "echo", "args": ["Test"], "raw_command": "echo Test"}
        ]
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            tf_path = tf.name

        try:
            json_str = export_exorcism_trace(events, tf_path)
            data = json.loads(json_str)
            self.assertEqual(data["version"], "1.11.0")
            self.assertEqual(data["engine"], "exorcism-dispatch-tracer")
            self.assertEqual(data["total_dispatches"], 1)
            self.assertEqual(len(data["events"]), 1)
            # Verify file on disk
            disk_data = json.loads(Path(tf_path).read_text(encoding="utf-8"))
            self.assertEqual(disk_data["version"], "1.11.0")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_zeroize_buffers(self):
        b = bytearray(b"SuperSecretPayload")
        zeroize_bytes(b)
        self.assertEqual(b, bytearray(len(b)))

        d = {"key1": "secret", "nested": {"k": "v"}, "arr": [1, 2, 3]}
        zeroize_dict(d)
        self.assertEqual(len(d), 0)

    def test_exorcism_normalizer_class(self):
        norm = ExorcismNormalizer()
        script = (
            "if 1==1 echo HelloExorcism\n"
        )
        res = norm.normalize(script)
        tele = norm.get_telemetry()
        self.assertIn("echo HelloExorcism", res)
        self.assertGreaterEqual(tele["predicates_normalized"], 1)

    def test_end_to_end_batch_deobfuscator_pipeline(self):
        # Obfuscated pattern: trampoline hop + opaque predicate + dead block
        script = (
            "@echo off\n"
            "goto :hopA\n"
            ":dead_chaff\n"
            "echo NeverReached\n"
            "exit /b\n"
            ":hopA\n"
            "goto :hopB\n"
            ":hopB\n"
            "goto :real_code\n"
            ":real_code\n"
            "if 1==1 echo Deobfuscated Successfully\n"
            "exit /b\n"
        )
        engine = BatchDeobfuscator(enable_exorcism=True)
        clean_text, meta = engine.deobfuscate(script)

        self.assertIn("Deobfuscated Successfully", clean_text)
        self.assertNotIn("NeverReached", clean_text)
        self.assertIn("exorcism_telemetry", meta)
        ext = meta["exorcism_telemetry"]
        self.assertTrue(ext["is_exorcism"])
        self.assertGreaterEqual(ext["trampolines_collapsed"], 1)
        self.assertGreaterEqual(ext["predicates_normalized"], 1)

    def test_cli_no_exorcism_flag(self):
        script = "if 1==0 echo DeadDecoy\n"
        with tempfile.NamedTemporaryFile("w+", suffix=".bat", delete=False) as tf:
            tf.write(script)
            tf.flush()
            in_path = tf.name

        out_path = in_path + ".out.bat"
        try:
            ret = cli_main([in_path, "-o", out_path, "--no-exorcism"])
            self.assertEqual(ret, 0)
            res = Path(out_path).read_text(encoding="utf-8")
            # With --no-exorcism, opaque predicate was not eliminated
            self.assertIn("if 1==0", res)
        finally:
            if os.path.exists(in_path): os.remove(in_path)
            if os.path.exists(out_path): os.remove(out_path)


if __name__ == "__main__":
    unittest.main()
