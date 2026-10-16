"""
Unit and Integration Tests for simple-batch-obfuscator Deobfuscator Module.
Covers character-level random variable fragment infiltration, delayed execution string
normalization, dynamic set alias resolution, statement dispatch unmasking, chunk reassembly,
Base64 UTF-16LE stager decoding, advanced undefined variable noise preprocessing,
memory zeroization, and full engine pipeline integration.
"""

import unittest
from pathlib import Path
from deobfuscator.simple_obfuscator import (
    detect_simple_obfuscator_signatures,
    normalize_delayed_execution_string,
    resolve_dynamic_set_aliases,
    strip_undefined_variable_noise,
    extract_and_assemble_chunks,
    normalize_simple_obfuscator,
    SimpleObfuscatorNormalizer,
    zeroize_dict,
    zeroize_bytes,
)
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script, deobfuscate_bytes


class TestSimpleObfuscator(unittest.TestCase):
    """Test suite for simple-batch-obfuscator deobfuscator and undefined variable noise preprocessor."""

    def test_detect_signatures_clean_script(self):
        clean = "@echo off\necho Normal operation\npause\n"
        sig = detect_simple_obfuscator_signatures(clean)
        self.assertFalse(sig["is_simple_obfuscator"])
        self.assertLess(sig["confidence"], 0.25)
        self.assertEqual(len(sig["indicators"]), 0)

    def test_detect_signatures_obfuscated_script(self):
        obfuscated = (
            "@echo off\n"
            "%r1%s%r2%e%r3%t%r4%l%r5%o%r6%c%r7%a%r8%l%r9% %r10%e%r11%n%r12%a%r13%b%r14%l%r15%e%r16%d\n"
            'set "v1=s"\n'
            'set "v2=t"\n'
            'set "alias=!v1!e!v2!"\n'
            '!alias! "c1=pow"\n'
            '!alias! "c2=ersh"\n'
            '!alias! "c3=ell"\n'
            '!alias! "c4= -c "\n'
            '!alias! "c5=whoami"\n'
            "%c1%%c2%%c3%%c4%%c5%\n"
        )
        sig = detect_simple_obfuscator_signatures(obfuscated)
        self.assertTrue(sig["is_simple_obfuscator"])
        self.assertGreaterEqual(sig["confidence"], 0.50)
        self.assertIn("character_level_variable_infiltration", sig["indicators"])
        self.assertIn("dynamic_set_keyword_synthesis", sig["indicators"])

    def test_normalize_delayed_execution_string(self):
        obf_line = (
            "%RoGL%s%DqNc%e%AzOu%t%qBVr%l%QKNL%o%rWAU%c%oSfp%a%qIhF%l%nWHx% %WWxl%"
            "e%AyeF%n%JQyM%a%bmOi%b%aqkx%l%eYGr%e%yGXP%d%JKvg%e%Wglh%l%SqcJ%a%VrfD%y%yhFx%e%eAVX%d%"
            "bvJB%e%WCCz%x%QnLP%p%afiu%a%RmHu%n%kOXk%s%mEzT%i%IPSi%o%eOLK%n%RqSi%"
        )
        res, mod = normalize_delayed_execution_string(obf_line)
        self.assertTrue(mod)
        self.assertEqual(res.strip(), "setlocal enabledelayedexpansion")

        clean_line = "echo hello world"
        res_clean, mod_clean = normalize_delayed_execution_string(clean_line)
        self.assertFalse(mod_clean)
        self.assertEqual(res_clean, clean_line)

    def test_resolve_dynamic_set_aliases(self):
        script = (
            'set "var_s=s"\n'
            'set "var_t=t"\n'
            'set "cmd_set=!var_s!e!var_t!"\n'
            '!cmd_set! "chunk1=calc"\n'
            '!cmd_set! "chunk2=.exe"\n'
        )
        res, aliases = resolve_dynamic_set_aliases(script)
        self.assertIn("cmd_set", aliases)
        self.assertIn('set "chunk1=calc"', res)
        self.assertIn('set "chunk2=.exe"', res)
        self.assertNotIn("!cmd_set!", res)

    def test_strip_undefined_variable_noise_character_infiltration(self):
        # Interleaved undefined variables inside word tokens
        line = "%RAND_A%p%RAND_B%o%RAND_C%w%RAND_D%e%RAND_E%r%RAND_F%s%RAND_G%h%RAND_H%e%RAND_I%l%RAND_J%l%RAND_K% -NoProfile"
        res, stripped = strip_undefined_variable_noise(line)
        self.assertEqual(res.strip(), "powershell -NoProfile")
        self.assertGreaterEqual(len(stripped), 10)

    def test_strip_undefined_variable_noise_preserves_legitimate_vars(self):
        script = (
            'set "MY_VAR=C:\\Test\\Path"\n'
            'echo %MY_VAR% %RAND_NOISE% %COMSPEC% %ERRORLEVEL% %~dp0 %%i\n'
        )
        res, stripped = strip_undefined_variable_noise(script)
        self.assertIn("%MY_VAR%", res)
        self.assertIn("%COMSPEC%", res)
        self.assertIn("%ERRORLEVEL%", res)
        self.assertIn("%~dp0", res)
        self.assertIn("%%i", res)
        self.assertNotIn("%RAND_NOISE%", res)
        self.assertIn("RAND_NOISE", stripped)

    def test_extract_and_assemble_chunks(self):
        script = (
            '@echo off\n'
            'set "c3=whoami"\n'
            'set "c1=cmd.exe "\n'
            'set "c2=/c "\n'
            '%c1%%c2%%c3%\n'
        )
        clean_text, chunk_map, count, assembled_cmd, decoded_ps = extract_and_assemble_chunks(
            script, aliases=set()
        )
        self.assertEqual(count, 3)
        self.assertEqual(assembled_cmd, "cmd.exe /c whoami")
        self.assertIn("cmd.exe /c whoami", clean_text)
        self.assertNotIn('set "c3=whoami"', clean_text)

    def test_powershell_b64_stager_decoding(self):
        # "Write-Output 'PWN_VERIFIED'" encoded in Base64 UTF-16LE
        raw_ps = "Write-Output 'PWN_VERIFIED'"
        b64_payload = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFAAVwBOAF8AVgBFAFIASQBGAEkARQBEACcA"
        script = (
            '@echo off\n'
            'set "p1=powershell.exe -NoProfile "\n'
            f'set "p2=-EncodedCommand {b64_payload}"\n'
            'set "p3="\n'
            '%p1%%p2%%p3%\n'
        )
        clean_text, meta = normalize_simple_obfuscator(script)
        self.assertIsNotNone(meta["decoded_powershell"])
        self.assertIn("PWN_VERIFIED", meta["decoded_powershell"])
        self.assertIn("powershell.exe -NoProfile -EncodedCommand", clean_text)

    def test_corpus_14_parity(self):
        corpus_14_script = '%RAND_A%p%RAND_B%o%RAND_C%w%RAND_D%e%RAND_E%r%RAND_F%s%RAND_G%h%RAND_H%e%RAND_I%l%RAND_J%l%RAND_K% -NoProfile -c "echo PSS_OK"'
        clean_text = deobfuscate_script(corpus_14_script, enable_simple_obfuscator=True)
        self.assertEqual(clean_text.strip(), 'powershell -NoProfile -c "echo PSS_OK"')

    def test_david_niessen_full_readme_sample(self):
        readme_path = Path("references/github_arsenal/simple-batch-obfuscator-DavidNiessen/README.md")
        if not readme_path.exists():
            self.skipTest("Reference README not found")

        text = readme_path.read_text(encoding="utf-8")
        start = text.find("@echo off")
        end = text.find("```", start)
        sample = text[start:end]

        clean_text, meta = normalize_simple_obfuscator(sample)
        self.assertTrue(meta["is_simple_obfuscator"])
        self.assertGreater(meta["chunks_assembled_count"], 150)
        self.assertIsNotNone(meta["assembled_command"])
        self.assertIn("powershell.exe -EncodedCommand", meta["assembled_command"])
        self.assertIsNotNone(meta["decoded_powershell"])
        self.assertIn("[Math]::Sin", meta["decoded_powershell"])
        self.assertIn("SetCursorPosition", meta["decoded_powershell"])

    def test_zeroize_memory(self):
        secrets = {"chunk_key": "sensitive_script_data", "arr": [1, 2, 3]}
        zeroize_dict(secrets)
        self.assertEqual(len(secrets), 0)

        buf = bytearray(b"cryptographic_key_buffer")
        zeroize_bytes(buf)
        self.assertTrue(all(b == 0 for b in buf))

        with SimpleObfuscatorNormalizer(custom_env={"temp_var": "sensitive"}) as norm:
            self.assertEqual(len(norm.custom_env), 1)
        self.assertEqual(len(norm.custom_env), 0)

    def test_batch_deobfuscator_e2e_pipeline(self):
        script = (
            "@echo off\n"
            "%RoGL%s%DqNc%e%AzOu%t%qBVr%l%QKNL%o%rWAU%c%oSfp%a%qIhF%l%nWHx% %WWxl%"
            "e%AyeF%n%JQyM%a%bmOi%b%aqkx%l%eYGr%e%yGXP%d%JKvg%e%Wglh%l%SqcJ%a%VrfD%y%yhFx%e%eAVX%d%"
            "bvJB%e%WCCz%x%QnLP%p%afiu%a%RmHu%n%kOXk%s%mEzT%i%IPSi%o%eOLK%n%RqSi%\n"
            'set "v1=s"\n'
            'set "v2=t"\n'
            'set "dyn_set=!v1!e!v2!"\n'
            '!dyn_set! "a=cmd.exe "\n'
            '!dyn_set! "b=/c "\n'
            '!dyn_set! "c=whoami"\n'
            "%a%%b%%c%\n"
        )
        engine = BatchDeobfuscator(enable_simple_obfuscator=True)
        clean_text, meta = engine.deobfuscate(script)
        self.assertIn("simple_obfuscator_telemetry", meta)
        sot = meta["simple_obfuscator_telemetry"]
        self.assertTrue(sot.get("is_simple_obfuscator"))
        self.assertIn("cmd.exe /c whoami", clean_text)

    def test_convenience_helpers(self):
        script = '%RAND_1%calc%RAND_2%.exe\n'
        res = deobfuscate_script(script, enable_simple_obfuscator=True)
        self.assertIn("calc.exe", res)

        raw = script.encode("utf-8")
        clean, meta = deobfuscate_bytes(raw, enable_simple_obfuscator=True)
        self.assertIn("calc.exe", clean)


if __name__ == "__main__":
    unittest.main()
