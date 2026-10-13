"""
Unit tests for Invoke-DOSfuscation (Daniel Bohannon) static deobfuscation engine.
Verifies loop unrolling, advanced environment variable slicing, delimiter normalization,
and memory zeroization.
"""

import unittest
from deobfuscator.core import BatchDeobfuscator, deobfuscate_script
from deobfuscator.dosfuscation import (
    DOSfuscationNormalizer,
    detect_dosfuscation_signatures,
    unwrap_dosfuscation_for_loops,
    resolve_dosfuscation_slicing,
    normalize_dosfuscation_delimiters,
    normalize_dosfuscation,
    zeroize_dict,
)


class TestDOSfuscationEngine(unittest.TestCase):
    """Test suite for Bohannon Invoke-DOSfuscation reverse arithmetic and deobfuscation."""

    def setUp(self):
        self.default_env = {
            "comspec": r"C:\Windows\system32\cmd.exe",
            "systemroot": r"C:\Windows",
            "windir": r"C:\Windows",
            "public": r"C:\Users\Public",
        }

    def test_signature_detection_indicators(self):
        """Test detection of FOR /L reverse loops, index arrays, and delimiter noise."""
        sample_reverse = (
            'cmd /V:ON /C "set reverse=ona/ tatsten&& '
            'FOR /L %A IN (11 -1 0) DO set final=!final!!reverse:~%A,1!&&IF %A==0 CALL %final:~-12%"'
        )
        sig = detect_dosfuscation_signatures(sample_reverse)
        self.assertTrue(sig["is_dosfuscation"])
        self.assertIn("for_l_reverse_loop", sig["indicators"])
        self.assertGreaterEqual(sig["confidence"], 0.4)

        sample_indexed = (
            "set unique=nets /ao&&FOR %A IN (0 1 2 3 2 6 2 4 5 6 0 7 1337) "
            "DO set final=!final!!unique:~%A,1!&& IF %A==1337 CALL !final:~-12!"
        )
        sig_idx = detect_dosfuscation_signatures(sample_indexed)
        self.assertTrue(sig_idx["is_dosfuscation"])
        self.assertIn("for_in_indexed_array", sig_idx["indicators"])

        sample_clean = "@echo off\necho Hello World\npause"
        sig_clean = detect_dosfuscation_signatures(sample_clean)
        self.assertFalse(sig_clean["is_dosfuscation"])
        self.assertEqual(sig_clean["confidence"], 0.0)

    def test_unwrap_for_l_reverse_loop_basic(self):
        """Test unwrapping FOR /L reverse reconstruction with stride -1."""
        script = (
            'cmd /V:ON /C "set reverse=ona/ tatsten&& '
            'FOR /L %A IN (11 -1 0) DO set final=!final!!reverse:~%A,1!&&IF %A==0 CALL %final:~-12%"'
        )
        clean_text, commands, meta = unwrap_dosfuscation_for_loops(script)
        self.assertEqual(len(commands), 1)
        self.assertIn("call netstat /ano", commands[0].lower())

    def test_unwrap_for_l_stride_padding(self):
        """Test unwrapping FOR /L reverse loop with stride -2 and character padding."""
        script = (
            'cmd /v /r "set reverse=OoBnFaU/S CtAaTtIsOtNe!n&&'
            'FOR /L %A IN (23 -2 1) DO set final=!final!!reverse:~%A,1!&&IF %A==1 CALL %final:~-12%"'
        )
        clean_text, commands, meta = unwrap_dosfuscation_for_loops(script)
        self.assertEqual(len(commands), 1)
        self.assertIn("call netstat /ano", commands[0].lower())

    def test_unwrap_for_l_with_carets_and_delimiters(self):
        """Test unwrapping heavily obfuscated FOR /L loop with carets and delimiter noise."""
        script = (
            ',;c^Md;/^V^:O^N;,;/C "((sE^T reVEr^sE=OoBnFaU/S CtAa^TtIsOtNe!n))&&'
            ',; fo^R;,;/L,;,%^a,;; i^N;,,;( ,+23; -2;;+1;,) ,;,;d^O,,(;(;s^Et fI^Nal=!finAl!!rev^Erse:~%^a,1!))&& '
            '(;i^F,%^a=^=^1,(Ca^lL;%fIn^Al:~-12%))"'
        )
        clean_text, commands, meta = unwrap_dosfuscation_for_loops(script)
        self.assertEqual(len(commands), 1)
        self.assertIn("netstat /ano", commands[0].lower())

    def test_unwrap_for_in_indexed_array_basic(self):
        """Test unwrapping FOR %A IN (...) index sequence command assembly."""
        script = (
            "set unique=nets /ao&&FOR %A IN (0 1 2 3 2 6 2 4 5 6 0 7 1337) "
            "DO set final=!final!!unique:~%A,1!&& IF %A==1337 CALL !final:~-12!"
        )
        clean_text, commands, meta = unwrap_dosfuscation_for_loops(script)
        self.assertEqual(len(commands), 1)
        self.assertIn("call netstat /ano", commands[0].lower())

    def test_unwrap_for_in_wildcard_substitution(self):
        """Test unwrapping FOR %A IN (...) with wildcard %final:*final!=% extractor."""
        script = (
            "set unique=nets /ao&&FOR %A IN (0 1 2 3 2 6 2 4 5 6 0 7 1337) "
            "DO set final=!final!!unique:~%A,1!&& IF %A==1337 CALL %final:*final!=%"
        )
        clean_text, commands, meta = unwrap_dosfuscation_for_loops(script)
        self.assertEqual(len(commands), 1)
        self.assertIn("netstat /ano", commands[0].lower())

    def test_unwrap_for_in_with_carets_and_delimiters(self):
        """Test unwrapping FOR %A IN (...) with interleaved carets, signs, and compound brackets."""
        script = (
            "((sE^T ^ unIQ^uE=OnBeFt^UsS C/AaToE ))&&,; fo^R;,;%^a,;; i^N;,,;( ,+1; 3 5 7 +5 1^3 +5,,9 11 +1^3 +1;;+15 ^+13^37;,),;,;"
            "d^O,,(;(;s^Et fI^Nal=!finAl!!uni^Que:~ %^a,1!))&&(;i^F,%^a=^=+13^37,(Ca^lL;%fIn^Al:~-12%))"
        )
        clean_text, commands, meta = unwrap_dosfuscation_for_loops(script)
        self.assertEqual(len(commands), 1)
        self.assertIn("netstat /ano", commands[0].lower())

    def test_normalize_delimiters(self):
        """Test normalization of comma and semicolon delimiter clusters."""
        input_line = ",;,cmd.exe,;,/c,;,echo;Command 1&&echo,Command 2"
        normalized = normalize_dosfuscation_delimiters(input_line)
        self.assertIn("cmd.exe", normalized)
        self.assertIn("Command 1", normalized)
        self.assertNotIn(",;,", normalized)

    def test_advanced_slicing_variants(self):
        """Test Bohannon environment slicing with tabs, whitespace, and explicit plus signs."""
        # 1. Negative start and negative length
        res1 = resolve_dosfuscation_slicing("%COMSPEC:~-7,-4%", self.default_env)
        self.assertEqual(res1.lower(), "cmd")

        # 2. Spaces and explicit plus sign
        res2 = resolve_dosfuscation_slicing("%coMSPec:~   -7,    +3%", self.default_env)
        self.assertEqual(res2.lower(), "cmd")

        # 3. Tabs and explicit plus sign
        res3 = resolve_dosfuscation_slicing("%coMSPec:~\t-7,\t+3%", self.default_env)
        self.assertEqual(res3.lower(), "cmd")

        # 4. Clamped negative index
        res4 = resolve_dosfuscation_slicing("%COMSPEC:~-40,3%", self.default_env)
        self.assertEqual(res4, "C:\\")

        # 5. Concatenated character extraction to build 'set'
        res5 = resolve_dosfuscation_slicing(
            "%comspec:~-16,1%%comspec:~-1%%comspec:~-13,1%",
            self.default_env
        )
        self.assertEqual(res5.lower(), "set")

    def test_delayed_expansion_substitution(self):
        """Test resolving delayed expansion substitution in multi-stage variable chain."""
        script = (
            "set command=neZsZ7Z /7no&&"
            "set sub2=!command:7=a!&&"
            "set sub1=!sub2:Z=t!&&"
            "CALL %sub1%"
        )
        engine = BatchDeobfuscator(custom_env=self.default_env)
        clean_text, meta = engine.deobfuscate(script)
        self.assertIn("call netstat /ano", clean_text.lower())

    def test_delayed_expansion_compound_path(self):
        """Test resolving careted delayed expansion path assembly."""
        script = (
            "s^et g^c^=^er^s&&s^e^t ^tf=^he^ll&&set^ f^a^=^pow&&"
            "^s^et^ dq^=C:\\WINDOWS\\System32\\W^i^n^do^ws^!fa^!^!g^c^!!^t^f^!\\^v^1^.0\\^!^fa!^!^gc!!^tf^!&&"
            "^ech^o^ hos^tname | !dq! -nop -"
        )
        engine = BatchDeobfuscator(custom_env=self.default_env)
        clean_text, meta = engine.deobfuscate(script)
        self.assertIn("windowspowershell\\v1.0\\powershell", clean_text.lower())
        self.assertIn("echo hostname", clean_text.lower())

    def test_zeroize_dict(self):
        """Verify cryptographic zeroization of in-memory dictionaries."""
        secret_dict = {"token": "secret_key_1337", "salt": bytearray(b"sensitive_salt")}
        zeroize_dict(secret_dict)
        self.assertEqual(len(secret_dict), 0)

    def test_dosfuscation_normalizer_class(self):
        """Test the DOSfuscationNormalizer wrapper class."""
        normalizer = DOSfuscationNormalizer(custom_env=self.default_env)
        sample = (
            'cmd /V:ON /C "set reverse=ona/ tatsten&& '
            'FOR /L %A IN (11 -1 0) DO set final=!final!!reverse:~%A,1!&&IF %A==0 CALL %final:~-12%"'
        )
        sig = normalizer.detect(sample)
        self.assertTrue(sig["is_dosfuscation"])

        clean_text, meta = normalizer.normalize(sample)
        self.assertEqual(meta["unwrapped_loops_count"], 1)
        self.assertIn("netstat /ano", clean_text.lower())

    def test_full_pipeline_with_convenience_function(self):
        """Test deobfuscate_script convenience function with DOSfuscation."""
        script = (
            'cmd /V:ON /C "set reverse=ona/ tatsten&& '
            'FOR /L %A IN (11 -1 0) DO set final=!final!!reverse:~%A,1!&&IF %A==0 CALL %final:~-12%"'
        )
        clean = deobfuscate_script(script)
        self.assertIn("call netstat /ano", clean.lower())


if __name__ == "__main__":
    unittest.main()
