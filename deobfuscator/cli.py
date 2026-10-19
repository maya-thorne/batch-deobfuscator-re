"""
Command-Line Interface (CLI) for batch-deobfuscator.
Production security toolchain for static reverse engineering and batch deobfuscation.
"""

import argparse
import sys
import os
import json
from pathlib import Path

from . import __version__
from .core import BatchDeobfuscator
from .normalizers import normalize_bom
from .diff import generate_unified_diff
from .batchstealer import normalize_batchstealer

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="batch-deobfuscator",
        description="batch-deobfuscator: Industrial-grade Multi-Pass Batch Script Deobfuscator & Forensics Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Deobfuscate script to stdout
  batch-deobfuscator samples/01_env_slicing_sample.bat

  # Deobfuscate and save to output file
  batch-deobfuscator input.bat -o output_clean.bat

  # View colorized before/after syntax diff
  batch-deobfuscator input.bat --diff

  # Output full forensic telemetry and symbol tables as JSON
  batch-deobfuscator input.bat --format json

  # Increase maximum convergence passes with verbose telemetry
  batch-deobfuscator input.bat --passes 25 --verbose

Engineered by Maya Thorne.
        """
    )

    parser.add_argument(
        "input",
        help="Path to obfuscated .bat or .cmd script file"
    )

    parser.add_argument(
        "-o", "--output",
        help="Path to save deobfuscated output script (defaults to stdout)"
    )

    parser.add_argument(
        "-p", "--passes",
        type=int,
        default=15,
        help="Maximum fixed-point deobfuscation passes (default: 15)"
    )

    parser.add_argument(
        "-d", "--diff",
        action="store_true",
        help="Show unified color diff between obfuscated and deobfuscated code"
    )

    parser.add_argument(
        "--format",
        choices=["text", "json", "assemblyline"],
        default="text",
        help="Output format: 'text' (default), 'json', or 'assemblyline' (CCCS Assemblyline 4 Service Result JSON)"
    )

    parser.add_argument(
        "--assemblyline-out",
        help="Export CCCS Assemblyline 4 analysis report directly to specified JSON file path"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print verbose step-by-step pass convergence telemetry to stderr"
    )

    parser.add_argument(
        "--no-batcloak",
        action="store_true",
        help="Disable BatCloak %%RANDOM%% and junk variable preprocessing"
    )

    parser.add_argument(
        "--no-somalifuscator",
        action="store_true",
        help="Disable Somalifuscator Caesar cipher inversion and KDOT array resolution"
    )

    parser.add_argument(
        "--no-oxidizer", "--no-0xidiz3r",
        action="store_true",
        dest="no_oxidizer",
        help="Disable 0xidiz3r zero-literal bootstrap resolution and alphabet normalization"
    )

    parser.add_argument(
        "--no-abobus",
        action="store_true",
        help="Disable Abobus Unicode noise filtering, decoy elimination, and trap chaff removal"
    )

    parser.add_argument(
        "--no-dosfuscation",
        action="store_true",
        help="Disable Invoke-DOSfuscation Bohannon loop unwrapping and advanced slicing"
    )

    parser.add_argument(
        "--no-cradlecrafter",
        action="store_true",
        help="Disable Invoke-CradleCrafter and PowerShell download stager deobfuscation"
    )

    parser.add_argument(
        "--no-bedecode",
        action="store_true",
        help="Disable Batch-Encryption-DeCoder (BEDeCode) runtime stub peeling and slice decoding"
    )

    parser.add_argument(
        "--no-batchshield",
        action="store_true",
        help="Disable BatchShield virtual symbol table and compound env deobfuscation"
    )

    parser.add_argument(
        "--no-pandacrypter", "--no-certutil",
        action="store_true",
        dest="no_pandacrypter",
        help="Disable PandaCrypter colon noise stripping and Certutil stager payload decoding"
    )

    parser.add_argument(
        "--no-exorcism",
        action="store_true",
        help="Disable Exorcism subroutine label jump and control flow normalization"
    )

    parser.add_argument(
        "--no-batchtoapp", "--no-dosx",
        action="store_true",
        dest="no_batchtoapp",
        help="Disable BatchToApp / DosX native wrapper and operator table deobfuscation"
    )

    parser.add_argument(
        "--no-machine1337",
        action="store_true",
        help="Disable batobfuscate-machine1337 fake header de-masking and CJK transcode recovery"
    )

    parser.add_argument(
        "--no-cmd-deobfuscator",
        action="store_true",
        help="Disable CMD-DeObfuscator chained env variable resolution, quote widening and nested cmd flattening"
    )

    parser.add_argument(
        "--no-simple-obfuscator",
        action="store_true",
        help="Disable simple-batch-obfuscator random variable fragment infiltration and chunk assembly"
    )

    parser.add_argument(
        "--no-jsbatch",
        action="store_true",
        help="Disable JSBatchDeobfuscator alphabet slicing and hybrid JS/BAT polyglot extraction"
    )

    parser.add_argument(
        "--no-batchstealer",
        action="store_true",
        help="Disable BatchStealer credential harvester and C2 webhook forensic normalization"
    )

    parser.add_argument(
        "--no-wirebits",
        action="store_true",
        help="Disable BatchObfuscator-wirebits escape decoding, PowerShell array casting, and char splicing resolution"
    )

    parser.add_argument(
        "--defang-c2",
        action="store_true",
        help="Defang active C2 Discord webhooks, Telegram bots, and external endpoints into safe indicators"
    )

    parser.add_argument(
        "--no-dse",
        action="store_true",
        help="Disable Dead Store Elimination (DSE) for unreferenced variables"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    return parser

def main(args=None) -> int:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = create_parser()
    opts = parser.parse_args(args)

    input_path = Path(opts.input)
    if not input_path.exists():
        sys.stderr.write(f"[-] Error: Input file not found: {input_path}\n")
        return 1

    b2a_pe_info = None
    try:
        raw_bytes = input_path.read_bytes()
        if raw_bytes[:2] == b"MZ" and not opts.no_batchtoapp:
            from .batchtoapp import inspect_batchtoapp_pe
            b2a_info = inspect_batchtoapp_pe(raw_bytes)
            if b2a_info.get("has_embedded_script") and b2a_info.get("extracted_script"):
                script_text = b2a_info["extracted_script"]
                b2a_pe_info = b2a_info
                if opts.verbose:
                    sys.stderr.write(f"[+] Successfully extracted embedded BatchToApp script from PE ({len(script_text)} chars)\n")
            else:
                script_text = normalize_bom(raw_bytes)
        else:
            script_text = normalize_bom(raw_bytes)
    except Exception as e:
        sys.stderr.write(f"[-] Error reading file: {e}\n")
        return 1

    engine = BatchDeobfuscator(
        max_passes=opts.passes,
        enable_batcloak=not opts.no_batcloak,
        enable_somalifuscator=not opts.no_somalifuscator,
        enable_oxidizer=not opts.no_oxidizer,
        enable_abobus=not opts.no_abobus,
        enable_dosfuscation=not opts.no_dosfuscation,
        enable_cradlecrafter=not opts.no_cradlecrafter,
        enable_bedecode=not opts.no_bedecode,
        enable_batchshield=not opts.no_batchshield,
        enable_pandacrypter=not opts.no_pandacrypter,
        enable_exorcism=not opts.no_exorcism,
        enable_batchtoapp=not opts.no_batchtoapp,
        enable_machine1337=not opts.no_machine1337,
        enable_cmd_deobfuscator=not opts.no_cmd_deobfuscator,
        enable_simple_obfuscator=not opts.no_simple_obfuscator,
        enable_jsbatch=not opts.no_jsbatch,
        enable_batchstealer=not opts.no_batchstealer,
        enable_wirebits=not opts.no_wirebits,
        eliminate_dead_code=not opts.no_dse
    )
    clean_text, meta = engine.deobfuscate(script_text)
    if opts.defang_c2:
        clean_text, _ = normalize_batchstealer(clean_text, defang_c2=True)
    if b2a_pe_info:
        meta["batchtoapp_pe"] = b2a_pe_info

    if opts.verbose:
        sys.stderr.write(f"\n[+] Analysis for: {input_path.name}\n")
        sys.stderr.write(f"  ↳ Passes executed: {meta['passes_executed']} (Converged: {meta['converged']})\n")
        sys.stderr.write(f"  ↳ Elapsed time: {meta['elapsed_ms']} ms\n")
        sys.stderr.write(f"  ↳ Resolved dynamic symbols: {meta['symbols_resolved_count']}\n")
        if meta.get("batcloak_telemetry", {}).get("detected"):
            bt = meta["batcloak_telemetry"]
            sys.stderr.write(f"  ↳ BatCloak Evasion Detected: True (Confidence: {bt['confidence']})\n")
            if bt.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(bt['indicators'])}\n")
            if bt.get("removed_random_vars"):
                sys.stderr.write(f"     • Pruned %RANDOM% chaff: {len(bt['removed_random_vars'])} statements\n")
            if bt.get("eliminated_dead_stores"):
                sys.stderr.write(f"     • Eliminated dead stores: {len(bt['eliminated_dead_stores'])} variables\n")
        st = meta.get("somalifuscator_telemetry", {})
        if st.get("signatures", {}).get("is_somalifuscator") or st.get("rotation_value") is not None:
            sig = st.get("signatures", {})
            sys.stderr.write(f"  ↳ Somalifuscator Detected: True (Confidence: {sig.get('confidence', 0.0)})\n")
            if st.get("rotation_value") is not None:
                sys.stderr.write(f"     • Solved Caesar shift: k = {st['rotation_value']}\n")
            if st.get("caesar_symbols_count"):
                sys.stderr.write(f"     • Recovered Caesar alphabet symbols: {st['caesar_symbols_count']}\n")
            if st.get("kdot_detected"):
                sys.stderr.write(f"     • Resolved KDOT shuffled array slicing: True\n")
            if st.get("unwrapped_loops_count"):
                sys.stderr.write(f"     • Unwrapped 'for /l' wrapper loops: {st['unwrapped_loops_count']}\n")
            if st.get("eliminated_chaff_count"):
                sys.stderr.write(f"     • Pruned Somalifuscator chaff/decoys: {st['eliminated_chaff_count']} statements\n")
        ot = meta.get("oxidizer_telemetry", {})
        if ot.get("is_oxidizer") or (ot.get("signatures", {}) and ot["signatures"].get("is_oxidizer")):
            sig = ot.get("signatures", {})
            sys.stderr.write(f"  ↳ 0xidiz3r Detected: True (Confidence: {sig.get('confidence', ot.get('confidence', 0.0))})\n")
            b_vars = ot.get("bootstrap_vars") or {}
            if b_vars.get("set_var"):
                sys.stderr.write(f"     • Bootstrap primitives: set={b_vars.get('set_var')}, space={b_vars.get('space_var')}, eq={b_vars.get('eq_var')}\n")
            if ot.get("alphabet_size"):
                sys.stderr.write(f"     • Harvested alphabet symbols: {ot['alphabet_size']}\n")
            if ot.get("eliminated_preamble_count"):
                sys.stderr.write(f"     • Pruned 0xidiz3r preamble chaff: {ot['eliminated_preamble_count']} statements\n")
        at = meta.get("abobus_telemetry", {})
        if at.get("is_abobus") or (at.get("signatures", {}) and at["signatures"].get("is_abobus")):
            sig = at.get("signatures", {})
            sys.stderr.write(f"  ↳ Abobus Detected: True (Confidence: {sig.get('confidence', at.get('confidence', 0.0))})\n")
            if sig.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(sig['indicators'])}\n")
            if at.get("eliminated_traps_count"):
                sys.stderr.write(f"     • Pruned Abobus traps/chaff: {at['eliminated_traps_count']} statements\n")
            if at.get("stripped_noise_count"):
                sys.stderr.write(f"     • Stripped Unicode/Kaomoji noise: {at['stripped_noise_count']} tokens\n")
            if at.get("dictionaries_resolved_count"):
                sys.stderr.write(f"     • Resolved substring dictionaries: {at['dictionaries_resolved_count']} tables\n")
        dt = meta.get("dosfuscation_telemetry", {})
        if dt.get("is_dosfuscation") or (dt.get("signatures", {}) and dt["signatures"].get("is_dosfuscation")):
            sig = dt.get("signatures", {})
            sys.stderr.write(f"  ↳ Invoke-DOSfuscation Detected: True (Confidence: {sig.get('confidence', dt.get('confidence', 0.0))})\n")
            if sig.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(sig['indicators'])}\n")
            if dt.get("unwrapped_loops_count"):
                sys.stderr.write(f"     • Unwrapped Bohannon loops: {dt['unwrapped_loops_count']} statements\n")
            if dt.get("delimiters_normalized"):
                sys.stderr.write(f"     • Normalized delimiter noise clusters: True\n")
            if dt.get("slicing_resolved"):
                sys.stderr.write(f"     • Resolved advanced environment slicing: True\n")
        ct = meta.get("cradlecrafter_telemetry", {})
        if ct.get("is_cradle") or (ct.get("signatures", {}) and ct["signatures"].get("is_cradle")) or ct.get("decoded_payloads_count", 0) > 0:
            sig = ct.get("signatures", {})
            sys.stderr.write(f"  ↳ Invoke-CradleCrafter / PowerShell Stager Detected: True (Confidence: {sig.get('confidence', ct.get('confidence', 0.0))})\n")
            if sig.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(sig['indicators'])}\n")
            if ct.get("decoded_payloads_count"):
                sys.stderr.write(f"     • Decoded Base64 stager payloads: {ct['decoded_payloads_count']}\n")
            if ct.get("extracted_urls"):
                sys.stderr.write(f"     • Extracted download URLs: {', '.join(ct['extracted_urls'])}\n")
            if ct.get("cradle_methods"):
                sys.stderr.write(f"     • Identified cradle methods: {', '.join(ct['cradle_methods'])}\n")
            if ct.get("extracted_destinations"):
                sys.stderr.write(f"     • Extracted file destinations: {', '.join(ct['extracted_destinations'])}\n")
        bdt = meta.get("bedecode_telemetry", {})
        if bdt.get("is_bedecode") or (bdt.get("signatures", {}) and bdt["signatures"].get("is_bedecode")):
            sig = bdt.get("signatures", {})
            sys.stderr.write(f"  ↳ Batch-Encryption-DeCoder (BEDeCode) Detected: True (Confidence: {sig.get('confidence', bdt.get('confidence', 0.0))})\n")
            if sig.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(sig['indicators'])}\n")
            if bdt.get("layers_unwrapped"):
                sys.stderr.write(f"     • Unwrapped nested onion layers: {bdt['layers_unwrapped']}\n")
            if bdt.get("slices_resolved"):
                sys.stderr.write(f"     • Resolved character slices: {bdt['slices_resolved']}\n")
            if bdt.get("env_bootstraps_resolved"):
                sys.stderr.write(f"     • Resolved environment bootstrap references: {bdt['env_bootstraps_resolved']}\n")
        bst = meta.get("batchshield_telemetry", {})
        if bst.get("is_batchshield") or (bst.get("signatures", {}) and bst["signatures"].get("is_batchshield")):
            sig = bst.get("signatures", {})
            sys.stderr.write(f"  ↳ BatchShield Detected: True (Confidence: {sig.get('confidence', bst.get('confidence', 0.0))})\n")
            if sig.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(sig['indicators'])}\n")
            if bst.get("symbols_resolved_count"):
                sys.stderr.write(f"     • Resolved virtual symbol definitions: {bst['symbols_resolved_count']}\n")
            if bst.get("chains_resolved_count"):
                sys.stderr.write(f"     • Resolved compound environment chains: {bst['chains_resolved_count']}\n")
            if bst.get("noise_stripped_count"):
                sys.stderr.write(f"     • Stripped dummy noise tokens: {bst['noise_stripped_count']}\n")
            if bst.get("chaff_eliminated_count"):
                sys.stderr.write(f"     • Pruned dead symbol definition lines: {bst['chaff_eliminated_count']}\n")
        pt = meta.get("pandacrypter_telemetry", {})
        if pt.get("is_pandacrypter") or pt.get("is_certutil") or pt.get("decoded_payloads_count", 0) > 0:
            sig = pt.get("signatures", {})
            label = "PandaCrypter & Certutil Stager" if pt.get("is_pandacrypter") else "Certutil Stager"
            sys.stderr.write(f"  ↳ {label} Detected: True (Confidence: {sig.get('confidence', pt.get('confidence', 0.0))})\n")
            if pt.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(pt['indicators'])}\n")
            if pt.get("colon_padding_stripped"):
                sys.stderr.write(f"     • Neutralized colon padding noise: {pt['colon_padding_stripped']} lines\n")
            if pt.get("decoded_payloads_count"):
                sys.stderr.write(f"     • Decoded staged payloads: {pt['decoded_payloads_count']}\n")
                for payload in pt.get("decoded_payloads", []):
                    sys.stderr.write(f"       - Mode: {payload.get('mode')} -> {payload.get('out_file')} (Size: {payload.get('size_bytes')} bytes, Format: {payload.get('format_desc')})\n")
        ext = meta.get("exorcism_telemetry", {})
        if ext.get("is_exorcism") or ext.get("trampolines_collapsed", 0) > 0 or ext.get("predicates_normalized", 0) > 0 or ext.get("subroutines_inlined_count", 0) > 0:
            sig = ext.get("signatures", {})
            sys.stderr.write(f"  ↳ Exorcism Control Flow Detected: True (Confidence: {sig.get('confidence', ext.get('confidence', 0.0))})\n")
            if ext.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(ext['indicators'])}\n")
            if ext.get("trampolines_collapsed"):
                sys.stderr.write(f"     • Collapsed jump trampolines: {ext['trampolines_collapsed']}\n")
            if ext.get("predicates_normalized"):
                sys.stderr.write(f"     • Normalized opaque predicates: {ext['predicates_normalized']}\n")
            if ext.get("subroutines_inlined_count"):
                sys.stderr.write(f"     • Inlined leaf subroutines: {ext['subroutines_inlined_count']}\n")
            if ext.get("fallthrough_gotos_removed"):
                sys.stderr.write(f"     • Pruned obsolete fall-through gotos: {ext['fallthrough_gotos_removed']}\n")
            if ext.get("pruned_blocks_count"):
                sys.stderr.write(f"     • Pruned unreachable dead blocks: {ext['pruned_blocks_count']}\n")
        b2at = meta.get("batchtoapp_telemetry", {})
        if b2at.get("is_batchtoapp") or (b2at.get("signatures", {}) and b2at["signatures"].get("is_batchtoapp")) or b2at.get("operators_resolved", 0) > 0 or b2at.get("noise_slices_stripped", 0) > 0:
            sig = b2at.get("signatures", {})
            sys.stderr.write(f"  ↳ BatchToApp / DosX Detected: True (Confidence: {sig.get('confidence', b2at.get('confidence', 0.0))})\n")
            if b2at.get("indicators") or sig.get("indicators"):
                ind = b2at.get("indicators") or sig.get("indicators", [])
                sys.stderr.write(f"     • Indicators: {', '.join(ind)}\n")
            if b2at.get("noise_slices_stripped"):
                sys.stderr.write(f"     • Stripped noise variable slices: {b2at['noise_slices_stripped']} tokens\n")
            if b2at.get("mutation_block_stripped"):
                sys.stderr.write(f"     • Unwrapped mutation jump & binary junk block: True\n")
            if b2at.get("operators_resolved"):
                sys.stderr.write(f"     • Resolved operator variable mappings: {b2at['operators_resolved']} commands\n")
            if b2at.get("closing_bracket_var"):
                sys.stderr.write(f"     • Inverted closing bracket variable: %{b2at['closing_bracket_var']}%\n")
            if b2at.get("fake_labels_pruned"):
                sys.stderr.write(f"     • Pruned unreferenced fake labels: {b2at['fake_labels_pruned']}\n")
            if b2at.get("header_shift_removed") or b2at.get("exit_label_removed") or b2at.get("guard_check_removed"):
                sys.stderr.write(f"     • Normalized wrapper headers, guards & exit label: True\n")
        m13t = meta.get("machine1337_telemetry", {})
        if m13t.get("is_machine1337") or m13t.get("header_stripped") or m13t.get("cjk_recovered") or m13t.get("carets_normalized", 0) > 0:
            sig = m13t.get("signatures", {})
            sys.stderr.write(f"  ↳ batobfuscate-machine1337 Detected: True (Confidence: {sig.get('confidence', m13t.get('confidence', 0.0))})\n")
            if m13t.get("header_stripped"):
                sys.stderr.write(f"     • Stripped fake wide header: {m13t.get('header_variant')} ({m13t.get('stripped_bytes')} bytes)\n")
            if m13t.get("cjk_recovered"):
                sys.stderr.write(f"     • Recovered CJK transcoded batch commands: True\n")
            if m13t.get("cls_preamble_stripped"):
                sys.stderr.write(f"     • Stripped cls execution error preamble: True\n")
            if m13t.get("carets_normalized"):
                sys.stderr.write(f"     • Normalized inline caret scrambling: {m13t['carets_normalized']} tokens\n")
        cdt = meta.get("cmd_deobfuscator_telemetry", {})
        if cdt.get("is_cmd_deobfuscator") or cdt.get("chains_resolved_count", 0) > 0 or cdt.get("quotes_widened_count", 0) > 0 or cdt.get("nested_cmds_flattened_count", 0) > 0:
            sig = cdt.get("signatures", {})
            sys.stderr.write(f"  ↳ CMD-DeObfuscator Detected: True (Confidence: {sig.get('confidence', cdt.get('confidence', 0.0))})\n")
            if cdt.get("indicators") or sig.get("indicators"):
                ind = cdt.get("indicators") or sig.get("indicators", [])
                sys.stderr.write(f"     • Indicators: {', '.join(ind)}\n")
            if cdt.get("chains_resolved_count"):
                sys.stderr.write(f"     • Resolved chained environment variables: {cdt['chains_resolved_count']} definitions\n")
            if cdt.get("cycles_detected_count"):
                sys.stderr.write(f"     • Cyclic dependencies guarded: {cdt['cycles_detected_count']} cycles\n")
            if cdt.get("delayed_expansions_resolved"):
                sys.stderr.write(f"     • Resolved delayed expansions: {cdt['delayed_expansions_resolved']} tokens\n")
            if cdt.get("quotes_widened_count"):
                sys.stderr.write(f"     • Widened fragmented token quotes: {cdt['quotes_widened_count']} tokens\n")
            if cdt.get("empty_quotes_stripped_count"):
                sys.stderr.write(f"     • Stripped empty quote pairs: {cdt['empty_quotes_stripped_count']} tokens\n")
            if cdt.get("nested_cmds_flattened_count"):
                sys.stderr.write(f"     • Flattened nested cmd.exe wrappers: {cdt['nested_cmds_flattened_count']} layers\n")
            if cdt.get("delimiters_normalized_count"):
                sys.stderr.write(f"     • Normalized delimiter clusters: {cdt['delimiters_normalized_count']} lines\n")
        sot = meta.get("simple_obfuscator_telemetry", {})
        if sot.get("is_simple_obfuscator") or sot.get("chunks_assembled_count", 0) > 0 or sot.get("undefined_vars_stripped_count", 0) > 0:
            sig = sot.get("signatures", {})
            sys.stderr.write(f"  ↳ simple-batch-obfuscator Detected: True (Confidence: {sot.get('confidence', sig.get('confidence', 0.0))})\n")
            if sot.get("indicators"):
                sys.stderr.write(f"     • Indicators: {', '.join(sot['indicators'])}\n")
            if sot.get("chunks_assembled_count"):
                sys.stderr.write(f"     • Reassembled variable chunks: {sot['chunks_assembled_count']}\n")
            if sot.get("undefined_vars_stripped_count"):
                sys.stderr.write(f"     • Undefined variable noise stripped: {sot['undefined_vars_stripped_count']}\n")
            if sot.get("decoded_powershell"):
                preview = sot['decoded_powershell'].replace('\n', ' ')[:70]
                sys.stderr.write(f"     • Decoded PowerShell stager payload: {preview}...\n")
        jst = meta.get("jsbatch_telemetry", {})
        if jst.get("is_jsbatch") or jst.get("is_polyglot") or jst.get("slices_resolved", 0) > 0 or jst.get("chained_tokens_resolved", 0) > 0:
            sig = jst.get("signatures", {})
            sys.stderr.write(f"  ↳ JSBatchDeobfuscator & Polyglot Detected: True (Confidence: {jst.get('confidence', sig.get('confidence', 0.0))})\n")
            if jst.get("polyglot_type") and jst.get("polyglot_type") != "none":
                sys.stderr.write(f"     • Polyglot wrapper type: {jst['polyglot_type']}\n")
            if jst.get("alphabet_key"):
                sys.stderr.write(f"     • Harvested alphabet key: %{jst['alphabet_key']}% ({jst.get('alphabet_size', 0)} chars)\n")
            if jst.get("slices_resolved"):
                sys.stderr.write(f"     • Resolved alphabet substring slices: {jst['slices_resolved']} tokens\n")
            if jst.get("chained_tokens_resolved"):
                sys.stderr.write(f"     • Resolved chained SET tokens: {jst['chained_tokens_resolved']} tokens\n")
            if jst.get("activex_objects"):
                sys.stderr.write(f"     • Extracted ActiveX ProgIDs: {', '.join(jst['activex_objects'])}\n")
            if jst.get("extracted_urls"):
                sys.stderr.write(f"     • Extracted C2 URLs: {', '.join(jst['extracted_urls'])}\n")
        bst = meta.get("batchstealer_telemetry", {})
        if bst.get("is_batchstealer") or (bst.get("signatures", {}) and bst["signatures"].get("is_batchstealer")) or bst.get("extracted_discord_webhooks_count", 0) > 0:
            sig = bst.get("signatures", {})
            conf = sig.get("confidence", bst.get("confidence", 0.0))
            sys.stderr.write(f"  ↳ BatchStealer Malware Forensics Detected: True (Confidence: {conf})\n")
            if bst.get("indicators") or sig.get("indicators"):
                ind = bst.get("indicators") or sig.get("indicators", [])
                sys.stderr.write(f"     • Indicators: {', '.join(ind)}\n")
            endpoints = bst.get("endpoints", {})
            if endpoints.get("discord_webhooks"):
                sys.stderr.write(f"     • Extracted Discord Webhooks: {len(endpoints['discord_webhooks'])}\n")
                for wh in endpoints["discord_webhooks"]:
                    sys.stderr.write(f"       - {wh.get('defanged_url', wh.get('url'))}\n")
            if endpoints.get("telegram_bots"):
                sys.stderr.write(f"     • Extracted Telegram Bots: {len(endpoints['telegram_bots'])}\n")
            if endpoints.get("download_urls"):
                sys.stderr.write(f"     • Extracted Staging Download URLs: {', '.join(endpoints['download_urls'])}\n")
            inv = bst.get("inventory", {})
            if inv.get("browsers"):
                b_names = [b.get("browser", "") for b in inv["browsers"]]
                sys.stderr.write(f"     • Targeted Browsers: {', '.join(b_names)}\n")
            if inv.get("messaging"):
                m_names = [m.get("client", "") for m in inv["messaging"]]
                sys.stderr.write(f"     • Targeted Messaging Clients: {', '.join(m_names)}\n")
            if inv.get("gaming"):
                g_names = [g.get("platform", "") for g in inv["gaming"]]
                sys.stderr.write(f"     • Targeted Gaming Platforms: {', '.join(g_names)}\n")
            if bst.get("mitre_attack"):
                mitre_ids = [m.get("id", "") for m in bst["mitre_attack"]]
                sys.stderr.write(f"     • MITRE ATT&CK Techniques: {', '.join(mitre_ids)}\n")
        wbt = meta.get("wirebits_telemetry", {})
        if wbt.get("is_wirebits") or (wbt.get("signatures", {}) and wbt["signatures"].get("is_wirebits")) or wbt.get("spliced_fragments_resolved", 0) > 0 or wbt.get("hex_escapes_decoded", 0) > 0:
            sig = wbt.get("signatures", {})
            conf = sig.get("confidence", wbt.get("confidence", 0.0))
            sys.stderr.write(f"  ↳ BatchObfuscator-wirebits Detected: True (Confidence: {conf})\n")
            if wbt.get("indicators") or sig.get("indicators"):
                ind = wbt.get("indicators") or sig.get("indicators", [])
                sys.stderr.write(f"     • Indicators: {', '.join(ind)}\n")
            if wbt.get("headers_neutralized"):
                sys.stderr.write(f"     • Neutralized Base64/BOM header & &cls preamble: True\n")
            if wbt.get("banners_stripped_count"):
                sys.stderr.write(f"     • Stripped TUI menu & banner noise: {wbt['banners_stripped_count']} lines\n")
            if wbt.get("hex_escapes_decoded"):
                sys.stderr.write(f"     • Decoded hexadecimal escapes: {wbt['hex_escapes_decoded']} tokens\n")
            if wbt.get("octal_escapes_decoded"):
                sys.stderr.write(f"     • Decoded octal escape sequences: {wbt['octal_escapes_decoded']} tokens\n")
            if wbt.get("powershell_arrays_resolved"):
                sys.stderr.write(f"     • Resolved PowerShell character arrays & joins: {wbt['powershell_arrays_resolved']} expressions\n")
            if wbt.get("radix_arithmetic_normalized"):
                sys.stderr.write(f"     • Normalized non-standard radix numbers: {wbt['radix_arithmetic_normalized']} constants\n")
            if wbt.get("spliced_fragments_resolved"):
                sys.stderr.write(f"     • Reassembled sequential char fragments: {wbt['spliced_fragments_resolved']} variables\n")
            if wbt.get("dead_stores_pruned"):
                sys.stderr.write(f"     • Pruned dead variable stores: {wbt['dead_stores_pruned']} assignments\n")
        if meta.get("batchtoapp_pe"):
            bpe = meta["batchtoapp_pe"]
            sys.stderr.write(f"  ↳ BatchToApp PE Wrapper Forensics:\n")
            sys.stderr.write(f"     • Architecture: {bpe.get('architecture', 'Unknown')}\n")
            if bpe.get("app_id"):
                sys.stderr.write(f"     • Application GUID: {bpe['app_id']}\n")
            if bpe.get("is_hidden") is not None:
                sys.stderr.write(f"     • Window Hidden: {bpe['is_hidden']}\n")
            if bpe.get("fs_protection") is not None:
                sys.stderr.write(f"     • FileSystem Anti-Tamper: {bpe['fs_protection']}\n")
        if meta["symbol_table"]:
            sys.stderr.write("  ↳ Symbol Table:\n")
            for k, v in list(meta["symbol_table"].items())[:10]:
                sys.stderr.write(f"     • %{k}% = {repr(v)}\n")
            if len(meta["symbol_table"]) > 10:
                sys.stderr.write(f"     ... and {len(meta['symbol_table']) - 10} more symbols\n")
        sys.stderr.write("\n")

    # Handle output writing or diff
    if opts.output:
        out_path = Path(opts.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(clean_text, encoding="utf-8")
        if opts.verbose or opts.diff:
            sys.stderr.write(f"[+] Clean script written to: {out_path}\n")

    if opts.assemblyline_out or opts.format == "assemblyline":
        from .assemblyline import AssemblylineBridge
        bridge = AssemblylineBridge()
        al_res = bridge.generate_service_result(
            script_text=script_text,
            deobfuscated_text=clean_text,
            meta=meta,
            file_path=str(input_path),
            working_dir=str(Path(opts.assemblyline_out).parent) if opts.assemblyline_out else None,
        )
        if opts.assemblyline_out:
            al_out_path = al_res.save(opts.assemblyline_out)
            if opts.verbose:
                sys.stderr.write(f"[+] CCCS Assemblyline report written to: {al_out_path}\n")
        if opts.format == "assemblyline":
            print(al_res.to_json())

    if opts.diff:
        diff_output = generate_unified_diff(
            script_text,
            clean_text,
            filename=input_path.name,
            use_color=not opts.no_color
        )
        print(diff_output)
    elif opts.format == "json":
        payload = {
            "file": str(input_path),
            "meta": meta,
            "deobfuscated_script": clean_text
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif opts.format != "assemblyline" and not opts.output and not opts.assemblyline_out:
        # If output file not specified, print clean script to stdout
        sys.stdout.write(clean_text + ("\n" if not clean_text.endswith("\n") else ""))

    return 0

if __name__ == "__main__":
    sys.exit(main())
