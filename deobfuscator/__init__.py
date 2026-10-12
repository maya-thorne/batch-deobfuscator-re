"""
batch-deobfuscator: Production-grade CLI Toolchain & Multi-Pass Static Batch Normalizer
Engineered by Maya Thorne.
"""

from .core import BatchDeobfuscator, deobfuscate_script, deobfuscate_bytes
from .normalizers import (
    strip_carets,
    strip_empty_quotes,
    split_chained_commands,
    strip_undefined_vars,
    resolve_slicing,
    resolve_substitution,
    normalize_bom,
    normalize_delimiters,
    collapse_spaces_outside_quotes,
    DYNAMIC_SYSTEM_VARS,
)
from .batcloak import (
    BatCloakNormalizer,
    normalize_batcloak_headers,
    strip_batcloak_random_vars,
    eliminate_dead_stores,
    detect_batcloak_signatures,
    zeroize_bytes,
)
from .somalifuscator import (
    solve_caesar_rotation,
    build_caesar_table,
    infer_and_complete_caesar_table,
    unwrap_somalifuscator_loops,
    extract_kdot_shuffled_array,
    resolve_kdot_slicing,
    strip_somalifuscator_chaff,
    detect_somalifuscator_signatures,
    normalize_somalifuscator,
    zeroize_dict,
)

__version__ = "1.3.0"
__author__ = "Maya Thorne"
__all__ = [
    "BatchDeobfuscator",
    "deobfuscate_script",
    "deobfuscate_bytes",
    "strip_carets",
    "strip_empty_quotes",
    "split_chained_commands",
    "strip_undefined_vars",
    "resolve_slicing",
    "resolve_substitution",
    "normalize_bom",
    "normalize_delimiters",
    "collapse_spaces_outside_quotes",
    "DYNAMIC_SYSTEM_VARS",
    "BatCloakNormalizer",
    "normalize_batcloak_headers",
    "strip_batcloak_random_vars",
    "eliminate_dead_stores",
    "detect_batcloak_signatures",
    "zeroize_bytes",
    "solve_caesar_rotation",
    "build_caesar_table",
    "infer_and_complete_caesar_table",
    "unwrap_somalifuscator_loops",
    "extract_kdot_shuffled_array",
    "resolve_kdot_slicing",
    "strip_somalifuscator_chaff",
    "detect_somalifuscator_signatures",
    "normalize_somalifuscator",
    "zeroize_dict",
]
