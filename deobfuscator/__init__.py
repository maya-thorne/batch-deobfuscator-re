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

__version__ = "1.2.0"
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
]
