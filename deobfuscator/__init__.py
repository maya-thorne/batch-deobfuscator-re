"""
batch-deobfuscator: Production-grade CLI Toolchain & Multi-Pass Static Batch Normalizer
Engineered by Maya Thorne.
"""

from .core import BatchDeobfuscator, deobfuscate_script
from .normalizers import (
    strip_carets,
    strip_empty_quotes,
    split_chained_commands,
    strip_undefined_vars,
    resolve_slicing,
    resolve_substitution,
    normalize_bom,
    normalize_delimiters,
    DYNAMIC_SYSTEM_VARS,
)

__version__ = "1.0.0"
__author__ = "Maya Thorne"
__all__ = [
    "BatchDeobfuscator",
    "deobfuscate_script",
    "strip_carets",
    "strip_empty_quotes",
    "split_chained_commands",
    "strip_undefined_vars",
    "resolve_slicing",
    "resolve_substitution",
    "normalize_bom",
    "normalize_delimiters",
    "DYNAMIC_SYSTEM_VARS",
]
