"""
Direct module execution support: python -m deobfuscator ...
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
