"""Test setup.

These tests run under plain CPython with no Ghidra and no JVM.  That is possible
because the modules they cover are deliberately Ghidra-free: the stub builders,
the printable carver, the gopclntab table walk and the report/pipeline plumbing
are all pure byte and string handling.  ``ungarble.log`` already degrades to
``print`` when ``ghidra.util.Msg`` is missing, which is what lets them import.

Anything that needs a live ``Program`` (the finder's instruction predicates, the
PCode emulator, the side-effect guard) cannot be reached from here and is still
only covered by running the plugin inside Ghidra.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
