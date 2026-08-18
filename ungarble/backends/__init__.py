"""Emulation backends.

Imported lazily: :mod:`ungarble.backends.pcode_backend` pulls in Ghidra classes
that only exist inside a running JVM, and eagerly importing it here made
:mod:`ungarble.backends.refinery_backend` unimportable outside Ghidra too --
including from the tests.  ``from . import pcode_backend`` still works, since
Python falls back to importing the submodule itself.
"""

__all__ = ["refinery_backend", "pcode_backend"]
