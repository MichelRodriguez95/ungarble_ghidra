# Deobfuscate strings obfuscated using the Golang Garble project.
# @author Invoke RE (original Binary Ninja plugin); Ghidra port
# @category Golang
# @menupath Tools.Ungarble
# @runtime PyGhidra

import os
import sys


def _package_root():
    """Directory holding the ``ungarble`` package (the repo root)."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        here = str(getSourceFile().getParentFile().getAbsolutePath())
    return os.path.dirname(here)


def _check_runtime():
    if sys.version_info[0] < 3:
        raise RuntimeError(
            "Ungarble requires PyGhidra (CPython 3). This script appears to be "
            "running under Jython, where neither JPype nor Unicorn are "
            "available. Relaunch Ghidra with support/pyghidraRun, or set the "
            "script's runtime to PyGhidra."
        )
    try:
        import jpype
    except ImportError:
        raise RuntimeError(
            "JPype is not importable -- this script must run under PyGhidra."
        )


def main():
    _check_runtime()

    root = _package_root()
    if root not in sys.path:
        sys.path.insert(0, root)

    from ungarble.ui import UngarbleWindow

    program = currentProgram
    if program is None:
        raise RuntimeError("Ungarble needs an open program.")

    try:
        tool = state.getTool()
    except Exception:
        tool = None

    if tool is None:
        raise RuntimeError(
            "Ungarble's window needs the Ghidra GUI. For headless use, run "
            "UngarbleHeadless.py instead."
        )

    UngarbleWindow(program, tool).show()


main()
