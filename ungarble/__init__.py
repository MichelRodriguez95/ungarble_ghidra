"""Ungarble for Ghidra.

Port of the Binary Ninja "Ungarble" plugin by Invoke RE: recovers strings that
were obfuscated by the Golang `garble <https://github.com/burrowers/garble>`_
project by locating the obfuscation sequences and emulating them.

Submodules are imported lazily -- :mod:`ungarble.ui` and :mod:`ungarble.tasks`
pull in Swing and JPype, which only exist inside a running Ghidra JVM.
"""

__version__ = "1.0"
__all__ = ["UngarbleFinder", "UngarbleEngine", "UngarbleWindow"]


def __getattr__(name):
    if name == "UngarbleFinder":
        from .finder import UngarbleFinder

        return UngarbleFinder
    if name == "UngarbleEngine":
        from .engine import UngarbleEngine

        return UngarbleEngine
    if name == "UngarbleWindow":
        from .ui import UngarbleWindow

        return UngarbleWindow
    raise AttributeError(name)
