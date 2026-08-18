"""Logging shim.

The Binary Ninja plugin used ``binaryninja.log.Logger``; in Ghidra we route the
same messages to ``Ghidra.util.Msg`` so they land in the Ghidra console / log
window, and additionally to stdout so they show up in the script console.
"""

_ORIGINATOR = "Ungarble"

try:
    from ghidra.util import Msg
except ImportError:
    Msg = None


def _emit(level, message):
    text = str(message)
    if Msg is None:
        print("[Ungarble/%s] %s" % (level, text))
        return
    if level == "error":
        Msg.error(_ORIGINATOR, text)
    elif level == "warn":
        Msg.warn(_ORIGINATOR, text)
    else:
        Msg.info(_ORIGINATOR, text)
    print("[Ungarble] %s" % text)


def log_info(message):
    _emit("info", message)


def log_warn(message):
    _emit("warn", message)


def log_error(message):
    _emit("error", message)
