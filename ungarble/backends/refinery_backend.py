"""Binary Refinery / Unicorn backend.

Carries over the Binary Ninja plugin's emulation so results match the original.
Requires CPython (PyGhidra) because ``unicorn`` is a native extension module and
cannot load under Jython.

From the original plugin's notes: ``vstack`` uses Unicorn to log writes to local
stack addresses throughout emulation.  ``-W`` logs writes inside calls made
during execution, ``-c`` waits until a function call completes, ``-C`` skips
calls entirely, ``-L`` is refinery's lenient flag (accept partial output) and
``-b`` sets the image base.  Credit to @huettenhain for the unit.

**CLI drift.** The plugin was written against a binary-refinery whose vstack
took the stop address via ``-s`` and the start address as a positional::

    vstack -C -s=<stop> <start> -b <base>

Current versions (0.11.x) take the whole range as one positional instead::

    vstack -C -b <base> <start>:<stop>

Both spellings are emitted here -- the modern one first, falling back to the
legacy one if the argument parser rejects it -- so the backend works across
refinery versions.  The flag semantics are unchanged either way.
"""

NAME = "refinery"

_UNAVAILABLE_REASON = None

_EXECUTABLE_MAGIC = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)


def available():
    """True when binary-refinery (and therefore Unicorn) can be imported.

    Note that PyPI also carries an unrelated project called ``refinery``; the
    ``refinery.lib.loader`` import below is what distinguishes them.
    """
    global _UNAVAILABLE_REASON
    try:
        import refinery
        from refinery.lib.loader import load_pipeline
    except Exception as exc:
        _UNAVAILABLE_REASON = str(exc)
        return False
    _UNAVAILABLE_REASON = None
    return True


def unavailable_reason():
    return _UNAVAILABLE_REASON


def is_executable(data):
    """Whether refinery will recognise *data* as an executable image."""
    if not data:
        return False
    return any(data.startswith(magic) for magic in _EXECUTABLE_MAGIC)


def _load_pipeline(command, clear_cache=False):
    from refinery.lib.loader import load_pipeline

    if clear_cache:
        load_pipeline.cache_clear()
    return load_pipeline(command)


def _flags(batch):
    """The flag set for each of the two pipelines the original plugin used.

    *batch* is the bulk "Ungarble Locations" path; otherwise it is the
    single-shot right-click path.
    """
    if batch:
        return "-C", 8
    return "-W -c -L", 9


def _commands(start_address, stop_address, base_address, batch, arch):
    """Modern then legacy spellings of the same vstack invocation."""
    flags, min_len = _flags(batch)
    arch_flag = " -a %s" % arch if arch else ""
    carve = " | carve printable -n %d" % min_len
    modern = "vstack %s%s -b 0x%x 0x%x:0x%x" % (
        flags,
        arch_flag,
        base_address,
        start_address,
        stop_address,
    )
    legacy = "vstack %s%s -s=0x%x 0x%x -b 0x%x" % (
        flags,
        arch_flag,
        stop_address,
        start_address,
        base_address,
    )
    return [modern + carve, legacy + carve]


def run_vstack(data, start_address, stop_address, base_address, batch=True, arch=None):
    """Emulate ``start_address``..``stop_address`` and carve the result."""
    if start_address > stop_address:
        raise ValueError("0x%x larger than 0x%x" % (start_address, stop_address))

    if arch is None and not is_executable(data):
        arch = "x64"

    last_error = None
    for command in _commands(start_address, stop_address, base_address, batch, arch):
        try:
            pipeline = _load_pipeline(command)
        except Exception as exc:
            last_error = exc
            continue
        result = data | pipeline | bytes
        return result.decode("ascii", "replace")

    raise RuntimeError("no usable vstack invocation: %s" % last_error)
