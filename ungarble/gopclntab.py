"""Self-contained gopclntab parser -- recovers Go function names with no
external dependency.

This is the fallback used when the GoResolver console tool is not on PATH. It
reads the ``.gopclntab`` table straight from Ghidra's program memory and walks
the pc/line header, function table and name table itself.

Why it exists / why it works on garble:

* Ghidra's own Golang analyzer refuses garbled binaries -- garble scrubs the
  build info, so ``GoRttiMapper.getGoBinary`` throws *"Invalid Go version
  string"*.
* garble also **randomises the pcHeader magic** (observed ``0xa0ab2568`` instead
  of the canonical ``0xFFFFFFF1``). Any parser that validates the magic bails.
  This one does not check the magic at all -- it parses the header structurally
  from the start of the ``.gopclntab`` block, which garble leaves intact.

Layout handled: Go 1.18+ (textStart present, uint32 function table, ``_func``
name offset at +4). That covers every Go version garble currently builds with.
If the parsed data fails a sanity check the parser returns ``{}`` so the caller
can defer to GoResolver rather than apply garbage.
"""

import struct

from .log import log_error, log_info

_BLOCK_NAMES = (".gopclntab", "__gopclntab", "gopclntab", ".data.rel.ro.gopclntab")


def _read_block_bytes(program, block):
    from jpype import JArray, JByte

    size = int(block.getSize())
    buf = JArray(JByte)(size)
    program.getMemory().getBytes(block.getStart(), buf)
    return bytes(bytearray(int(b) & 0xFF for b in buf))


def _find_block(program):
    memory = program.getMemory()
    for name in _BLOCK_NAMES:
        block = memory.getBlock(name)
        if block is not None and block.isInitialized():
            return block
    return None


def _looks_like_go_name(name):
    if not name or len(name) > 300:
        return False
    if not all(32 <= ord(c) < 127 for c in name):
        return False
    return ("." in name) or name.startswith("type:") or name.startswith("go:")


def parse(program):
    """Return ``{entry_address: name}`` from the program's gopclntab, or {}."""
    block = _find_block(program)
    if block is None:
        log_info("gopclntab parser: no .gopclntab block found")
        return {}
    try:
        data = _read_block_bytes(program, block)
    except Exception as exc:
        log_error("gopclntab parser: could not read block: %s" % exc)
        return {}
    return parse_bytes(data)


def parse_bytes(data):
    """``{entry_address: name}`` from raw ``.gopclntab`` bytes, or ``{}``.

    Split out from :func:`parse` so the table walk can be exercised on a
    synthetic table without a Ghidra program -- it is pure byte handling, and it
    is where the version-layout assumptions live.
    """
    if len(data) < 64:
        return {}
    minlc = data[6]
    ptr = data[7]
    if ptr not in (4, 8) or minlc not in (1, 2, 4):
        log_info("gopclntab parser: implausible header (ptr=%d minLC=%d)" % (ptr, minlc))
        return {}

    def rd(off, size=None):
        size = size or ptr
        return int.from_bytes(data[off:off + size], "little")

    try:
        nfunc = rd(8)
        text_start = rd(8 + 2 * ptr)
        funcname_off = rd(8 + 3 * ptr)
        pcln_off = rd(8 + 7 * ptr)
    except Exception:
        return {}

    if nfunc <= 0 or nfunc > 5_000_000:
        return {}
    if funcname_off >= len(data) or pcln_off >= len(data):
        log_info("gopclntab parser: offsets out of range (not Go 1.18+?)")
        return {}

    names = {}
    functab = pcln_off
    sample_seen = sample_good = 0
    for i in range(nfunc):
        rec = functab + i * 8
        if rec + 8 > len(data):
            break
        entry_off, func_off = struct.unpack("<II", data[rec:rec + 8])
        fs = pcln_off + func_off
        if fs + 8 > len(data):
            continue
        name_off = struct.unpack("<i", data[fs + 4:fs + 8])[0]
        pos = funcname_off + name_off
        if pos < 0 or pos >= len(data):
            continue
        end = data.find(b"\x00", pos)
        if end < 0:
            continue
        name = data[pos:end].decode("utf-8", "replace")
        if not name:
            continue
        if sample_seen < 64:
            sample_seen += 1
            if _looks_like_go_name(name):
                sample_good += 1
        names[text_start + entry_off] = name

    if sample_seen >= 8 and sample_good < sample_seen * 0.5:
        log_info("gopclntab parser: %d/%d sample names look wrong, deferring"
                 % (sample_good, sample_seen))
        return {}

    log_info("gopclntab parser: recovered %d names" % len(names))
    return names


def available():
    """The built-in parser is always available (no external dependency)."""
    return True
