"""Tests for the built-in gopclntab parser.

This parser is the reason name recovery works with nothing installed, and it
carries two assumptions that nothing else in the plugin would catch if they
broke: the Go 1.18+ field order in the pcHeader, and the decision to *ignore the
magic* so garble's randomised header still parses.

The synthetic table below is the smallest thing that exercises both.
"""

import struct

import pytest

from ungarble.gopclntab import parse_bytes

CANONICAL_MAGIC = 0xFFFFFFF1
GARBLE_MAGIC = 0xA0AB2568


def build_pclntab(names, *, text_start=0x400000, ptr=8, minlc=1,
                  magic=CANONICAL_MAGIC, sentinel=True,
                  funcname_off=None, pcln_off=None):
    """Assemble a Go 1.18+ style ``.gopclntab``.

    *names* is a list of ``(entry_offset, name)``.  An empty name means the
    ``_func`` points at the funcnametab's leading NUL sentinel, which is what a
    real table's first entry does.

    Layout the parser depends on::

        +0   magic (4)      -- ignored on purpose: garble randomises it
        +6   minLC (1)
        +7   ptrSize (1)
        +8   nfunc, nfiles, textStart, funcnameOffset, cuOffset,
             filetabOffset, pctabOffset, pclnOffset      (ptr-sized each)

    then the funcnametab, then at ``pclnOffset`` the functab: one
    ``(entryOff, funcOff)`` pair of uint32 per function, followed by the
    ``_func`` structs whose ``nameOff`` sits at +4.
    """
    header_size = 8 + 8 * ptr

    nametab = bytearray(b"\x00") if sentinel else bytearray()
    name_offsets = []
    for _, name in names:
        if name == "":
            name_offsets.append(0)
            continue
        name_offsets.append(len(nametab))
        nametab += name.encode() + b"\x00"

    nfunc = len(names)
    functab_size = (nfunc + 1) * 8

    functab = bytearray()
    funcs = bytearray()
    for (entry_off, _), name_off in zip(names, name_offsets):
        func_off = functab_size + len(funcs)
        functab += struct.pack("<II", entry_off, func_off)
        funcs += struct.pack("<Ii", entry_off, name_off)
    functab += struct.pack("<II", 0xFFFFFFFF, 0)

    resolved_funcname_off = header_size if funcname_off is None else funcname_off
    resolved_pcln_off = (
        header_size + len(nametab) if pcln_off is None else pcln_off
    )

    header = bytearray(struct.pack("<I", magic))
    header += b"\x00\x00"
    header += bytes((minlc, ptr))
    for field in (nfunc, 0, text_start, resolved_funcname_off,
                  0, 0, 0, resolved_pcln_off):
        header += int(field).to_bytes(ptr, "little")

    return bytes(header + nametab + functab + funcs)


GO_NAMES = [
    (0x1000, "runtime.main"),
    (0x1100, "runtime.gcStart"),
    (0x1200, "main.main"),
    (0x1300, "main.fwKj4nfcNL25"),
    (0x1400, "type:.eq.runtime._type"),
    (0x1500, "go:buildid"),
    (0x1600, "sync.(*Mutex).Lock"),
    (0x1700, "internal/poll.(*FD).Read"),
    (0x1800, "os.OpenFile"),
    (0x1900, "fmt.Sprintf"),
]


def test_recovers_every_name_at_its_text_relative_entry():
    table = build_pclntab(GO_NAMES)
    assert parse_bytes(table) == {
        0x400000 + off: name for off, name in GO_NAMES
    }


def test_ignores_a_randomised_magic():
    """garble randomises the pcHeader magic; a parser that validates it bails.

    This is the whole reason the plugin does not just use Ghidra's Go analyzer,
    so it is worth pinning down.
    """
    expected = {0x400000 + off: name for off, name in GO_NAMES}
    assert parse_bytes(build_pclntab(GO_NAMES, magic=GARBLE_MAGIC)) == expected
    assert parse_bytes(build_pclntab(GO_NAMES, magic=0x00000000)) == expected
    assert parse_bytes(build_pclntab(GO_NAMES, magic=0xDEADBEEF)) == expected


def test_the_empty_name_sentinel_does_not_make_the_parser_defer():
    """Regression: an empty name is normal, not evidence of a bad layout.

    The funcnametab starts with a NUL sentinel, so a _func can legitimately
    resolve to "".  Counting those against the plausibility sample made the
    parser return {} on real binaries.
    """
    table = build_pclntab([(0x900, "")] + GO_NAMES)
    recovered = parse_bytes(table)
    assert recovered == {0x400000 + off: name for off, name in GO_NAMES}


def test_defers_when_the_names_do_not_look_like_go_symbols():
    """A wrong layout yields plausible-length garbage; better to hand over."""
    junk = [(0x1000 + i * 0x100, "zzzz%d" % i) for i in range(10)]
    assert parse_bytes(build_pclntab(junk)) == {}


def test_defers_on_a_mixed_but_mostly_wrong_sample():
    mostly_junk = [(0x1000 + i * 0x100, "qqq%d" % i) for i in range(9)]
    mostly_junk += [(0x2000, "runtime.main"), (0x2100, "main.main")]
    assert parse_bytes(build_pclntab(mostly_junk)) == {}


def test_keeps_a_small_all_good_sample():
    few = [(0x1000, "runtime.main"), (0x1100, "main.main")]
    assert parse_bytes(build_pclntab(few)) == {
        0x401000: "runtime.main", 0x401100: "main.main",
    }


@pytest.mark.parametrize("ptr", [0, 1, 3, 5, 16])
def test_rejects_an_implausible_pointer_size(ptr):
    table = bytearray(build_pclntab(GO_NAMES))
    table[7] = ptr
    assert parse_bytes(bytes(table)) == {}


@pytest.mark.parametrize("minlc", [0, 3, 5, 255])
def test_rejects_an_implausible_min_instruction_length(minlc):
    table = bytearray(build_pclntab(GO_NAMES))
    table[6] = minlc
    assert parse_bytes(bytes(table)) == {}


def test_rejects_a_table_too_short_to_hold_a_header():
    assert parse_bytes(b"") == {}
    assert parse_bytes(b"\x00" * 63) == {}


def test_rejects_offsets_that_point_outside_the_table():
    assert parse_bytes(build_pclntab(GO_NAMES, funcname_off=1 << 30)) == {}
    assert parse_bytes(build_pclntab(GO_NAMES, pcln_off=1 << 30)) == {}


def test_rejects_an_absurd_function_count():
    table = bytearray(build_pclntab(GO_NAMES))
    table[8:16] = (6_000_000).to_bytes(8, "little")
    assert parse_bytes(bytes(table)) == {}
    table[8:16] = (0).to_bytes(8, "little")
    assert parse_bytes(bytes(table)) == {}


def test_survives_a_truncated_table_without_raising():
    full = build_pclntab(GO_NAMES)
    for cut in range(64, len(full), 7):
        parse_bytes(full[:cut])


def test_text_start_shifts_every_recovered_address():
    table = build_pclntab(GO_NAMES, text_start=0x800000)
    assert parse_bytes(table) == {
        0x800000 + off: name for off, name in GO_NAMES
    }
