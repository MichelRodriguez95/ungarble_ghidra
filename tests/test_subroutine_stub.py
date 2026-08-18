"""Tests for the whole-function replacement stub.

The split and seed obfuscators put their decoder in a dedicated function, so the
patch replaces the function rather than a region inside a caller.  That makes the
`call` target *relative to where the stub is placed*, which the region stub never
had to compute -- get it wrong and the patched binary calls into the middle of
something else.

As with the region stubs these decode what they build instead of comparing golden
bytes, so a self-consistent rewrite of the arithmetic still fails.
"""

import struct

import pytest

from ungarble.patcher import build_subroutine_stub

FUNC_VA = 0x4F9740
CALLEE_VA = 0x44E3E0


def decode_amd64(stub, stub_va):
    assert stub[0:2] == b"\x31\xc0", "xor eax, eax"
    assert stub[2:5] == b"\x48\x8d\x1d", "lea rbx, [rip+disp32]"
    disp = struct.unpack_from("<i", stub, 5)[0]
    data_start = 9 + disp
    assert stub[9] == 0xB9, "mov ecx, imm32"
    length = struct.unpack_from("<I", stub, 10)[0]
    assert stub[14] == 0xE8, "call rel32"
    rel = struct.unpack_from("<i", stub, 15)[0]
    callee = stub_va + 19 + rel
    assert stub[19] == 0xC3, "ret"
    return {"data_start": data_start, "length": length, "callee": callee}


def _sign_extend(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


PUSH_LR = 0xF81F0FFE
POP_LR = 0xF84107FE
ARM_RET = 0xD65F03C0


def decode_arm64(stub, stub_va):
    words = [struct.unpack_from("<I", stub, i)[0] for i in range(0, 28, 4)]
    push, movz_x0, adr_x1, movz_w2, branch, pop, ret = words
    assert push == PUSH_LR, "must save the link register before the bl"
    assert pop == POP_LR, "must restore the link register after the bl"
    assert movz_x0 & 0xFF800000 == 0xD2800000 and movz_x0 & 0x1F == 0
    assert (movz_x0 >> 5) & 0xFFFF == 0, "x0 must be nil"
    assert adr_x1 & 0x9F000000 == 0x10000000 and adr_x1 & 0x1F == 1
    immlo, immhi = (adr_x1 >> 29) & 0x3, (adr_x1 >> 5) & 0x7FFFF
    data_start = 8 + _sign_extend((immhi << 2) | immlo, 21)
    assert movz_w2 & 0xFF800000 == 0x52800000 and movz_w2 & 0x1F == 2
    length = (movz_w2 >> 5) & 0xFFFF
    assert branch & 0xFC000000 == 0x94000000, "bl"
    callee = stub_va + 16 + _sign_extend(branch & 0x3FFFFFF, 26) * 4
    assert ret == ARM_RET, "ret"
    return {"data_start": data_start, "length": length, "callee": callee}


def test_arm64_saves_and_restores_the_link_register_around_the_call():
    """The bug that hung the patched binary: bl clobbers x30."""
    stub = build_subroutine_stub("arm64", 128, b"abcd", 4, 0x9EE40, 0x5F720)
    words = [struct.unpack_from("<I", stub, i)[0] for i in range(0, 28, 4)]
    bl_index = next(i for i, w in enumerate(words)
                    if w & 0xFC000000 == 0x94000000)
    ret_index = next(i for i, w in enumerate(words) if w == ARM_RET)
    assert PUSH_LR in words[:bl_index], "save comes before the bl"
    assert POP_LR in words[bl_index + 1:ret_index], "restore between bl and ret"


@pytest.mark.parametrize("payload", [b"a", b"hola mundo", b"x" * 200,
                                     bytes(range(0x20, 0x7F))])
def test_amd64_points_at_the_plaintext_and_calls_the_right_callee(payload):
    stub = build_subroutine_stub("amd64", len(payload) + 128, payload,
                                 len(payload), FUNC_VA, CALLEE_VA)
    decoded = decode_amd64(stub, FUNC_VA)
    start = decoded["data_start"]
    assert stub[start:start + len(payload)] == payload
    assert decoded["length"] == len(payload)
    assert decoded["callee"] == CALLEE_VA


@pytest.mark.parametrize("callee", [0x401000, 0x44E3E0, 0x7FFFFF, FUNC_VA + 0x40])
def test_amd64_call_is_relative_to_where_the_stub_lands(callee):
    """A backward *and* a forward call have to encode correctly."""
    stub = build_subroutine_stub("amd64", 128, b"abcd", 4, FUNC_VA, callee)
    assert decode_amd64(stub, FUNC_VA)["callee"] == callee


def test_amd64_pads_with_traps_to_the_original_size():
    region = 300
    stub = build_subroutine_stub("amd64", region, b"abcd", 4, FUNC_VA, CALLEE_VA)
    assert len(stub) == region, "the function must keep its size"
    tail = stub[20 + 4:]
    assert tail and all(b == 0xCC for b in tail), "padding must trap, not flow"


def test_amd64_rejects_a_function_too_small():
    assert build_subroutine_stub("amd64", 24, b"abcd", 4, FUNC_VA, CALLEE_VA)
    assert build_subroutine_stub("amd64", 23, b"abcd", 4, FUNC_VA, CALLEE_VA) is None


@pytest.mark.parametrize("payload", [b"a", b"abcd", b"abcde", b"y" * 100])
def test_arm64_points_at_the_plaintext_and_calls_the_right_callee(payload):
    region = len(payload) + 128
    region -= region % 4
    stub = build_subroutine_stub("arm64", region, payload, len(payload),
                                 0x9EE40, 0x5F720)
    decoded = decode_arm64(stub, 0x9EE40)
    start = decoded["data_start"]
    assert stub[start:start + len(payload)] == payload
    assert decoded["length"] == len(payload)
    assert decoded["callee"] == 0x5F720


@pytest.mark.parametrize("callee", [0x1000, 0x5F720, 0x9EE40 + 0x400])
def test_arm64_bl_is_relative_to_where_the_stub_lands(callee):
    stub = build_subroutine_stub("arm64", 128, b"abcd", 4, 0x9EE40, callee)
    assert decode_arm64(stub, 0x9EE40)["callee"] == callee


@pytest.mark.parametrize("size", [1, 2, 3, 4, 17])
def test_arm64_keeps_everything_four_aligned(size):
    payload = b"z" * size
    region = size + 128 - ((size + 128) % 4)
    stub = build_subroutine_stub("arm64", region, payload, size, 0x9EE40, 0x5F720)
    assert len(stub) == region
    assert decode_arm64(stub, 0x9EE40)["data_start"] % 4 == 0


def test_rejects_a_missing_callee():
    assert build_subroutine_stub("amd64", 128, b"abcd", 4, FUNC_VA, None) is None
    assert build_subroutine_stub("arm64", 128, b"abcd", 4, 0x9EE40, None) is None


def test_rejects_an_unknown_architecture():
    assert build_subroutine_stub("riscv64", 256, b"abcd", 4, 0, 0x100) is None


def test_rejects_a_length_longer_than_the_plaintext():
    assert build_subroutine_stub("amd64", 128, b"abc", 8, FUNC_VA, CALLEE_VA) is None


def test_arm64_rejects_a_length_wider_than_movz():
    payload = b"a" * 0x10000
    assert build_subroutine_stub("arm64", 0x20000, payload, 0x10000,
                                 0x9EE40, 0x5F720) is None


@pytest.mark.parametrize("arch,stub_va,callee", [("amd64", FUNC_VA, CALLEE_VA),
                                                ("arm64", 0x9EE40, 0x5F720)])
def test_only_the_callsite_length_is_inlined(arch, stub_va, callee):
    stub = build_subroutine_stub(arch, 256, b"wanted" + b"JUNKJUNK", 6,
                                 stub_va, callee)
    decoded = (decode_amd64(stub, stub_va) if arch == "amd64"
               else decode_arm64(stub, stub_va))
    assert decoded["length"] == 6
    start = decoded["data_start"]
    assert stub[start:start + 6] == b"wanted"
    assert b"JUNK" not in stub


def test_the_morestack_tail_allowance_is_a_tail_not_a_function():
    """A `call morestack` + `jmp back` tail is 10 bytes; the bound must fit it
    and must not fit real trailing code."""
    from ungarble.patcher import MAX_MORESTACK_TAIL

    assert 10 <= MAX_MORESTACK_TAIL <= 64


def test_the_subroutine_call_offset_matches_the_stub_layout():
    """SUB_CALL_OFFSET is where re-emulation has to stop, so it must be exactly
    where build_subroutine_stub puts the call."""
    from ungarble.patcher import SUB_CALL_OFFSET

    stub = build_subroutine_stub("amd64", 128, b"abcd", 4, FUNC_VA, CALLEE_VA)
    assert stub[SUB_CALL_OFFSET["amd64"]] == 0xE8, "amd64 call sits here"

    stub = build_subroutine_stub("arm64", 128, b"abcd", 4, 0x9EE40, 0x5F720)
    offset = SUB_CALL_OFFSET["arm64"]
    word = struct.unpack_from("<I", stub, offset)[0]
    assert word & 0xFC000000 == 0x94000000, "arm64 bl sits here"
