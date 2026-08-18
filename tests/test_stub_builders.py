"""Tests for the replacement-stub encoders.

These are the highest-risk lines in the plugin: a wrong displacement produces a
binary that still runs, still passes a superficial look, and hands
``slicebytetostring`` the wrong bytes.  They are also the cheapest thing here to
test -- pure functions over ``bytes``, no Ghidra involved.

The tests *decode* each stub instead of comparing against golden hex, so they
fail when a displacement stops pointing at the inline data rather than merely
when a byte changes.  A golden-bytes test would pass a rewrite that broke the
arithmetic in a self-consistent way.
"""

import pytest

from ungarble.patcher import build_stub


_X_NOP = 0x90


def decode_amd64(stub):
    """Decode the amd64 stub: xor / lea / mov / jmp / data / nops."""
    assert stub[0:2] == b"\x31\xc0", "expected xor eax, eax"
    assert stub[2:5] == b"\x48\x8d\x1d", "expected lea rbx, [rip+disp32]"
    disp = int.from_bytes(stub[5:9], "little", signed=True)
    data_start = 9 + disp

    assert stub[9] == 0xB9, "expected mov ecx, imm32"
    length = int.from_bytes(stub[10:14], "little")

    opcode = stub[14]
    if opcode == 0xEB:
        rel = int.from_bytes(stub[15:16], "little", signed=True)
        over = 16 + rel
        jmp_len = 2
    elif opcode == 0xE9:
        rel = int.from_bytes(stub[15:19], "little", signed=True)
        over = 19 + rel
        jmp_len = 5
    else:
        raise AssertionError("expected a jmp at offset 14, got %#04x" % opcode)

    return {
        "data_start": data_start,
        "length": length,
        "over": over,
        "jmp_len": jmp_len,
    }


def _sign_extend(value, bits):
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


def decode_arm64(stub):
    """Decode the arm64 stub: movz x0 / adr x1 / movz w2 / b / data / nops."""
    words = [int.from_bytes(stub[i:i + 4], "little") for i in range(0, 16, 4)]
    movz_x0, adr_x1, movz_w2, branch = words

    assert movz_x0 & 0xFF800000 == 0xD2800000, "expected 64-bit movz"
    assert movz_x0 & 0x1F == 0, "movz must target x0"
    assert (movz_x0 >> 5) & 0xFFFF == 0, "x0 must be zeroed (nil tmp buffer)"

    assert adr_x1 & 0x9F000000 == 0x10000000, "expected adr"
    assert adr_x1 & 0x1F == 1, "adr must target x1"
    immlo = (adr_x1 >> 29) & 0x3
    immhi = (adr_x1 >> 5) & 0x7FFFF
    adr_offset = _sign_extend((immhi << 2) | immlo, 21)
    data_start = 4 + adr_offset

    assert movz_w2 & 0xFF800000 == 0x52800000, "expected 32-bit movz"
    assert movz_w2 & 0x1F == 2, "movz must target w2"
    length = (movz_w2 >> 5) & 0xFFFF

    assert branch & 0xFC000000 == 0x14000000, "expected unconditional b"
    over = 12 + _sign_extend(branch & 0x3FFFFFF, 26) * 4

    return {"data_start": data_start, "length": length, "over": over}


@pytest.mark.parametrize("payload", [
    b"a",
    b"hello",
    b"/tmp/very/long/path/to/something",
    bytes(range(0x20, 0x7F)),
    b"x" * 200,
])
def test_amd64_lea_points_at_the_inline_plaintext(payload):
    region = len(payload) + 64
    stub = build_stub("amd64", region, payload, len(payload))
    decoded = decode_amd64(stub)
    start = decoded["data_start"]
    assert stub[start:start + len(payload)] == payload
    assert decoded["length"] == len(payload)


@pytest.mark.parametrize("size", [1, 5, 127, 128, 300])
def test_amd64_jmp_lands_immediately_after_the_data(size):
    payload = b"z" * size
    stub = build_stub("amd64", size + 64, payload, size)
    decoded = decode_amd64(stub)
    assert decoded["over"] == decoded["data_start"] + size


@pytest.mark.parametrize("size", [1, 40, 127, 128, 300])
def test_amd64_pads_to_exactly_the_region(size):
    payload = b"q" * size
    region = size + 37
    stub = build_stub("amd64", region, payload, size)
    assert len(stub) == region, "the patch must be byte-for-byte the same size"
    over = decode_amd64(stub)["over"]
    assert all(b == _X_NOP for b in stub[over:]), "tail must be nops up to the call"


def test_amd64_switches_to_a_near_jump_past_the_rel8_limit():
    assert decode_amd64(build_stub("amd64", 400, b"a" * 127, 127))["jmp_len"] == 2
    assert decode_amd64(build_stub("amd64", 400, b"a" * 128, 128))["jmp_len"] == 5


def test_amd64_rejects_a_region_too_small_for_the_stub():
    payload = b"abcdefgh"
    assert build_stub("amd64", 16 + len(payload), payload, len(payload)) is not None
    assert build_stub("amd64", 15 + len(payload), payload, len(payload)) is None
    assert build_stub("amd64", 4, payload, len(payload)) is None


def test_amd64_minimum_viable_region_is_exact():
    payload = b"hi"
    stub = build_stub("amd64", 18, payload, 2)
    assert len(stub) == 18
    decoded = decode_amd64(stub)
    assert stub[decoded["data_start"]:decoded["data_start"] + 2] == payload


@pytest.mark.parametrize("payload", [
    b"a",
    b"abcd",
    b"abcde",
    b"go string here",
    b"y" * 100,
])
def test_arm64_adr_points_at_the_inline_plaintext(payload):
    region = len(payload) + 64
    region -= region % 4
    stub = build_stub("arm64", region, payload, len(payload))
    decoded = decode_arm64(stub)
    start = decoded["data_start"]
    assert stub[start:start + len(payload)] == payload
    assert decoded["length"] == len(payload)


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 17, 64])
def test_arm64_branch_clears_the_data_and_its_alignment_padding(size):
    payload = b"w" * size
    stub = build_stub("arm64", size + 64 - ((size + 64) % 4), payload, size)
    decoded = decode_arm64(stub)
    padded = size + (-size % 4)
    assert decoded["over"] == decoded["data_start"] + padded
    assert decoded["over"] % 4 == 0, "execution must resume 4-aligned"


@pytest.mark.parametrize("size", [1, 2, 3, 8, 33])
def test_arm64_tail_is_nop_instructions_to_the_region_end(size):
    payload = b"k" * size
    region = size + 64 - ((size + 64) % 4)
    stub = build_stub("arm64", region, payload, size)
    assert len(stub) == region
    tail = stub[decode_arm64(stub)["over"]:]
    assert len(tail) % 4 == 0
    assert all(
        tail[i:i + 4] == b"\x1f\x20\x03\xd5" for i in range(0, len(tail), 4)
    ), "tail must be arm64 nops"


def test_arm64_rejects_a_length_wider_than_movz():
    payload = b"a" * 0x10000
    assert build_stub("arm64", 0x20000, payload, 0x10000) is None
    assert build_stub("arm64", 0x20000, b"a" * 0xFFFF, 0xFFFF) is not None


def test_arm64_rejects_a_region_that_cannot_be_filled_with_whole_nops():
    payload = b"abcd"
    assert build_stub("arm64", 24, payload, 4) is not None
    for unusable in (21, 22, 23):
        assert build_stub("arm64", unusable, payload, 4) is None


def test_arm64_rejects_a_region_too_small():
    assert build_stub("arm64", 16, b"abcd", 4) is None


def test_build_stub_rejects_an_unknown_architecture():
    assert build_stub("riscv64", 128, b"abcd", 4) is None
    assert build_stub("386", 128, b"abcd", 4) is None


def test_build_stub_rejects_a_length_longer_than_the_plaintext():
    assert build_stub("amd64", 128, b"abc", 8) is None
    assert build_stub("arm64", 128, b"abc", 8) is None


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_build_stub_inlines_only_the_callsite_length(arch):
    stub = build_stub(arch, 128, b"wanted" + b"JUNKJUNK", 6)
    decoded = decode_amd64(stub) if arch == "amd64" else decode_arm64(stub)
    assert decoded["length"] == 6
    start = decoded["data_start"]
    assert stub[start:start + 6] == b"wanted"
    assert b"JUNK" not in stub
