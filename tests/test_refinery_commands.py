"""Tests for the refinery pipeline strings.

The backend emits two spellings of the same vstack invocation because the CLI
changed between refinery versions.  These are the exact strings that reproduce
the original Binary Ninja plugin's results, so the flags and the carve length are
load-bearing, not cosmetic.
"""

import pytest

from ungarble.backends.refinery_backend import _commands, is_executable


def test_the_modern_range_spelling_comes_first():
    modern, legacy = _commands(0x1000, 0x1050, 0x400000, True, None)
    assert "0x1000:0x1050" in modern, "modern vstack takes one positional range"
    assert "-s=0x1050 0x1000" in legacy, "legacy vstack took stop via -s"


def test_the_bulk_pipeline_matches_the_original_plugin():
    for command in _commands(0x1000, 0x1050, 0x400000, True, None):
        assert "vstack -C " in command
        assert command.endswith("| carve printable -n 8")


def test_the_single_row_pipeline_matches_the_original_plugin():
    for command in _commands(0x1000, 0x1050, 0x400000, False, None):
        assert "vstack -W -c -L " in command
        assert command.endswith("| carve printable -n 9")


def test_both_spellings_carry_the_image_base():
    for command in _commands(0x1000, 0x1050, 0x400000, True, None):
        assert "-b 0x400000" in command


def test_an_explicit_architecture_is_passed_through():
    for command in _commands(0x1000, 0x1050, 0x400000, True, "x64"):
        assert "-a x64" in command


def test_no_architecture_flag_when_refinery_can_infer_it():
    for command in _commands(0x1000, 0x1050, 0x400000, True, None):
        assert " -a " not in command


@pytest.mark.parametrize("magic", [
    b"MZ\x90\x00",
    b"\x7fELF\x02\x01\x01",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
])
def test_recognises_executable_images(magic):
    assert is_executable(magic)


@pytest.mark.parametrize("blob", [b"", b"\x00\x00\x00\x00", b"random bytes"])
def test_treats_anything_else_as_a_raw_blob(blob):
    assert not is_executable(blob)
