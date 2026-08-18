"""Tests for the pure-python stand-in for refinery's ``carve printable``.

The PCode backend falls back to this when the register ABI read looks
implausible, so it decides what a recovered string looks like whenever emulation
drifts.
"""

from ungarble.carve import best_printable, carve_printable


def test_finds_runs_at_or_above_the_minimum_length():
    data = b"\x00short\x00" + b"A" * 8 + b"\x00"
    assert carve_printable(data, 8) == [b"A" * 8]


def test_excludes_runs_below_the_minimum():
    assert carve_printable(b"\x00abcdefg\x00", 8) == []
    assert carve_printable(b"\x00abcdefgh\x00", 8) == [b"abcdefgh"]


def test_returns_every_qualifying_run_in_order():
    data = b"\x00" + b"first_run" + b"\x00\x00" + b"second_run" + b"\xff"
    assert carve_printable(data, 8) == [b"first_run", b"second_run"]


def test_a_run_ending_at_the_buffer_end_is_not_dropped():
    assert carve_printable(b"\x00" + b"trailing", 8) == [b"trailing"]


def test_tab_newline_and_carriage_return_count_as_printable():
    data = b"\x00" + b"a\tb\nc\rdefg" + b"\x00"
    assert carve_printable(data, 8) == [b"a\tb\nc\rdefg"]


def test_high_bytes_break_a_run():
    assert carve_printable(b"abcdefgh\x80abcdefgh", 8) == [
        b"abcdefgh", b"abcdefgh",
    ]


def test_best_printable_picks_the_longest_run():
    data = b"\x00" + b"shortrun1" + b"\x00" + b"the_longest_run_here" + b"\x00"
    assert best_printable(data, 8) == "the_longest_run_here"


def test_best_printable_is_empty_when_nothing_qualifies():
    assert best_printable(b"\x00\x01\x02", 8) == ""
    assert best_printable(b"", 8) == ""
    assert best_printable(b"abc", 8) == ""


def test_the_minimum_length_is_honoured_by_best_printable():
    data = b"\x00" + b"12345678" + b"\x00"
    assert best_printable(data, 8) == "12345678"
    assert best_printable(data, 9) == ""
