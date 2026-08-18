"""Tests for reading a GoResolver ``resolve`` report.

Graph-matched names from a report take precedence over the gopclntab baseline,
so a parsing slip here silently drops the only source of *de-hashed* names.
"""

import json

import pytest

from ungarble.symbols import load_goresolver_report


def write(tmp_path, payload):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(payload))
    return str(path)


def test_reads_the_symbols_map(tmp_path):
    path = write(tmp_path, {"Symbols": {
        "0x401000": {"Name": "main.checkPassword"},
        "0x401100": {"Name": "main.main"},
    }})
    assert load_goresolver_report(path) == {
        0x401000: "main.checkPassword",
        0x401100: "main.main",
    }


def test_accepts_a_bare_mapping_without_the_symbols_wrapper(tmp_path):
    path = write(tmp_path, {"0x401000": {"Name": "runtime.main"}})
    assert load_goresolver_report(path) == {0x401000: "runtime.main"}


def test_accepts_a_plain_string_value(tmp_path):
    path = write(tmp_path, {"Symbols": {"0x401000": "runtime.main"}})
    assert load_goresolver_report(path) == {0x401000: "runtime.main"}


def test_parses_hex_keys_with_and_without_the_prefix(tmp_path):
    path = write(tmp_path, {"Symbols": {
        "0x401000": {"Name": "a.a"},
        "401100": {"Name": "b.b"},
    }})
    assert load_goresolver_report(path) == {0x401000: "a.a", 0x401100: "b.b"}


def test_accepts_an_integer_key(tmp_path):
    assert load_goresolver_report(write(tmp_path, {"Symbols": {}})) == {}


def test_skips_unparseable_keys_instead_of_failing(tmp_path):
    path = write(tmp_path, {"Symbols": {
        "not-an-address": {"Name": "junk.junk"},
        "0x401000": {"Name": "real.real"},
    }})
    assert load_goresolver_report(path) == {0x401000: "real.real"}


def test_skips_entries_with_no_name(tmp_path):
    path = write(tmp_path, {"Symbols": {
        "0x401000": {"Name": ""},
        "0x401100": {"Other": "field"},
        "0x401200": {"Name": "kept.kept"},
    }})
    assert load_goresolver_report(path) == {0x401200: "kept.kept"}


def test_an_empty_report_yields_nothing(tmp_path):
    assert load_goresolver_report(write(tmp_path, {"Symbols": {}})) == {}


def test_a_missing_file_raises_rather_than_silently_returning_nothing(tmp_path):
    with pytest.raises(OSError):
        load_goresolver_report(str(tmp_path / "absent.json"))
