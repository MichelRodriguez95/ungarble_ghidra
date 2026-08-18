"""Tests for the comment-type resolution.

Ghidra replaced ``CodeUnit.EOL_COMMENT`` with a ``CommentType`` enum.  Four call
sites need that resolved and one of them used to import the enum unguarded,
which took out name recovery entirely on the older API.  Both branches are
exercised here by standing in fake ``ghidra`` modules, since neither API is
importable in a plain CPython test run.
"""

import sys
import types

import pytest

import ungarble.compat as compat


@pytest.fixture(autouse=True)
def clean_state():
    """Drop the resolution cache and any fake ghidra modules around each test."""
    saved = {name: mod for name, mod in sys.modules.items()
             if name == "ghidra" or name.startswith("ghidra.")}
    for name in saved:
        del sys.modules[name]
    compat._CACHE.clear()
    yield
    for name in list(sys.modules):
        if name == "ghidra" or name.startswith("ghidra."):
            del sys.modules[name]
    sys.modules.update(saved)
    compat._CACHE.clear()


def install_listing(**members):
    """Register a fake ``ghidra.program.model.listing`` exposing *members*."""
    for name in ("ghidra", "ghidra.program", "ghidra.program.model"):
        sys.modules.setdefault(name, types.ModuleType(name))
    listing = types.ModuleType("ghidra.program.model.listing")
    for key, value in members.items():
        setattr(listing, key, value)
    sys.modules["ghidra.program.model.listing"] = listing
    return listing


class ModernCommentType:
    EOL = "enum:EOL"
    PRE = "enum:PRE"
    PLATE = "enum:PLATE"
    POST = "enum:POST"
    REPEATABLE = "enum:REPEATABLE"


class LegacyCodeUnit:
    EOL_COMMENT = 0
    PRE_COMMENT = 1
    POST_COMMENT = 2
    PLATE_COMMENT = 3
    REPEATABLE_COMMENT = 4


@pytest.mark.parametrize("kind", ["EOL", "PRE", "PLATE"])
def test_prefers_the_enum_when_present(kind):
    install_listing(CommentType=ModernCommentType, CodeUnit=LegacyCodeUnit)
    assert compat.comment_type(kind) == "enum:%s" % kind


@pytest.mark.parametrize("kind,expected", [
    ("EOL", 0), ("PRE", 1), ("PLATE", 3),
])
def test_falls_back_to_the_integer_constants(kind, expected):
    """The case that used to break: no CommentType on this Ghidra."""
    install_listing(CodeUnit=LegacyCodeUnit)
    assert compat.comment_type(kind) == expected


def test_falls_back_when_the_enum_lacks_the_member():
    class Partial:
        EOL = "enum:EOL"

    install_listing(CommentType=Partial, CodeUnit=LegacyCodeUnit)
    assert compat.comment_type("EOL") == "enum:EOL"
    assert compat.comment_type("PLATE") == 3


def test_kind_is_case_insensitive():
    install_listing(CommentType=ModernCommentType, CodeUnit=LegacyCodeUnit)
    assert compat.comment_type("eol") == "enum:EOL"
    assert compat.comment_type("Plate") == "enum:PLATE"


def test_resolution_is_cached():
    install_listing(CommentType=ModernCommentType, CodeUnit=LegacyCodeUnit)
    assert compat.comment_type("EOL") == "enum:EOL"
    del sys.modules["ghidra.program.model.listing"]
    assert compat.comment_type("EOL") == "enum:EOL"


def test_set_comment_passes_the_resolved_type_through():
    install_listing(CommentType=ModernCommentType, CodeUnit=LegacyCodeUnit)
    calls = []

    class Listing:
        def setComment(self, address, kind, text):
            calls.append((address, kind, text))

    compat.set_comment(Listing(), 0x401000, "PRE", "ungarbled: hi")
    assert calls == [(0x401000, "enum:PRE", "ungarbled: hi")]


def test_every_kind_the_plugin_uses_has_a_legacy_mapping():
    """Guards the class of bug this module exists to prevent."""
    for kind in ("EOL", "PRE", "PLATE"):
        assert kind in compat._LEGACY
