"""Regression test for the LEA misclassification in the side-effect guard.

Found end to end on a real garble binary: the guard rejected *every* location,
because Ghidra types the destination operand of ``LEA reg, [mem]`` as an address
with a WRITE ref type.  Reading the operand model naively therefore counted
``lea rbx, [rsp+0x3a]`` -- which appears in every garble sequence, right before
the call -- as a store to memory, and the whole feature yielded 0 patches.

Only the LEA short-circuit is reachable without a live Ghidra ``Program``; the
rest of ``_offstack_store`` needs real operand types and is covered by the
end-to-end run.  This pins the one line that made the difference between 0 and 45
patched locations.
"""

from ungarble.patcher import Patcher


class FakeInstruction:
    """Just enough of Ghidra's Instruction for the mnemonic short-circuit."""

    def __init__(self, mnemonic):
        self._mnemonic = mnemonic

    def getMnemonicString(self):
        return self._mnemonic

    def getNumOperands(self):
        raise AssertionError(
            "operands must not be inspected once the mnemonic rules the "
            "instruction out as a memory store"
        )


def bare_patcher(arch="amd64"):
    """A Patcher without a Program, for the paths that do not need one."""
    patcher = Patcher.__new__(Patcher)
    patcher.arch = arch
    return patcher


def test_lea_is_not_treated_as_a_memory_store():
    patcher = bare_patcher()
    assert patcher._offstack_store(FakeInstruction("LEA"), {}) is False


def test_the_check_is_case_insensitive():
    patcher = bare_patcher()
    for spelling in ("lea", "LEA", "Lea"):
        assert patcher._offstack_store(FakeInstruction(spelling), {}) is False


def test_lea_short_circuits_before_touching_ghidra():
    """The early return must come first -- both for speed and so this test runs.

    If the ``ghidra`` import moves above the mnemonic check, this fails with
    ModuleNotFoundError under plain CPython, which is the signal we want.
    """
    patcher = bare_patcher("arm64")
    assert patcher._offstack_store(FakeInstruction("lea"), {}) is False
