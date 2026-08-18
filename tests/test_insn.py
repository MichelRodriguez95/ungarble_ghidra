"""Tests for portable store detection.

The bug this guards against was expensive: the finder decided "does this
instruction write memory?" from ``getOperandRefType(i).isWrite()``, which is true
for x86's ``MOV [RSP+8], RDX`` but **false** for AArch64's ``STRB W6,[X7,X1]`` --
Ghidra types that operand as ``DATA``.  The callsite-anchored finder therefore
saw 192 locations on amd64 and 0 on arm64, because no arm64 store read as a write.

The p-code is the portable signal.  Fake Ghidra modules stand in here, since
neither API exists under plain CPython.
"""

import sys
import types

import pytest

import ungarble.insn as insn_mod


class FakePcodeOp:
    STORE = 3
    LOAD = 2
    COPY = 1
    INT_ADD = 4


class FakeOp:
    def __init__(self, opcode):
        self._opcode = opcode

    def getOpcode(self):
        return self._opcode


class FakeRefType:
    def __init__(self, write):
        self._write = write

    def isWrite(self):
        return self._write


class FakeInstruction:
    def __init__(self, pcode=None, ref_types=(), raise_pcode=False):
        self._pcode = pcode or []
        self._ref_types = ref_types
        self._raise = raise_pcode

    def getPcode(self):
        if self._raise:
            raise RuntimeError("no p-code for this instruction")
        return self._pcode

    def getNumOperands(self):
        return len(self._ref_types)

    def getOperandRefType(self, index):
        return self._ref_types[index]


@pytest.fixture(autouse=True)
def fake_pcode_module():
    """Install a fake ``ghidra.program.model.pcode`` exposing PcodeOp."""
    saved = {n: m for n, m in sys.modules.items()
             if n == "ghidra" or n.startswith("ghidra.")}
    for name in saved:
        del sys.modules[name]
    for name in ("ghidra", "ghidra.program", "ghidra.program.model"):
        sys.modules[name] = types.ModuleType(name)
    module = types.ModuleType("ghidra.program.model.pcode")
    module.PcodeOp = FakePcodeOp
    sys.modules["ghidra.program.model.pcode"] = module
    yield
    for name in list(sys.modules):
        if name == "ghidra" or name.startswith("ghidra."):
            del sys.modules[name]
    sys.modules.update(saved)


def test_a_store_op_means_the_instruction_writes_memory():
    """The arm64 case: refType says DATA, the p-code says STORE."""
    arm64_store = FakeInstruction(
        pcode=[FakeOp(FakePcodeOp.COPY), FakeOp(FakePcodeOp.INT_ADD),
               FakeOp(FakePcodeOp.STORE)],
        ref_types=(FakeRefType(False), FakeRefType(False)),
    )
    assert insn_mod.writes_memory(arm64_store) is True


def test_a_load_only_instruction_does_not_write_memory():
    load = FakeInstruction(
        pcode=[FakeOp(FakePcodeOp.INT_ADD), FakeOp(FakePcodeOp.LOAD)],
        ref_types=(FakeRefType(False), FakeRefType(False)),
    )
    assert insn_mod.writes_memory(load) is False


def test_an_instruction_touching_no_memory_does_not_write_memory():
    arithmetic = FakeInstruction(pcode=[FakeOp(FakePcodeOp.INT_ADD)])
    assert insn_mod.writes_memory(arithmetic) is False


def test_the_x86_case_still_works():
    x86_store = FakeInstruction(
        pcode=[FakeOp(FakePcodeOp.STORE)],
        ref_types=(FakeRefType(True), FakeRefType(False)),
    )
    assert insn_mod.writes_memory(x86_store) is True


def test_falls_back_to_ref_types_when_pcode_is_unavailable():
    no_pcode = FakeInstruction(ref_types=(FakeRefType(True),), raise_pcode=True)
    assert insn_mod.writes_memory(no_pcode) is True

    no_pcode_no_write = FakeInstruction(
        ref_types=(FakeRefType(False),), raise_pcode=True)
    assert insn_mod.writes_memory(no_pcode_no_write) is False


def test_the_fallback_survives_an_instruction_that_answers_nothing():
    class Hostile:
        def getPcode(self):
            raise RuntimeError("nope")

        def getNumOperands(self):
            raise RuntimeError("nope either")

    assert insn_mod.writes_memory(Hostile()) is False
