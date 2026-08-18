"""Instruction-level helpers shared by the finder and the patcher.

They live here because both need the same question answered -- *does this
instruction write memory, and where* -- and getting it wrong is expensive in
opposite directions: the finder misses sequences, the patcher corrupts code.

The reason it needs a helper at all: **operand ref types do not identify stores
portably.** On x86 the destination operand of ``MOV [RSP+8], RDX`` comes back as
``refType=WRITE``, but on AArch64 the memory operand of ``STRB W6,[X7,X1]`` comes
back as ``refType=DATA`` with ``isWrite() == False`` -- so a check built on
``getOperandRefType`` silently sees no stores at all on arm64.  Measured
consequence before this existed: the callsite-anchored finder found 192 locations
on amd64 and **0** on arm64, purely because every arm64 buffer write read as
"not a write".

The p-code is the portable answer: a store lowers to a ``STORE`` op on every
processor Ghidra models.
"""


def writes_memory(insn):
    """Whether *insn* writes to memory, per its p-code.

    Falls back to the operand ref types if p-code is unavailable for some
    instruction, so this can only ever be more permissive than the old check.
    """
    try:
        from ghidra.program.model.pcode import PcodeOp

        for op in insn.getPcode():
            if op.getOpcode() == PcodeOp.STORE:
                return True
        return False
    except Exception:
        return _writes_memory_by_ref_type(insn)


def _writes_memory_by_ref_type(insn):
    try:
        for index in range(insn.getNumOperands()):
            ref_type = insn.getOperandRefType(index)
            if ref_type is not None and ref_type.isWrite():
                return True
    except Exception:
        pass
    return False


def frame_offset(insn, index, stack_registers, aliases):
    """Frame offset of memory operand *index*, resolving ``sp+k`` aliases.

    arm64 rarely addresses a buffer off ``sp`` directly: it materialises the
    address first (``add x27, sp, #0x136``) and then stores through ``[x27]``, so
    the base register has to be traced back to the frame.  amd64 does the same
    with ``lea``.  Ghidra returns operand objects in addressing order (base,
    index, scale, displacement), so the base is the first register -- except that
    a scaled operand with no displacement carries the scale as its only scalar
    and must read as offset 0.
    """
    from ghidra.program.model.lang import Register
    from ghidra.program.model.scalar import Scalar

    objects = list(insn.getOpObjects(index))
    registers = [o for o in objects if isinstance(o, Register)]
    if not registers:
        return None
    scalars = [o for o in objects if isinstance(o, Scalar)]
    if len(scalars) == 1 and len(registers) > 1:
        displacement = 0
    elif scalars:
        displacement = int(scalars[-1].getUnsignedValue())
    else:
        displacement = 0

    base = base_register_name(registers[0])
    if base in stack_registers:
        return displacement
    if base in aliases:
        return aliases[base] + displacement
    return None


def base_register_name(register):
    """Widest register containing *register* (``w6`` -> ``X6``), uppercased."""
    try:
        base = register.getBaseRegister()
        if base is not None:
            register = base
    except Exception:
        pass
    return str(register.getName()).upper()


def track_frame_aliases(insn, stack_registers, aliases):
    """Update *aliases* (register -> frame offset) for *insn*.

    Only three things create one: ``lea rD, [SP+k]``, ``add xD, SP, #k`` and
    copying a register that already holds one.  Anything else written to a
    register destroys whatever it held.
    """
    destination = insn.getRegister(0)
    if destination is None:
        return
    name = base_register_name(destination)
    mnemonic = str(insn.getMnemonicString()).lower()

    if mnemonic == "lea":
        for index in range(1, insn.getNumOperands()):
            offset = frame_offset(insn, index, stack_registers, aliases)
            if offset is not None:
                aliases[name] = offset
                return
    elif mnemonic == "add" and insn.getNumOperands() == 3:
        base = insn.getRegister(1)
        scalar = insn.getScalar(2)
        if base is not None and scalar is not None:
            base_name = base_register_name(base)
            value = int(scalar.getUnsignedValue())
            if base_name in stack_registers:
                aliases[name] = value
                return
            if base_name in aliases:
                aliases[name] = aliases[base_name] + value
                return
    elif mnemonic == "mov" and insn.getNumOperands() == 2:
        source = insn.getRegister(1)
        if source is not None:
            source_name = base_register_name(source)
            if source_name in aliases:
                aliases[name] = aliases[source_name]
                return

    aliases.pop(name, None)


def memory_operands(insn):
    """Indices of *insn*'s operands that address memory.

    A bare register operand that Ghidra happens to type as an address -- the
    destination of ``LEA`` does exactly that -- is not one of them.
    """
    from ghidra.program.model.lang import OperandType, Register

    indices = []
    for index in range(insn.getNumOperands()):
        optype = insn.getOperandType(index)
        dynamic = OperandType.isDynamic(optype)
        if not (dynamic or OperandType.isAddress(optype)):
            continue
        if not dynamic:
            objects = list(insn.getOpObjects(index))
            if (len(objects) == 1
                    and isinstance(objects[0], Register)):
                continue
        indices.append(index)
    return indices
