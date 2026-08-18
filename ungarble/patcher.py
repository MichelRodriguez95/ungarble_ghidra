"""Write a functional, string-deobfuscated copy of the binary.

Turns recovered strings into a *runnable* executable rather than just
annotations in the Ghidra database.

garble's obfuscation sequence is always larger than the string it produces (a
`mov r64, imm64` costs 10 bytes per 8 characters), so the whole sequence can be
overwritten *in place* with a small stub that leaves the plaintext inline and
points the `slicebytetostring` arguments at it:

    (amd64)                      (arm64)
    xor eax, eax                 mov  x0, #0
    lea rbx, [rip+disp]          adr  x1, <data>
    mov ecx, <length>            mov  w2, #length
    jmp over                     b    over
    <plaintext bytes>            <plaintext bytes>
  over:                        over:
    nop ... nop                  nop ... nop     ; pad to the original call

The patch is **byte-for-byte the same size and stays in place**. Go's `pclntab`
maps program counters to runtime metadata (GC, stack unwinding, panics); moving
or resizing code invalidates it and the binary crashes at runtime. Same-size
in-place patching keeps it valid.

Correctness guards, all of which *skip and report* rather than mis-patch:
  * a location is skipped if anything *references an address strictly inside*
    the sequence -- overwriting it would corrupt a jump/data target;
  * the region is skipped if it has side effects the stub does not reproduce
    (see :meth:`Patcher.side_effect_reason`) -- the stub rebuilds exactly one
    thing, the ``(pointer, length)`` pair, and drops everything else the code
    it replaces was doing;
  * every stub is *re-emulated on the patched bytes* before the file is written,
    confirming the plaintext is actually reached (verified=True/False).

Supported for patching: amd64 (`x86` 64-bit) and arm64 (`AARCH64`). Both use
Go's register ABI. 32-bit x86/arm use Go's stack-based ABI0 and are reported as
unsupported for patching rather than mis-patched.
"""

from .log import log_error, log_info

_X_XOR_EAX = b"\x31\xc0"
_X_LEA_RBX = b"\x48\x8d\x1d"
_X_MOV_ECX = b"\xb9"
_X_JMP_S = b"\xeb"
_X_JMP_N = b"\xe9"
_X_NOP = b"\x90"
_X_HEADER = 2 + 7 + 5

_A_NOP = b"\x1f\x20\x03\xd5"


def _mnemonic(insn):
    return str(insn.getMnemonicString()).lower()


def _jbytes(data):
    """Python bytes -> Java byte[] (jbyte is signed, so fold 0x80..0xFF)."""
    from jpype import JArray, JByte

    return JArray(JByte)([b - 256 if b > 127 else b for b in bytearray(data)])


def _u32le(v):
    return (v & 0xFFFFFFFF).to_bytes(4, "little")


def _s8(v):
    return (v & 0xFF).to_bytes(1, "little")


_PATCH_ARCH = {
    ("x86", 8): "amd64",
    ("AARCH64", 8): "arm64",
}

_PRESERVED_REGS = {
    "amd64": frozenset(("RSP", "RBP", "R14", "R15")),
    "arm64": frozenset(("SP", "X29", "X28", "X18")),
}

_STACK_REGS = {
    "amd64": frozenset(("RSP", "ESP", "RBP", "EBP")),
    "arm64": frozenset(("SP", "WSP", "X29", "W29")),
}


def _build_amd64(region_size, data, length):
    jmp_len = 2 if len(data) <= 0x7F else 5
    fixed = _X_HEADER + jmp_len
    total = fixed + len(data)
    if total > region_size:
        return None
    disp = fixed - (2 + 7)
    stub = bytearray()
    stub += _X_XOR_EAX
    stub += _X_LEA_RBX + _u32le(disp)
    stub += _X_MOV_ECX + _u32le(length)
    if jmp_len == 2:
        stub += _X_JMP_S + _s8(len(data))
    else:
        stub += _X_JMP_N + _u32le(len(data))
    stub += data
    stub += _X_NOP * (region_size - total)
    return bytes(stub)


def _movz(rd, imm16, is64):
    """MOVZ (W|X)rd, #imm16 -- load a 16-bit immediate, zeroing the rest."""
    word = 0x52800000 | (imm16 << 5) | (rd & 0x1F)
    if is64:
        word |= 0x80000000
    return _u32le(word)


def _adr(rd, offset):
    """ADR Xrd, #offset -- PC-relative address, offset in [-1MiB, +1MiB)."""
    offset &= 0x1FFFFF
    immlo = offset & 0x3
    immhi = (offset >> 2) & 0x7FFFF
    word = 0x10000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)
    return _u32le(word)


def _b(offset_bytes):
    """B #offset -- unconditional branch, offset is a byte count (mult of 4)."""
    imm26 = (offset_bytes >> 2) & 0x3FFFFFF
    word = 0x14000000 | imm26
    return _u32le(word)


def _build_arm64(region_size, data, length):
    if length > 0xFFFF:
        return None
    header = 16
    data_pad = (-len(data)) % 4
    total = header + len(data) + data_pad
    if total > region_size or (region_size - total) % 4 != 0:
        return None
    stub = bytearray()
    stub += _movz(0, 0, True)
    stub += _adr(1, 12)
    stub += _movz(2, length, False)
    stub += _b(4 + len(data) + data_pad)
    stub += data
    stub += b"\x00" * data_pad
    stub += _A_NOP * ((region_size - total) // 4)
    return bytes(stub)


_BUILDERS = {"amd64": _build_amd64, "arm64": _build_arm64}


_X_CALL = b"\xe8"
_X_RET = b"\xc3"
_X_TRAP = b"\xcc"
_X_SUB_HEADER = 2 + 7 + 5 + 5 + 1

_A_RET = b"\xc0\x03\x5f\xd6"
_A_PUSH_LR = b"\xfe\x0f\x1f\xf8"
_A_POP_LR = b"\xfe\x07\x41\xf8"
_A_SUB_HEADER = 28


def _build_amd64_subroutine(region_size, data, length, stub_va, callee_va):
    total = _X_SUB_HEADER + len(data)
    if total > region_size or callee_va is None:
        return None
    stub = bytearray()
    stub += _X_XOR_EAX
    stub += _X_LEA_RBX + _u32le(_X_SUB_HEADER - 9)
    stub += _X_MOV_ECX + _u32le(length)
    relative = (callee_va - (stub_va + 2 + 7 + 5 + 5)) & 0xFFFFFFFF
    stub += _X_CALL + _u32le(relative)
    stub += _X_RET
    stub += data
    stub += _X_TRAP * (region_size - total)
    return bytes(stub)


def _bl(offset_bytes):
    """BL #offset -- branch with link, offset is a byte count (mult of 4)."""
    return _u32le(0x94000000 | ((offset_bytes >> 2) & 0x3FFFFFF))


def _build_arm64_subroutine(region_size, data, length, stub_va, callee_va):
    """Whole-function replacement for arm64.

    The link register has to be saved and restored around the ``bl``.  aarch64
    keeps the return address in ``x30`` rather than on the stack, so a ``bl``
    *overwrites* it -- and a stub that went straight from ``bl`` to ``ret`` would
    return to the instruction after the ``bl``, which is the ``ret`` itself: an
    infinite loop.  Found by running the patched binary; every one of those 85
    patches had passed re-emulation, because re-emulation stops at the call and
    never reaches the return.  amd64 has no equivalent problem: ``call`` pushes
    the address and ``ret`` pops it.
    """
    if length > 0xFFFF or callee_va is None:
        return None
    data_pad = (-len(data)) % 4
    total = _A_SUB_HEADER + len(data) + data_pad
    if total > region_size or (region_size - total) % 4 != 0:
        return None
    stub = bytearray()
    stub += _A_PUSH_LR
    stub += _movz(0, 0, True)
    stub += _adr(1, _A_SUB_HEADER - 8)
    stub += _movz(2, length, False)
    stub += _bl(callee_va - (stub_va + 16))
    stub += _A_POP_LR
    stub += _A_RET
    stub += data
    stub += b"\x00" * data_pad
    stub += _A_NOP * ((region_size - total) // 4)
    return bytes(stub)


_SUB_BUILDERS = {"amd64": _build_amd64_subroutine,
                 "arm64": _build_arm64_subroutine}

SUB_CALL_OFFSET = {"amd64": 2 + 7 + 5, "arm64": 16}

MAX_MORESTACK_TAIL = 32


def build_subroutine_stub(arch, region_size, plaintext, length, stub_va, callee_va):
    """Assemble a whole-function replacement, or ``None`` if it will not fit."""
    data = plaintext[:length]
    if len(data) < length:
        return None
    builder = _SUB_BUILDERS.get(arch)
    if builder is None:
        return None
    return builder(region_size, data, length, stub_va, callee_va)


def build_stub(arch, region_size, plaintext, length):
    """Assemble the replacement stub for *arch*, or ``None`` if it will not fit."""
    data = plaintext[:length]
    if len(data) < length:
        return None
    builder = _BUILDERS.get(arch)
    if builder is None:
        return None
    return builder(region_size, data, length)


class Patcher(object):
    def __init__(self, program):
        self.program = program
        self.memory = program.getMemory()
        self.processor = str(program.getLanguage().getProcessor())
        self.ptr_size = program.getDefaultPointerSize()
        self.arch = _PATCH_ARCH.get((self.processor, self.ptr_size))
        self.supported = self.arch is not None


    def file_offset(self, address):
        block = self.memory.getBlock(address)
        if block is None or not block.isInitialized():
            return None
        for info in block.getSourceInfos():
            if info.contains(address) and info.getFileBytes().isPresent():
                return int(info.getFileBytesOffset(address))
        return None

    def callsite_length(self, call_address):
        """The length operand set just before *call_address* (RCX / W2)."""
        listing = self.program.getListing()
        insn = listing.getInstructionAt(call_address)
        if insn is None:
            return None
        len_regs = ("ECX", "RCX", "CX") if self.arch == "amd64" else ("W2", "X2")
        insn = insn.getPrevious()
        for _ in range(8):
            if insn is None:
                break
            mnem = insn.getMnemonicString().lower()
            if mnem in ("mov", "movz") and insn.getNumOperands() == 2:
                reg = insn.getRegister(0)
                if reg is not None and reg.getName().upper() in len_regs:
                    scalar = insn.getScalar(1)
                    if scalar is not None:
                        return int(scalar.getUnsignedValue())
            insn = insn.getPrevious()
        return None

    def _reference_inside(self, start_address, call_address):
        """Offset of an *externally* referenced byte inside the region, or None.

        Overwriting a byte that some jump or data reference targets would
        corrupt that target.  But a garble sequence routinely spans several
        basic blocks, so it contains internal branch targets that are part of
        the very code we are replacing -- those are harmless.  Only a reference
        whose *source* lies outside ``[start, call)`` is dangerous, because that
        code will still jump/read into bytes we changed.  A reference to *start*
        itself is fine: the stub begins there and flows into the call.
        """
        ref_mgr = self.program.getReferenceManager()
        start_off = int(start_address.getOffset())
        call_off = int(call_address.getOffset())
        addr = start_address.next()
        while addr is not None and addr.compareTo(call_address) < 0:
            refs = ref_mgr.getReferencesTo(addr)
            while refs.hasNext():
                src = int(refs.next().getFromAddress().getOffset())
                if src < start_off or src >= call_off:
                    return int(addr.getOffset())
            addr = addr.next()
        return None


    @staticmethod
    def _base_register_name(register):
        """Widest register containing *register* (``EBP`` -> ``RBP``), uppercased."""
        try:
            base = register.getBaseRegister()
            if base is not None:
                register = base
        except Exception:
            pass
        return str(register.getName()).upper()

    def _written_registers(self, insn):
        from ghidra.program.model.lang import Register

        names = set()
        for obj in insn.getResultObjects():
            if isinstance(obj, Register):
                names.add(self._base_register_name(obj))
        return names

    def _offstack_store(self, insn, aliases):
        """True when *insn* writes memory through anything but SP/FP.

        A store to a global, or through a pointer we cannot tie to the current
        frame, outlives that frame -- so dropping it changes what the program
        does even though every register looks fine at the callsite.

        Two things make this fiddlier than it sounds, both learned from real
        garble output:

        * ``LEA`` writes a *register*, but Ghidra types its destination operand
          as an address with a WRITE ref type, so a naive read of the operand
          model counts ``lea rbx, [rsp+0x3a]`` as a memory store.
        * garble's decode loop indexes its stack buffer, e.g.
          ``mov byte ptr [RSP + RDI*0x1 + 0x3a], DL``.  The operand carries two
          registers -- ``RSP`` the base and ``RDI`` the index -- and only the
          base says which region is written.  Requiring *every* register to be
          a stack register rejected the entire sequence.

        Ghidra returns the operand objects in addressing order, so the first
        register is the base.
        """
        if _mnemonic(insn) == "lea":
            return False

        from .insn import frame_offset, memory_operands, writes_memory

        if not writes_memory(insn):
            return False

        stack_regs = _STACK_REGS.get(self.arch, frozenset())
        for i in memory_operands(insn):
            if frame_offset(insn, i, stack_regs, aliases) is None:
                return True
        return False


    def side_effect_reason(self, start_address, call_address):
        """Why replacing ``[start, call)`` with the stub could break the function.

        The stub reproduces exactly *one* effect of the code it overwrites: the
        ``(pointer, length)`` pair handed to slicebytetostring.  Everything else
        that code was doing is dropped, so re-emulating the stub and finding the
        right string proves the stub encodes correctly -- it does **not** prove
        the region was safe to delete.  This checks that separately.

        Three things are cheap to detect and are the realistic ways an in-place
        patch corrupts a Go function:

        * a write to a register the ABI preserves across a call.  Scratch
          registers need no check -- the call the region ends in could clobber
          them anyway -- which is what keeps this from rejecting everything.
        * a call inside the region: the stub NOPs it out along with whatever it
          did.
        * a store through anything other than SP/FP (or a register holding
          ``SP+k``), i.e. to memory that outlives the frame.
        * a ``ret`` inside the region.  The callsite-anchored finder
          walks straight past control flow to find where a buffer is built, which
          is right for *emulation* -- the emulator follows the real path -- but it
          means the address range can enclose code the sequence merely sits
          around.  arm64 garble does this routinely: its decode loop is laid out
          after an unrelated ``ret``.  Overwriting that range would delete the
          ``ret``.

        Also rejects a region that is not wholly disassembled, since undefined
        bytes in the middle are something the stub would silently destroy.

        **Not covered:** a store to a stack slot *outside* the decoded buffer
        that code after the call reads back.  Proving that absent needs
        stack-slot liveness; such a region passes this check.

        Returns a reason string, or ``None`` when nothing suspicious was found.
        """
        from .insn import track_frame_aliases

        preserved = _PRESERVED_REGS.get(self.arch, frozenset())
        stack_regs = _STACK_REGS.get(self.arch, frozenset())
        aliases = {}
        listing = self.program.getListing()
        expected = start_address
        insn = listing.getInstructionAt(start_address)
        if insn is None:
            return "0x%x is not the start of an instruction" % int(
                start_address.getOffset())

        while insn is not None and insn.getAddress().compareTo(call_address) < 0:
            address = insn.getAddress()
            if address.compareTo(expected) != 0:
                return ("undefined bytes at 0x%x inside the region"
                        % int(expected.getOffset()))
            try:
                flow = insn.getFlowType()
                if flow.isCall():
                    return ("0x%x calls out of the region (the stub would drop "
                            "the call)" % int(address.getOffset()))
                if flow.isTerminal():
                    return ("0x%x returns from the function inside the region; "
                           "the region encloses unrelated code"
                            % int(address.getOffset()))
                clobbered = self._written_registers(insn) & preserved
                if clobbered:
                    return ("0x%x writes %s, which must survive the call"
                            % (int(address.getOffset()), ", ".join(sorted(clobbered))))
                track_frame_aliases(insn, stack_regs, aliases)
                if self._offstack_store(insn, aliases):
                    return ("0x%x stores through a pointer that cannot be tied "
                            "to this frame" % int(address.getOffset()))
                expected = address.add(insn.getLength())
            except Exception as exc:
                log_error("side-effect check failed at 0x%x: %s"
                          % (int(address.getOffset()), exc))
                return ("could not analyse 0x%x (%s)"
                        % (int(address.getOffset()), exc))
            insn = insn.getNext()

        return None


    def plan_patch(self, start_address, call_address, plaintext_bytes,
                   strict=True):
        info = {
            "start": int(start_address.getOffset()),
            "call": int(call_address.getOffset()),
            "patch": None,
            "reason": None,
        }
        if not self.supported:
            info["reason"] = "unsupported architecture %s/%d-bit" % (
                self.processor, self.ptr_size * 8)
            return info

        subroutine = self._subroutine_region(start_address, call_address)
        info["subroutine"] = subroutine is not None

        if subroutine is not None:
            end_address, callee = subroutine
            region_size = int(end_address.getOffset()) - int(start_address.getOffset())
        else:
            end_address, callee = call_address, None
            region_size = (int(call_address.getOffset())
                           - int(start_address.getOffset()))
            if region_size <= _X_HEADER + 2:
                info["reason"] = "region too small (%d bytes)" % region_size
                return info

        inner = self._reference_inside(start_address, end_address)
        if inner is not None:
            info["reason"] = "0x%x is referenced from elsewhere (jump/data target)" % inner
            return info

        if strict and subroutine is None:
            side_effect = self.side_effect_reason(start_address, call_address)
            if side_effect is not None:
                info["reason"] = side_effect
                return info

        length = self.callsite_length(call_address)
        if length is None and subroutine is not None:
            length = len(plaintext_bytes)
        if length is None:
            info["reason"] = "could not read callsite length"
            return info
        if length <= 0:
            info["reason"] = "callsite length is zero"
            return info
        info["length"] = length

        file_off = self.file_offset(start_address)
        if file_off is None:
            info["reason"] = "start address is not file-backed"
            return info

        if subroutine is not None:
            stub = build_subroutine_stub(
                self.arch, region_size, plaintext_bytes, length,
                int(start_address.getOffset()), int(callee.getOffset()))
        else:
            stub = build_stub(self.arch, region_size, plaintext_bytes, length)
        if stub is None:
            info["reason"] = (
                "plaintext (%d) does not fit the %d-byte %s"
                % (length, region_size,
                   "function" if subroutine is not None else "region")
            )
            return info

        info["patch"] = {"offset": file_off, "bytes": stub}
        info["stub"] = stub
        info["string"] = plaintext_bytes[:length].decode("ascii", "replace")
        if subroutine is not None:
            info["verify_stop"] = int(start_address.getOffset()) + SUB_CALL_OFFSET[
                self.arch]
        else:
            info["verify_stop"] = int(call_address.getOffset())
        return info

    def _subroutine_region(self, start_address, call_address):
        """``(end_exclusive, callee)`` when this location is a whole decoder.

        True when *start* is the entry point of the function containing the call,
        which is what the finder produces for the split and seed families.  *end*
        is just past the ``ret`` that follows the call, so the replacement covers
        the prologue *and* the epilogue and the frame stays balanced.  Anything
        the compiler parked after that ``ret`` -- the ``morestack`` tail -- is
        left alone; nothing reaches it once the stack check is gone.
        """
        if self.arch != "amd64":
            return None
        function = self.program.getFunctionManager().getFunctionContaining(call_address)
        if function is None or not function.getEntryPoint().equals(start_address):
            return None
        listing = self.program.getListing()
        call_insn = listing.getInstructionAt(call_address)
        if call_insn is None:
            return None
        flows = call_insn.getFlows()
        callee = flows[0] if flows else None
        if callee is None:
            return None
        insn = call_insn
        for _ in range(12):
            insn = insn.getNext()
            if insn is None:
                return None
            if not insn.getFlowType().isTerminal():
                continue
            end = insn.getAddress().add(insn.getLength())
            body_end = function.getBody().getMaxAddress()
            if body_end is None:
                return None
            trailing = int(body_end.getOffset()) - int(end.getOffset()) + 1
            if trailing > MAX_MORESTACK_TAIL:
                return None
            return end, callee
        return None


    def verify_patch(self, start_address, call_address, stub, expected_bytes,
                     engine, verify_stop=None):
        """Re-emulate the patched bytes and confirm the plaintext is reached.

        The stub is laid into the emulator's own memory (never the program
        database -- Ghidra forbids overwriting defined instructions), executed
        from *start* to the *call*, and the argument the program would hand to
        slicebytetostring is read back and compared with *expected_bytes*.

        This proves the *stub* is encoded correctly.  It says nothing about
        whether the region was safe to overwrite -- that is
        :meth:`side_effect_reason`'s job.
        """
        backend = getattr(engine, "_pcode_backend", None)
        if callable(backend):
            backend = backend()
        else:
            from .backends.pcode_backend import PcodeEmulationBackend

            backend = PcodeEmulationBackend(self.program)
        stop = (int(call_address.getOffset()) if verify_stop is None
                else int(verify_stop))
        got = backend.run_bytes_with_overlay(
            int(start_address.getOffset()),
            stop,
            int(start_address.getOffset()),
            stub,
        )
        return bool(got) and bytes(got) == bytes(expected_bytes)


def apply_patches(original_data, patches):
    """Apply every patch that fits and does not overlap an earlier one.

    Returns ``(image, rejected)`` where *rejected* is a list of
    ``(index, reason)`` into *patches*.

    Both conditions used to raise, which threw away a whole run's work over a
    single bad entry -- and a duplicate is ordinary input, not a bug: two
    callsites can resolve to the same obfuscation start, so the same region gets
    planned twice.  Rejecting just that patch lets the caller report it beside
    every other skip.

    Earlier patches win, so the result does not depend on how a later duplicate
    was encoded.
    """
    image = bytearray(original_data)
    claimed = []
    rejected = []
    for index, patch in enumerate(patches):
        offset = patch["offset"]
        blob = patch["bytes"]
        end = offset + len(blob)
        if offset < 0 or end > len(image):
            rejected.append((index, "patch at 0x%x runs past end of file" % offset))
            continue
        clash = next(
            ((c_start, c_end) for c_start, c_end in claimed
             if offset < c_end and c_start < end),
            None,
        )
        if clash is not None:
            rejected.append((
                index,
                "patch at 0x%x overlaps an earlier patch at 0x%x" % (offset, clash[0]),
            ))
            continue
        image[offset:end] = blob
        claimed.append((offset, end))
    return bytes(image), rejected


def write_patched_binary(program, original_data, results, engine, out_path,
                         on_progress=None, verify=True, strict=True,
                         require_constant=True):
    """Emulate every target, patch the file in place and write it out.

    *results* is a list of ``(start_address, call_address)`` pairs.  Returns a
    summary with per-location outcomes (patched / skipped, and each patch's
    ``verified`` flag).

    *strict* applies :meth:`Patcher.side_effect_reason`, which skips regions
    whose other effects the stub does not reproduce.  It is on by default
    because a region that fails it can corrupt the function while still passing
    re-emulation; turn it off only to compare yield.

    *require_constant* only patches strings that emulate identically from two
    different machine states, so a legitimate ``string(byteSlice)`` conversion of
    runtime data is never frozen into the binary.  Leave it on: with the
    callsite-anchored finder, some detected locations are ordinary conversions
    rather than garble literals, and nothing else distinguishes them.
    """
    patcher = Patcher(program)
    if not patcher.supported:
        raise RuntimeError(
            "In-place patching supports amd64 and arm64 only; this program is "
            "%s/%d-bit" % (patcher.processor, patcher.ptr_size * 8)
        )

    planned, skipped = [], []
    total = len(results)
    for index, (start, call) in enumerate(results):
        if on_progress is not None:
            on_progress(index, total)
        raw = engine.run_bytes(int(start.getOffset()), int(call.getOffset()),
                               require_constant=require_constant)
        if not raw:
            skipped.append({
                "start": int(start.getOffset()),
                "reason": ("emulation produced nothing, or the string was not "
                           "constant across machine states"
                           if require_constant else "emulation produced nothing"),
            })
            continue
        info = patcher.plan_patch(start, call, raw, strict=strict)
        if info["patch"] is None:
            skipped.append({"start": info["start"], "reason": info["reason"]})
            log_info("skip 0x%x: %s" % (info["start"], info["reason"]))
            continue
        info["verified"] = (
            patcher.verify_patch(start, call, info["stub"], raw[:info["length"]],
                                 engine, verify_stop=info.get("verify_stop"))
            if verify else None
        )
        if verify and not info["verified"]:
            skipped.append({"start": info["start"],
                            "reason": "patch failed verification (emulated result mismatch)"})
            log_info("skip 0x%x: failed verification" % info["start"])
            continue
        planned.append(info)

    image, rejected = apply_patches(
        original_data, [info["patch"] for info in planned]
    )
    rejections = dict(rejected)
    kept = []
    for index, info in enumerate(planned):
        reason = rejections.get(index)
        if reason is None:
            kept.append(info)
            continue
        skipped.append({"start": info["start"], "reason": reason})
        log_info("skip 0x%x: %s" % (info["start"], reason))
    planned = kept

    with open(out_path, "wb") as handle:
        handle.write(image)
    try:
        import os

        os.chmod(out_path, 0o755)
    except Exception:
        pass

    log_info("wrote %s: %d patched, %d skipped" % (out_path, len(planned), len(skipped)))
    if on_progress is not None:
        on_progress(total, total)
    return {
        "output": out_path,
        "patched": [
            {"start": info["start"], "call": info["call"],
             "string": info["string"], "verified": info.get("verified")}
            for info in planned
        ],
        "skipped": skipped,
    }
