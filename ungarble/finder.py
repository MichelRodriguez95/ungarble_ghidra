"""Locate garble string-obfuscation sequences in a Ghidra program.

This is the port of ``FindLocations`` from the Binary Ninja plugin.

The original matched on Binary Ninja's *disassembly text tokens*, e.g.
``len(instr[0]) == 5`` for ``mov ecx, 0x2e`` or ``len(instr[0]) == 12`` for
``mov qword [rsp+0x88], rbp``.  Those counts are an artifact of Binary Ninja's
tokeniser and have no meaning in Ghidra, so every predicate below is expressed
against Ghidra's structured operand model instead (``getOperandType`` /
``getOpObjects`` / ``getScalar``).  The *semantics* being matched are identical:

    len(tokens) == 5   ->  ``MOV reg, imm``          (_is_reg_imm_mov)
    len(tokens) == 12  ->  ``MOV [mem], reg``        (_is_mem_store_mov)
    'lea', 5 tokens    ->  ``LEA reg, [mem]``        (_is_lea_mem)
    token[4].value     ->  the immediate             (_imm)
    match_param_type   ->  any operand scalar > 0xFFFF (_has_big_scalar)
"""

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.lang import OperandType, Register
from ghidra.program.model.scalar import Scalar
from ghidra.util.task import TaskMonitor

from .insn import (base_register_name, frame_offset, memory_operands,
                   track_frame_aliases, writes_memory)
from .log import log_error, log_info

IMM_THRESHOLD = 0xFFFF

MAX_BB_DEPTH = 6

MAX_PREV_DEPTH = 4

MAX_ANCHOR_BACK = 400
MAX_ANCHOR_GAP = 48

_CALLSITE_ABI = {
    ("x86", 8): {
        "pointer": frozenset(("RBX",)),
        "length": frozenset(("ECX", "RCX", "CX")),
        "stack": frozenset(("RSP", "ESP", "RBP", "EBP")),
    },
    ("AARCH64", 8): {
        "pointer": frozenset(("X1", "W1")),
        "length": frozenset(("W2", "X2")),
        "stack": frozenset(("SP", "WSP", "X29", "W29")),
    },
}

_SLICEBYTETOSTRING_NAMES = ("runtime.slicebytetostring",)

MAX_DECODER_BODY = 16 * 1024

STACK_FAMILY = "stack"
SPLIT_FAMILY = "split"
SEED_FAMILY = "seed"


def _mnem(insn):
    return insn.getMnemonicString().lower()


def _imm(insn, index):
    """Unsigned immediate of operand *index*, or ``None``."""
    scalar = insn.getScalar(index)
    if scalar is None:
        return None
    return int(scalar.getUnsignedValue())


def _has_big_scalar(insn):
    """Port of ``match_param_type``: any operand carrying a scalar > 0xFFFF.

    Binary Ninja walked the nested token lists looking for ``token.value >
    0xFFFF``; Ghidra hands us the operand objects directly.
    """
    for i in range(insn.getNumOperands()):
        for obj in insn.getOpObjects(i):
            if isinstance(obj, Scalar) and int(obj.getUnsignedValue()) > IMM_THRESHOLD:
                return True
    return False


def _is_reg_imm_mov(insn):
    """``MOV reg, imm`` -- the 5-token form in the original plugin."""
    if _mnem(insn) != "mov" or insn.getNumOperands() != 2:
        return False
    dst, src = insn.getOperandType(0), insn.getOperandType(1)
    if not OperandType.isRegister(dst) or OperandType.isDynamic(dst):
        return False
    if OperandType.isDynamic(src) or OperandType.isRegister(src):
        return False
    return OperandType.isScalar(src) and insn.getScalar(1) is not None


def _is_mem_store_mov(insn):
    """``MOV [mem], src`` -- the 12-token form in the original plugin."""
    if _mnem(insn) != "mov" or insn.getNumOperands() != 2:
        return False
    dst = insn.getOperandType(0)
    return OperandType.isDynamic(dst) or (
        OperandType.isAddress(dst) and not OperandType.isRegister(dst)
    )


def _is_lea_mem(insn):
    """``LEA reg, [mem]`` -- pointer to the decoded buffer on the stack."""
    if _mnem(insn) != "lea" or insn.getNumOperands() != 2:
        return False
    dst, src = insn.getOperandType(0), insn.getOperandType(1)
    if not OperandType.isRegister(dst) or OperandType.isDynamic(dst):
        return False
    return OperandType.isDynamic(src) or OperandType.isAddress(src)


class UngarbleFinder(object):
    """Finds ``(start, end)`` address pairs bounding obfuscation sequences.

    *end* is always the address of the ``call slicebytetostring`` that consumes
    the decoded buffer; *start* is where the sequence begins building the blob.
    """

    def __init__(self, program, monitor=None):
        self.program = program
        self.monitor = monitor if monitor is not None else TaskMonitor.DUMMY
        self.listing = program.getListing()
        self.block_model = BasicBlockModel(program)
        self.cancelled = False
        self.callsite_abi = _CALLSITE_ABI.get(
            (str(program.getLanguage().getProcessor()),
             program.getDefaultPointerSize())
        )


    def _is_cancelled(self):
        """Honour both the local flag and Ghidra's monitor."""
        if self.cancelled:
            return True
        try:
            if self.monitor.isCancelled():
                self.cancelled = True
                return True
        except Exception:
            pass
        return False

    def _instructions(self, block):
        """All instructions in a CodeBlock, in address order."""
        out = []
        it = self.listing.getInstructions(block, True)
        while it.hasNext():
            out.append(it.next())
        return out

    @staticmethod
    def _block_key(block):
        return int(block.getFirstStartAddress().getOffset())

    @staticmethod
    def _call_target(insn):
        """Address a call instruction transfers to, or ``None``."""
        flows = insn.getFlows()
        if flows is not None and len(flows) > 0:
            return flows[0]
        return None

    def _blocks_of_function(self, func):
        return self.block_model.getCodeBlocksContaining(func.getBody(), self.monitor)

    def _block_at(self, address):
        blocks = self.block_model.getCodeBlocksContaining(address, self.monitor)
        if blocks is None or len(blocks) == 0:
            return None
        return blocks[0]


    def _check_slicebytetostr_strict(self, instrs, i):
        """Strict callsite shape, port of ``check_slicebytetostr_strict``.

            xor  eax, eax
            lea  rbx, [rsp+0x6d]
            mov  ecx, 0x2e          ; length, always small
            call slicebytetostring

        The second variant in the original allowed one filler instruction (a
        ``nop``) between the ``mov`` and the ``call``.
        """
        for gap in (1, 2):
            j = i - gap
            if j - 2 < 0:
                continue
            mov_insn, lea_insn, xor_insn = instrs[j], instrs[j - 1], instrs[j - 2]
            if not _is_reg_imm_mov(mov_insn):
                continue
            length = _imm(mov_insn, 1)
            if length is None or length >= IMM_THRESHOLD:
                continue
            if _is_lea_mem(lea_insn) and _mnem(xor_insn) == "xor":
                return True
        return False

    def _check_bb_slicebytetostr(self, block, depth=0, visited=None):
        """Port of ``check_bb_slicebytetostr``.

        Linear scanning found calls further down the function, so the original
        walks basic-block edges instead.  A ``visited`` set is added here that
        the Binary Ninja version lacked -- Go functions are loop-heavy and the
        unguarded recursion could otherwise spin.
        """
        if visited is None:
            visited = set()
        if depth >= MAX_BB_DEPTH:
            return None
        key = self._block_key(block)
        if key in visited:
            return None
        visited.add(key)

        instrs = self._instructions(block)
        for i, insn in enumerate(instrs):
            if _mnem(insn) != "call":
                continue
            if self._check_slicebytetostr_strict(instrs, i):
                target = self._call_target(insn)
                if target is not None:
                    log_info(
                        "slicebytetostring candidate at 0x%x (callsite 0x%x, block 0x%x)"
                        % (target.getOffset(), insn.getAddress().getOffset(), key)
                    )
                    return target

        dests = block.getDestinations(self.monitor)
        while dests.hasNext():
            if self._is_cancelled():
                return None
            result = self._check_bb_slicebytetostr(
                dests.next().getDestinationBlock(), depth + 1, visited
            )
            if result is not None:
                return result
        return None

    def _find_slicebytetostr_in_function(self, func):
        """Port of ``match_disas_adv_seq_bb``.

            mov rdx, 0x7774231724166841   ; big immediate
            mov qword [rsp+0x88], rbp     ; store to stack
            mov <reg>, <imm>              ; next chunk

        Deliberately simple -- as the original notes, Go functions frequently
        fail to lift cleanly, so this stays at the disassembly level.
        """
        blocks = self._blocks_of_function(func)
        while blocks.hasNext():
            if self._is_cancelled():
                return None
            block = blocks.next()
            instrs = self._instructions(block)
            for i, insn in enumerate(instrs):
                if i + 2 >= len(instrs):
                    break
                if not _is_reg_imm_mov(insn):
                    continue
                value = _imm(insn, 1)
                if value is None or value <= IMM_THRESHOLD:
                    continue
                if not _is_mem_store_mov(instrs[i + 1]):
                    continue
                if not _is_reg_imm_mov(instrs[i + 2]):
                    continue
                if i > 0 and _mnem(instrs[i - 1]) == "mov":
                    continue
                target = self._check_bb_slicebytetostr(block, 0)
                if target is not None:
                    return target
        return None

    def _slicebytetostring_from_pclntab(self):
        """``runtime.slicebytetostring``'s address straight from the pclntab.

        The heuristic below matches x86 instruction shapes, which AArch64 simply
        does not have (no ``lea``, no ``xor``, no ``mov`` to memory), so on arm64
        it can never succeed.  The pclntab is ground truth, survives garble, and
        the plugin already parses it for name recovery -- so ask it first.

        Also worth it on amd64: it replaces a guess with a fact.
        """
        try:
            from . import gopclntab

            names = gopclntab.parse(self.program)
        except Exception as exc:
            log_info("pclntab lookup unavailable: %s" % exc)
            return None
        if not names:
            return None
        space = self.program.getAddressFactory().getDefaultAddressSpace()
        for offset, name in names.items():
            if name in _SLICEBYTETOSTRING_NAMES:
                address = space.getAddress(int(offset))
                callers = len(self._call_sites(address))
                if callers == 0:
                    log_info("pclntab named slicebytetostring at 0x%x but nothing "
                             "calls it; ignoring" % int(offset))
                    return None
                log_info("slicebytetostring from pclntab: 0x%x (%d callsites)"
                         % (int(offset), callers))
                return address
        return None

    def find_slicebytetostring(self):
        """Locate slicebytetostring: pclntab first, then the x86 heuristic."""
        address = self._slicebytetostring_from_pclntab()
        if address is not None:
            return address
        log_info("pclntab did not name slicebytetostring; falling back to the "
                 "instruction heuristic")
        return self._find_slicebytetostring_heuristic()

    def _find_slicebytetostring_heuristic(self):
        """Scan functions until the heuristic identifies slicebytetostring."""
        functions = self.listing.getFunctions(True)
        while functions.hasNext():
            if self._is_cancelled():
                return None
            func = functions.next()
            try:
                result = self._find_slicebytetostr_in_function(func)
            except Exception as exc:
                log_error("error scanning %s: %s" % (func.getName(), exc))
                continue
            if result is not None:
                return result
        return None


    def _match_obf_start_in_block(self, block):
        """Port of ``match_disas_bb_simple``.

        First ``mov`` carrying a large scalar whose predecessor is *not* a
        ``mov`` (i.e. the head of the run) and which has another large-scalar
        instruction two slots later.
        """
        instrs = self._instructions(block)
        count = len(instrs)
        for i, insn in enumerate(instrs):
            if i >= count - 2:
                break
            try:
                if _mnem(insn) != "mov":
                    continue
                if not _has_big_scalar(insn):
                    continue
                if not _has_big_scalar(instrs[i + 2]):
                    continue
                if i > 0 and _mnem(instrs[i - 1]) == "mov":
                    continue
                return insn.getAddress()
            except Exception:
                continue
        return None

    def _collect_obf_starts(self, block):
        """Port of ``get_obf_start`` -- walk predecessors collecting starts."""
        found = []
        visited = set()

        def recurse(current, depth):
            depth += 1
            if depth == MAX_PREV_DEPTH:
                return
            key = self._block_key(current)
            if key in visited:
                return
            visited.add(key)
            address = self._match_obf_start_in_block(current)
            if address is not None:
                found.append(address)
            sources = current.getSources(self.monitor)
            while sources.hasNext():
                if self._is_cancelled():
                    return
                recurse(sources.next().getSourceBlock(), depth)

        recurse(block, 0)
        return found


    def _stack_displacement(self, insn, index, abi):
        """Displacement of operand *index* when it addresses the frame directly.

        No alias resolution: this is only used to read the buffer pointer out of
        ``lea rbx, [rsp+X]``, where a direct ``SP`` base is exactly the shape
        being matched.
        """
        return frame_offset(insn, index, abi["stack"], {})

    def _pointer_setup(self, insn, abi):
        """Buffer displacement if *insn* puts ``SP+disp`` in the pointer register.

        amd64: ``LEA RBX, [RSP + disp]``.  arm64: ``ADD X1, SP, #disp``.
        """
        destination = insn.getRegister(0)
        if destination is None:
            return None
        if str(destination.getName()).upper() not in abi["pointer"]:
            return None
        mnemonic = _mnem(insn)
        if mnemonic == "lea":
            for index in range(1, insn.getNumOperands()):
                displacement = self._stack_displacement(insn, index, abi)
                if displacement is not None:
                    return displacement
            return None
        if mnemonic == "add" and insn.getNumOperands() == 3:
            base = insn.getRegister(1)
            scalar = insn.getScalar(2)
            if (base is not None and scalar is not None
                    and str(base.getName()).upper() in abi["stack"]):
                return int(scalar.getUnsignedValue())
        return None

    def _length_setup(self, insn, abi):
        """Length if *insn* loads an immediate into the length register."""
        if _mnem(insn) not in ("mov", "movz", "movk", "orr"):
            return None
        destination = insn.getRegister(0)
        if destination is None:
            return None
        if str(destination.getName()).upper() not in abi["length"]:
            return None
        for index in range(1, insn.getNumOperands()):
            scalar = insn.getScalar(index)
            if scalar is not None:
                value = int(scalar.getUnsignedValue())
                if 0 < value < IMM_THRESHOLD:
                    return value
        return None

    def _buffer_at_callsite(self, call_insn, abi):
        """``(displacement, length)`` the callsite hands over, or ``None``.

        Both have to come from the few instructions right before the call; a
        pointer computed some other way (``add x1, x5, x7``) is not a shape this
        understands and the callsite is left alone.
        """
        displacement = length = None
        insn = call_insn.getPrevious()
        for _ in range(10):
            if insn is None:
                break
            if displacement is None:
                displacement = self._pointer_setup(insn, abi)
            if length is None:
                length = self._length_setup(insn, abi)
            if displacement is not None and length is not None:
                return displacement, length
            if insn.getFlowType().isCall():
                break
            insn = insn.getPrevious()
        return None


    def _register_source(self, insn, abi):
        """How *insn* produced its destination register: the kind, or ``None``.

        ``"stack"`` for ``lea reg,[sp+X]`` / ``add reg,sp,#X``, ``"register"``
        for a register-to-register move, ``"memory"`` for a load, ``"immediate"``
        for a constant.
        """
        if insn.getRegister(0) is None:
            return None
        mnemonic = _mnem(insn)
        if self._pointer_setup(insn, abi) is not None:
            return "stack"
        if mnemonic not in ("mov", "movz", "ldr", "ldur", "orr", "lea"):
            return None
        for index in range(1, insn.getNumOperands()):
            optype = insn.getOperandType(index)
            if OperandType.isDynamic(optype):
                return "memory"
            if OperandType.isRegister(optype):
                return "register"
            if OperandType.isScalar(optype):
                return "immediate"
        return None

    def _callsite_family(self, call_insn, abi):
        """Which garble literal obfuscator this callsite belongs to, or ``None``.

        Decided by where the *pointer* register's value came from, since that is
        what actually distinguishes the three: the stack family computes it from
        the stack pointer, the other two copy or load it.
        """
        pointer_kind = None
        insn = call_insn.getPrevious()
        for _ in range(8):
            if insn is None or insn.getFlowType().isCall():
                break
            destination = insn.getRegister(0)
            if destination is not None and pointer_kind is None:
                if base_register_name(destination) in abi["pointer"]:
                    pointer_kind = self._register_source(insn, abi)
            insn = insn.getPrevious()

        if pointer_kind == "stack":
            return STACK_FAMILY
        if pointer_kind == "register":
            return SPLIT_FAMILY
        if pointer_kind == "memory":
            return SEED_FAMILY
        return None

    def _subroutine_start(self, call_address):
        """Entry of the decoder subroutine feeding *call_address*, or ``None``.

        The split and seed decoders build their blob in their own frame and on
        the heap, so there is no region in a caller to carve out -- the function
        *is* the sequence.  Emulating it from its entry runs the Go stack-growth
        check first, which is harmless: with the goroutine register pointing at
        the emulated stack the check simply falls through.
        """
        function = self.program.getFunctionManager().getFunctionContaining(call_address)
        if function is None:
            return None
        if int(function.getBody().getNumAddresses()) > MAX_DECODER_BODY:
            return None
        entry = function.getEntryPoint()
        if entry.compareTo(call_address) >= 0:
            return None
        return entry

    def _frame_offset(self, insn, index, abi, aliases):
        """Frame offset of a memory operand -- see :func:`ungarble.insn.frame_offset`."""
        return frame_offset(insn, index, abi["stack"], aliases)

    def _track_frame_aliases(self, insn, abi, aliases):
        """See :func:`ungarble.insn.track_frame_aliases`."""
        track_frame_aliases(insn, abi["stack"], aliases)

    def _writes_into_buffer(self, insn, low, high, abi, aliases):
        """Whether *insn* stores into frame range ``[low, high)``.

        Store detection goes through the p-code, not the operand ref types:
        AArch64 reports a store's memory operand as ``DATA``, so a ref-type check
        finds no arm64 stores at all.  See :mod:`ungarble.insn`.
        """
        if _mnem(insn) == "lea":
            return False
        if not writes_memory(insn):
            return False
        for index in memory_operands(insn):
            offset = self._frame_offset(insn, index, abi, aliases)
            if offset is not None and low <= offset < high:
                return True
        return False

    def _anchor_window(self, call_insn):
        """Instructions leading to the call, in address order.

        Deliberately walks *linear* predecessors and ignores control flow --
        no following jumps, no stopping at a ``ret``.  That looks wrong and is
        not: the question being asked is "which instructions store into this one
        frame slot", and a garble sequence's blob-building block is laid out at a
        lower address than its decode loop on both architectures, sometimes with
        an unrelated ``ret`` in between (arm64 does this routinely).  Walking
        straight through finds it; honouring control flow does not.

        Measured: an earlier version that stopped at terminators and followed
        basic-block predecessors instead recovered 54 locations on amd64 where
        this recovers 123.

        The walk stops at a call -- the far side of one belongs to other code --
        and :meth:`_earliest_buffer_write` bounds it further with a gap limit, so
        the region cannot run away.
        """
        window = []
        insn = call_insn.getPrevious()
        for _ in range(MAX_ANCHOR_BACK):
            if insn is None or insn.getFlowType().isCall():
                break
            window.insert(0, insn)
            insn = insn.getPrevious()
        return window

    def _extend_to_feeders(self, address, limit=4):
        """Pull *address* back over the instructions that feed it.

        The earliest buffer write is ``mov [rsp+X], rdx``; the immediate it
        stores was loaded by the ``mov rdx, imm64`` just before it, and starting
        the region at the store would leave that dangling.  Walks back while each
        previous instruction writes a register this one reads.
        """
        insn = self.listing.getInstructionAt(address)
        if insn is None:
            return address
        for _ in range(limit):
            previous = insn.getPrevious()
            if previous is None or previous.getFlowType().isCall():
                break
            written = {base_register_name(o) for o in previous.getResultObjects()
                       if isinstance(o, Register)}
            read = {base_register_name(o) for o in insn.getInputObjects()
                    if isinstance(o, Register)}
            if not (written & read):
                break
            insn = previous
        return insn.getAddress()

    def _anchored_start(self, call_address):
        """Start of the sequence feeding *call_address*, or ``None``."""
        abi = self.callsite_abi
        if abi is None:
            return None
        call_insn = self.listing.getInstructionAt(call_address)
        if call_insn is None:
            return None
        setup = self._buffer_at_callsite(call_insn, abi)
        if setup is None:
            return None
        displacement, length = setup
        low, high = displacement, displacement + max(length, 1)

        window = self._anchor_window(call_insn)
        if not window:
            return None
        earliest = self._earliest_buffer_write(window, low, high, abi)
        if earliest is None:
            return None
        return self._extend_to_feeders(earliest)

    def _earliest_buffer_write(self, window, low, high, abi):
        """Start of the run of buffer writes that reaches the end of *window*."""
        aliases = {}
        marks = []
        for insn in window:
            try:
                self._track_frame_aliases(insn, abi, aliases)
                marks.append(self._writes_into_buffer(insn, low, high, abi, aliases))
            except Exception:
                marks.append(False)

        earliest = None
        gap = 0
        for index in range(len(window) - 1, -1, -1):
            if marks[index]:
                earliest = window[index].getAddress()
                gap = 0
            elif earliest is not None:
                gap += 1
                if gap > MAX_ANCHOR_GAP:
                    break
        return earliest

    def _call_sites(self, target):
        """Addresses that call *target* (Binary Ninja: ``bv.get_callers``)."""
        sites = []
        refs = self.program.getReferenceManager().getReferencesTo(target)
        while refs.hasNext():
            ref = refs.next()
            if ref.getReferenceType().isCall():
                sites.append(ref.getFromAddress())
        return sites


    def find_targets(self, on_result=None, on_progress=None):
        """Port of ``find_target_locations`` + ``recurse_from_callsites``.

        Returns a list of ``(start_address, end_address)`` tuples and, when
        given, invokes *on_result* with each pair as it is discovered.
        """
        log_info("Finding slicebytetostring")
        target = self.find_slicebytetostring()
        if target is None:
            log_error("Unable to locate slicebytetostring")
            return []
        log_info(
            "Recursively enumerating all callsites from 0x%x" % target.getOffset()
        )

        results = []
        sites = self._call_sites(target)
        total = len(sites)
        counts = {"block": 0, "anchor": 0, SPLIT_FAMILY: 0, SEED_FAMILY: 0}
        for i, site in enumerate(sites):
            if self._is_cancelled():
                break
            if on_progress is not None:
                on_progress(i, total)
            block = self._block_at(site)
            if block is None:
                continue

            chosen = None
            starts = self._collect_obf_starts(block)
            if starts:
                chosen = starts[0] if len(starts) == 1 else starts[1]
                if len(starts) > 1:
                    log_info("0x%x has more than one start location:"
                             % site.getOffset())
                    for address in starts:
                        log_info("  0x%x" % address.getOffset())
                counts["block"] += 1
            else:
                chosen = self._anchored_start(site)
                if chosen is not None:
                    counts["anchor"] += 1

            if chosen is None and self.callsite_abi is not None:
                call_insn = self.listing.getInstructionAt(site)
                family = (self._callsite_family(call_insn, self.callsite_abi)
                          if call_insn is not None else None)
                if family in (SPLIT_FAMILY, SEED_FAMILY):
                    chosen = self._subroutine_start(site)
                    if chosen is not None:
                        counts[family] += 1

            if chosen is None:
                continue
            if chosen.compareTo(site) >= 0:
                continue
            results.append((chosen, site))
            if on_result is not None:
                on_result(chosen, site)

        log_info("%d location(s): %d block scan, %d callsite anchor, "
                 "%d split, %d seed"
                 % (len(results), counts["block"], counts["anchor"],
                    counts[SPLIT_FAMILY], counts[SEED_FAMILY]))
        if on_progress is not None:
            on_progress(total, total)
        return results
