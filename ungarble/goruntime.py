"""Stand-ins for the Go runtime helpers a garble decoder calls.

The stack-family decoder builds its blob with plain instructions, so emulating it
needs nothing from the runtime.  The **split** and **seed** families do not:

* split calls ``runtime.growslice`` (six times, in the sample measured) to grow
  the byte slice it assembles;
* seed calls ``runtime.newobject`` four times to allocate its closures and its
  result string header, and then makes ~24 *indirect* calls to those closures,
  which is where the actual decryption happens.

Emulating the real helpers is hopeless -- they need an initialised mheap, a
goroutine, a P -- and skipping them without supplying a return value is just as
useless, because the decoder then works through a null pointer.  So the helpers
get stubs, and the distinction that makes this work is:

    a **direct** call to a runtime helper is stubbed;
    an **indirect** call (``call rbx`` / ``call rcx``) is *executed*, because
    that is the obfuscator's own code and it is what computes the string.

Helper identification comes from the ``gopclntab`` names the plugin already
parses, so it is by name rather than by guessing from the callsite.
"""

from .log import log_info

HEAP_BASE_64 = 0x00007FFFE0000000
HEAP_BASE_32 = 0x2F000000
HEAP_SIZE = 0x40000

MAX_ALLOC = 0x4000
DEFAULT_ALLOC = 0x100

_ABI = {
    "x86": {
        "arg": ("RAX", "RBX", "RCX", "RDI", "RSI"),
        "ret": ("RAX", "RBX", "RCX"),
        "g": "R14",
    },
    "AARCH64": {
        "arg": ("x0", "x1", "x2", "x3", "x4"),
        "ret": ("x0", "x1", "x2"),
        "g": "x28",
    },
}

_GROWSLICE = "runtime.growslice"
_MEMMOVE = ("runtime.memmove", "runtime.typedmemmove", "runtime.typedslicecopy")
_NEWOBJECT = "runtime.newobject"
_VOID_PREFIXES = ("runtime.gcWriteBarrier", "runtime.morestack",
                  "runtime.wbMove", "runtime.publicationBarrier")


class GoRuntimeStubs(object):
    """Fake heap plus stubs for the helpers a decoder calls.

    *names* is the ``{address: name}`` map from :mod:`ungarble.gopclntab`; an
    empty map degrades this to "stub every direct call with a fresh allocation",
    which is still far better than stepping over it with no return value.
    """

    def __init__(self, program, names=None):
        self.program = program
        self.names = names or {}
        self.processor = str(program.getLanguage().getProcessor())
        self.abi = _ABI.get(self.processor)
        self.heap_base = (HEAP_BASE_64 if program.getDefaultPointerSize() >= 8
                          else HEAP_BASE_32)
        self.offset = 0
        self.allocations = 0


    def reset(self):
        self.offset = 0
        self.allocations = 0

    def allocate(self, size):
        """Bump-allocate *size* bytes, or ``None`` when the heap is exhausted."""
        size = max(1, min(int(size), MAX_ALLOC))
        size = (size + 15) & ~15
        if self.offset + size > HEAP_SIZE:
            return None
        pointer = self.heap_base + self.offset
        self.offset += size
        self.allocations += 1
        return pointer


    def name_of(self, address):
        if address is None:
            return None
        return self.names.get(int(address.getOffset()))


    def handle(self, emu, insn, read_register, write_register, read_memory):
        """Decide what to do with the call at *insn*.

        Returns ``True`` when the call was stubbed and the caller should step
        over it, ``False`` when it must be executed.
        """
        if self.abi is None:
            return True

        if not self._is_direct(insn):
            return False

        flows = insn.getFlows()
        target = flows[0] if flows else None
        name = self.name_of(target)

        if name is not None:
            if any(name.startswith(prefix) for prefix in _VOID_PREFIXES):
                return True
            if name == _GROWSLICE:
                self._growslice(read_register, write_register, read_memory, emu)
                return True
            if name == _NEWOBJECT:
                self._newobject(read_register, write_register, read_memory)
                return True
            if name in _MEMMOVE:
                self._memmove(read_register, read_memory, emu)
                return True

        pointer = self.allocate(DEFAULT_ALLOC)
        if pointer is not None:
            write_register(self.abi["ret"][0], pointer)
        return True

    @staticmethod
    def _is_direct(insn):
        """Whether the call names its target rather than going through a register."""
        from ghidra.program.model.lang import Register

        for index in range(insn.getNumOperands()):
            for obj in insn.getOpObjects(index):
                if isinstance(obj, Register):
                    return False
        return True


    def _newobject(self, read_register, write_register, read_memory):
        """``newobject(typ *_type) *any`` -- allocate a zeroed object.

        ``_type`` begins with its size, so the right amount can be allocated
        instead of guessing.
        """
        type_pointer = read_register(self.abi["arg"][0])
        size = DEFAULT_ALLOC
        if type_pointer:
            raw = read_memory(type_pointer, 8)
            if raw and len(raw) == 8:
                candidate = int.from_bytes(raw, "little")
                if 0 < candidate <= MAX_ALLOC:
                    size = candidate
        pointer = self.allocate(size)
        if pointer is not None:
            write_register(self.abi["ret"][0], pointer)

    def _memmove(self, read_register, read_memory, emu):
        """``memmove(dst, src, n)`` -- actually perform the copy.

        Stepping over a copy leaves the destination blank, which for a decoder
        that assembles its blob in pieces means losing the string.  There is no
        return value to fake, so the only useful stub is doing the work.
        """
        argument = self.abi["arg"]
        destination = read_register(argument[0])
        source = read_register(argument[1])
        count = read_register(argument[2]) or 0
        if not destination or not source or not 0 < count <= MAX_ALLOC:
            return
        raw = read_memory(source, count)
        if not raw:
            return
        try:
            emu.writeMemory(self._address(destination), bytes(raw))
        except Exception:
            pass

    def _growslice(self, read_register, write_register, read_memory, emu):
        """``growslice(oldPtr, newLen, oldCap, num, et) (ptr, len, cap)``.

        Allocates a bigger buffer and copies the old contents over, which is the
        part that matters: the split decoder appends to this slice repeatedly and
        loses the string if each grow returns a blank buffer.

        Note the return registers overlap the arguments -- ``newLen`` arrives in
        the same register the returned length goes out in -- so the requested
        length is read *before* anything is written back.
        """
        argument = self.abi["arg"]
        old_pointer = read_register(argument[0])
        new_length = read_register(argument[1]) or 0
        old_capacity = read_register(argument[2]) or 0

        capacity = max(new_length, old_capacity, 1)
        pointer = self.allocate(capacity)
        if pointer is None:
            return

        copy = min(old_capacity, capacity)
        if old_pointer and copy:
            raw = read_memory(old_pointer, copy)
            if raw:
                try:
                    emu.writeMemory(self._address(pointer), bytes(raw))
                except Exception:
                    pass

        write_register(self.abi["ret"][0], pointer)
        write_register(self.abi["ret"][1], new_length)
        write_register(self.abi["ret"][2], capacity)

    def _address(self, offset):
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(
            int(offset))


    def goroutine_register(self):
        """The register Go keeps the current goroutine in, or ``None``.

        Every Go function starts with ``cmp rsp,[r14+0x10]``; pointing that at
        the emulated stack keeps the check falling through instead of resolving
        through unmapped memory.
        """
        return self.abi["g"] if self.abi else None

    def describe(self):
        return ("fake heap at 0x%x (%d KiB), %d helper name(s) known"
                % (self.heap_base, HEAP_SIZE // 1024, len(self.names)))


_NAME_CACHE = {}


def load_names(program):
    """``{address: name}`` for runtime helper lookup, or ``{}``.  Cached."""
    try:
        key = (str(program.getName()), int(program.getUniqueProgramID()))
    except Exception:
        key = str(program.getName())
    if key in _NAME_CACHE:
        return _NAME_CACHE[key]
    try:
        from . import gopclntab

        names = gopclntab.parse(program)
    except Exception as exc:
        log_info("runtime helper names unavailable: %s" % exc)
        names = {}
    _NAME_CACHE[key] = names
    return names
