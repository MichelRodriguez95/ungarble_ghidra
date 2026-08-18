"""Dependency-free fallback backend built on Ghidra's own PCode emulator.

Used when binary-refinery / Unicorn are not installed.  It replaces refinery's
``vstack`` unit with ``EmulatorHelper``: run the obfuscation sequence, then
recover the plaintext.

Two recovery strategies, in order:

1.  **Register ABI.**  Emulation stops *at* the ``call slicebytetostring``, so
    the Go register ABI still holds the arguments -- on amd64 ``RBX`` is the
    data pointer and ``RCX`` the length.  This yields the exact string with no
    guessing, and is more precise than carving.
2.  **Stack carve.**  If the registers are implausible, fall back to carving
    the longest printable run out of the emulated stack window, which is what
    ``vstack | carve printable`` effectively does.

Ghidra's ``MemoryAccessFilter`` (the natural write-logging hook) is an abstract
class, and JPype can only implement Java *interfaces* from Python, so writes
cannot be logged directly -- hence the read-back approach above.
"""

from ghidra.util.task import TaskMonitor

from .. import goruntime
from ..carve import best_printable
from ..log import log_error, log_info

NAME = "pcode"

_STACK_SIZE = 0x10000
_STACK_BASE_64 = 0x00007FFFF0000000
_STACK_BASE_32 = 0x2FFF0000

MAX_STEPS = 200000

MAX_STRING_LEN = 8192

_ABI = {
    ("x86", 8): ("RBX", "RCX"),
    ("AARCH64", 8): ("x1", "x2"),
}

_SEED_REGISTERS = {
    "x86": ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI",
            "R8", "R9", "R10", "R11", "R12", "R13"),
    "AARCH64": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                "x8", "x9", "x10", "x11"),
}


def available():
    """Always available -- it only uses Ghidra's own emulator."""
    return True


def unavailable_reason():
    return None


def _permissive_fault_handler():
    """A MemoryFaultHandler that treats every fault as 'read zeros, continue'.

    Without this, any read of uninitialized memory (.bss, TLS, unmapped stack
    slack) aborts the run instead of degrading gracefully.
    """
    from ghidra.pcode.memstate import MemoryFaultHandler
    from jpype import JImplements, JOverride

    @JImplements(MemoryFaultHandler)
    class _Handler(object):
        @JOverride
        def uninitializedRead(self, address, size, buf, buf_offset):
            return True

        @JOverride
        def unknownAddress(self, address, write):
            return True

    return _Handler()


def _to_bytes(java_array):
    if java_array is None:
        return b""
    return bytes(bytearray(int(b) & 0xFF for b in java_array))


def _write_reg(emu, name, value):
    """Write an unsigned int to a register, tolerating an unknown name."""
    try:
        emu.writeRegister(name, int(value))
        return True
    except Exception:
        return False


def _reg(emu, name):
    """Read a register as an unsigned Python int, or None."""
    try:
        value = emu.readRegister(name)
    except Exception:
        return None
    if value is None:
        return None
    return int(value.longValue()) & 0xFFFFFFFFFFFFFFFF


class PcodeEmulationBackend(object):
    def __init__(self, program, monitor=None):
        self.program = program
        self.monitor = monitor if monitor is not None else TaskMonitor.DUMMY
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        self.pointer_size = program.getDefaultPointerSize()
        processor = str(program.getLanguage().getProcessor())
        self.processor = processor
        self.abi = _ABI.get((processor, self.pointer_size))
        self.stack_base = (
            _STACK_BASE_64 if self.pointer_size >= 8 else _STACK_BASE_32
        )
        self._runtime_stubs = None

    def _address(self, offset):
        return self.space.getAddress(offset)

    def _prepare(self, emu, start_address, fill=0x00, seed_registers=None):
        """Set up a run.  *fill* is the byte the stack window starts as.

        *seed_registers* pre-loads the scratch/argument registers with a value.
        Both exist so the same sequence can be run from two different starting
        states -- see :meth:`run_bytes_constant`.
        """
        emu.setMemoryFaultHandler(_permissive_fault_handler())

        pattern = bytes((fill & 0xFF,)) * _STACK_SIZE
        try:
            emu.writeMemory(self._address(self.stack_base), pattern)
        except Exception:
            from jpype import JArray, JByte

            signed = (fill & 0xFF) - 256 if (fill & 0xFF) > 127 else (fill & 0xFF)
            emu.writeMemory(
                self._address(self.stack_base),
                JArray(JByte)([signed] * _STACK_SIZE),
            )

        if seed_registers is not None:
            for name in _SEED_REGISTERS.get(self.processor, ()):
                try:
                    emu.writeRegister(name, seed_registers)
                except Exception:
                    pass

        stubs = self._stubs()
        if stubs is not None:
            stubs.reset()
            try:
                emu.writeMemory(self._address(stubs.heap_base),
                                b"\x00" * goruntime.HEAP_SIZE)
            except Exception:
                pass
            register = stubs.goroutine_register()
            if register is not None:
                try:
                    emu.writeRegister(register, self.stack_base + _STACK_SIZE // 2)
                except Exception:
                    pass

        sp_register = emu.getStackPointerRegister()
        emu.writeRegister(sp_register, self.stack_base + _STACK_SIZE // 2)
        emu.getEmulator().setExecuteAddress(start_address)

    def _stubs(self):
        """Lazily built Go runtime stubs, shared across runs of this backend."""
        if self._runtime_stubs is None:
            try:
                self._runtime_stubs = goruntime.GoRuntimeStubs(
                    self.program, goruntime.load_names(self.program))
                log_info("Go runtime stubs: %s" % self._runtime_stubs.describe())
            except Exception as exc:
                log_error("could not build Go runtime stubs: %s" % exc)
                self._runtime_stubs = False
        return self._runtime_stubs or None

    def _read_memory(self, emu, pointer, size):
        try:
            return _to_bytes(emu.readMemory(self._address(pointer), int(size)))
        except Exception:
            return b""

    def _run_to(self, emu, stop_address, skip_calls):
        """Step until *stop_address*; returns True when it was reached.

        *skip_calls* no longer means "step over every call".  A split or seed
        decoder calls ``runtime.growslice`` / ``runtime.newobject`` -- which must
        be stubbed, since stepping over them leaves a null pointer behind -- and
        then calls its *own* closures indirectly, which must be executed because
        that is where the decryption happens.  :class:`GoRuntimeStubs` decides
        which is which; see :mod:`ungarble.goruntime`.
        """
        listing = self.program.getListing()
        stubs = self._stubs() if skip_calls else None
        steps = 0
        while steps < MAX_STEPS:
            if self.monitor.isCancelled():
                return False
            current = emu.getExecutionAddress()
            if current is None:
                return False
            if current.getOffset() == stop_address:
                return True

            if skip_calls:
                insn = listing.getInstructionAt(current)
                if insn is not None and insn.getFlowType().isCall():
                    fallthrough = insn.getFallThrough()
                    handled = True
                    if stubs is not None:
                        try:
                            handled = stubs.handle(
                                emu, insn,
                                lambda name: _reg(emu, name),
                                lambda name, value: _write_reg(emu, name, value),
                                lambda pointer, size: self._read_memory(
                                    emu, pointer, size),
                            )
                        except Exception as exc:
                            log_info("runtime stub failed at 0x%x: %s"
                                     % (current.getOffset(), exc))
                            handled = True
                    if handled and fallthrough is not None:
                        emu.getEmulator().setExecuteAddress(fallthrough.getOffset())
                        steps += 1
                        continue

            try:
                if not emu.step(self.monitor):
                    log_info("emulation stopped: %s" % emu.getLastError())
                    return False
            except Exception as exc:
                log_info("emulation aborted at 0x%x: %s" % (current.getOffset(), exc))
                return False
            steps += 1

        log_info("emulation hit the %d instruction cap" % MAX_STEPS)
        return False

    def _read_argument_bytes(self, emu):
        """Raw ``(pointer, length)`` bytes of the slicebytetostring argument.

        Returns ``b""`` when the registers look implausible, so callers can
        fall back to carving.
        """
        if self.abi is None:
            return b""
        ptr_reg, len_reg = self.abi
        pointer = _reg(emu, ptr_reg)
        length = _reg(emu, len_reg)
        if not pointer or not length:
            return b""
        length &= 0xFFFFFFFF
        if length <= 0 or length > MAX_STRING_LEN:
            return b""
        try:
            raw = _to_bytes(emu.readMemory(self._address(pointer), int(length)))
        except Exception:
            return b""
        if not raw:
            return b""
        printable = sum(1 for b in bytearray(raw) if 0x20 <= b < 0x7F or b in (9, 10, 13))
        if printable * 4 < len(raw) * 3:
            return b""
        return raw

    def _recover_from_registers(self, emu):
        raw = self._read_argument_bytes(emu)
        return raw.decode("ascii", "replace") if raw else ""

    def _recover_from_stack(self, emu, min_len):
        try:
            raw = _to_bytes(emu.readMemory(self._address(self.stack_base), _STACK_SIZE))
        except Exception:
            return ""
        return best_printable(raw, min_len)

    def _attempt_bytes(self, start_address, stop_address, skip_calls,
                       fill=0x00, seed_registers=None):
        """Like :meth:`_attempt` but returns exact argument bytes, no carving.

        Used by the patcher, which needs the precise buffer the program passes
        to slicebytetostring -- carving the stack would fold in neighbouring
        bytes and corrupt the inline string.
        """
        from ghidra.app.emulator import EmulatorHelper

        emu = EmulatorHelper(self.program)
        try:
            self._prepare(emu, start_address, fill=fill,
                          seed_registers=seed_registers)
            reached = self._run_to(emu, stop_address, skip_calls)
            return self._read_argument_bytes(emu), reached
        finally:
            try:
                emu.dispose()
            except Exception:
                pass

    def run_bytes_with_overlay(self, start_address, stop_address,
                               overlay_address, overlay_bytes):
        """Emulate with *overlay_bytes* written over the emulator's memory.

        Used to verify a patch (feature 5): the stub is laid into the emulator's
        own memory state -- never the program database, which would conflict
        with the defined instructions -- and executed, so we confirm the patched
        code really hands the plaintext to slicebytetostring.
        """
        from ghidra.app.emulator import EmulatorHelper
        from jpype import JArray, JByte

        signed = [b - 256 if b > 127 else b for b in bytearray(overlay_bytes)]
        emu = EmulatorHelper(self.program)
        try:
            self._prepare(emu, int(start_address))
            emu.writeMemory(self._address(int(overlay_address)), JArray(JByte)(signed))
            self._run_to(emu, int(stop_address), False)
            return self._read_argument_bytes(emu)
        except Exception as exc:
            log_error("overlay emulation failed at 0x%x: %s" % (start_address, exc))
            return b""
        finally:
            try:
                emu.dispose()
            except Exception:
                pass

    def run_bytes(self, start_address, stop_address, fill=0x00,
                  seed_registers=None):
        """Exact plaintext bytes for one sequence, or ``b""``."""
        if start_address > stop_address:
            return b""
        for skip_calls in (True, False):
            try:
                raw, reached = self._attempt_bytes(
                    start_address, stop_address, skip_calls,
                    fill=fill, seed_registers=seed_registers)
            except Exception as exc:
                log_error("PCode emulation failed at 0x%x: %s" % (start_address, exc))
                return b""
            if raw:
                return raw
            if reached or self.monitor.isCancelled():
                break
        return b""

    def run_bytes_constant(self, start_address, stop_address):
        """Bytes for the sequence, but only if they do not depend on input.

        Broadening detection to the callsite (see ``finder._anchored_start``)
        also picks up **legitimate** ``string(someByteSlice)`` conversions, where
        the buffer holds data computed at run time.  Emulating one of those in a
        blank machine still yields *something*, and re-emulating the stub then
        confirms the stub reproduces that something -- so the existing
        verification cannot tell the difference, and patching would freeze one
        arbitrary value into the program.

        A garble literal is a compile-time constant: it is built from immediates
        and keys inside the region and reads nothing else.  So run the sequence
        from two different machine states and keep the result only when they
        agree.  A runtime conversion reads whatever the seed put in its registers
        or stack slot and the two runs disagree.

        Returns ``b""`` when the two runs differ.
        """
        first = self.run_bytes(start_address, stop_address,
                               fill=0x00, seed_registers=0)
        if not first:
            return b""
        second = self.run_bytes(start_address, stop_address,
                                fill=0xA5, seed_registers=0xA5A5A5A5A5A5A5A5)
        if second and first != second:
            log_info("0x%x is not constant across machine states "
                     "(%r vs %r); not a literal, skipping"
                     % (start_address, first[:24], second[:24]))
            return b""
        return first

    def _attempt(self, start_address, stop_address, min_len, skip_calls):
        from ghidra.app.emulator import EmulatorHelper

        emu = EmulatorHelper(self.program)
        try:
            self._prepare(emu, start_address)
            reached = self._run_to(emu, stop_address, skip_calls)
            result = self._recover_from_registers(emu)
            if not result:
                result = self._recover_from_stack(emu, min_len)
            return result, reached
        finally:
            try:
                emu.dispose()
            except Exception:
                pass

    def run(self, start_address, stop_address, min_len=8):
        """Emulate the sequence and return the recovered string."""
        if start_address > stop_address:
            raise ValueError("0x%x larger than 0x%x" % (start_address, stop_address))
        for skip_calls in (True, False):
            try:
                result, reached = self._attempt(
                    start_address, stop_address, min_len, skip_calls)
            except Exception as exc:
                log_error("PCode emulation failed at 0x%x: %s" % (start_address, exc))
                return ""
            if result:
                return result
            if reached or self.monitor.isCancelled():
                break
        return ""


def run_vstack(program, start_address, stop_address, monitor=None, batch=True):
    """Signature-compatible entry point mirroring the refinery backend."""
    backend = PcodeEmulationBackend(program, monitor)
    return backend.run(start_address, stop_address, min_len=8 if batch else 9)
