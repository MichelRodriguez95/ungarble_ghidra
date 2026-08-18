"""Backend selection and dispatch.

Prefers the Binary Refinery / Unicorn backend so results match the original
Binary Ninja plugin bit for bit, and falls back to Ghidra's PCode emulator when
refinery is missing (Jython, or a PyGhidra interpreter without the pip deps) or
when the original file on disk cannot be found.
"""

from .backends import pcode_backend, refinery_backend
from .log import log_error, log_info

REFINERY = refinery_backend.NAME
PCODE = pcode_backend.NAME


class UngarbleEngine(object):
    def __init__(self, program, file_data=None, monitor=None, prefer=None):
        self.program = program
        self.file_data = file_data
        self.monitor = monitor
        self.image_base = int(program.getImageBase().getOffset())
        self._pcode = None
        self.backend = self._select(prefer)
        log_info("Emulation backend: %s" % self.describe())

    def _select(self, prefer):
        """Pick a backend.  ``auto`` now means PCode, deliberately.

        It used to mean refinery-when-available, for bit-for-bit parity with the
        Binary Ninja original.  That stopped being the right default once the
        split and seed obfuscators were supported: those decoders call into the
        Go runtime, and only the PCode backend stands in for the helpers (see
        :mod:`ungarble.goruntime`).  Measured on the same binary, the PCode
        backend recovered **241** strings where the refinery path recovered 176.

        ``refinery`` is still selectable explicitly, and is still the way to
        reproduce the original plugin's results exactly.
        """
        if prefer == REFINERY:
            if refinery_backend.available():
                if self.file_data:
                    return REFINERY
                log_info(
                    "binary-refinery is installed but the original file is "
                    "unavailable; using the PCode backend"
                )
                return PCODE
            log_error(
                "binary-refinery unavailable (%s); using the PCode backend"
                % refinery_backend.unavailable_reason()
            )
        return PCODE

    def _pcode_backend(self):
        """The PCode backend for this program, built once."""
        if self._pcode is None or self._pcode.monitor is not self.monitor:
            self._pcode = pcode_backend.PcodeEmulationBackend(
                self.program, self.monitor)
        return self._pcode

    def describe(self):
        if self.backend == REFINERY:
            return "binary-refinery / Unicorn (vstack)"
        reason = refinery_backend.unavailable_reason()
        if reason:
            return "Ghidra PCode emulator (refinery unavailable: %s)" % reason
        return "Ghidra PCode emulator"

    def available_backends(self):
        backends = [PCODE]
        if refinery_backend.available() and self.file_data:
            backends.insert(0, REFINERY)
        return backends

    def set_backend(self, name):
        self.backend = name
        log_info("Emulation backend: %s" % self.describe())

    def run(self, start_address, stop_address, batch=True):
        """Recover the string for one ``(start, stop)`` pair.

        *batch* mirrors the two pipelines of the original plugin: the bulk
        "Ungarble Locations" run and the single-shot right-click action.
        """
        start = int(start_address)
        stop = int(stop_address)
        if start > stop:
            log_error("0x%x larger than 0x%x" % (start, stop))
            return ""

        if self.backend == REFINERY:
            try:
                return refinery_backend.run_vstack(
                    self.file_data, start, stop, self.image_base, batch=batch
                )
            except Exception as exc:
                log_error(
                    "refinery backend failed at 0x%x (%s); "
                    "falling back to the PCode emulator" % (start, exc)
                )

        backend = self._pcode_backend()
        return backend.run(start, stop, min_len=8 if batch else 9)

    def run_bytes(self, start_address, stop_address, require_constant=True):
        """Exact plaintext bytes for one sequence (for the patcher).

        Always uses the PCode backend: it reads the precise
        ``(pointer, length)`` the program passes to slicebytetostring, which is
        what an in-place patch needs.  The refinery backend carves printable
        runs and cannot guarantee an exact-length buffer.

        *require_constant* runs the sequence from two different machine states and
        returns bytes only when they agree, which is what keeps a legitimate
        ``string(byteSlice)`` conversion from being patched with one arbitrary
        snapshot of runtime data.  See
        :meth:`~ungarble.backends.pcode_backend.PcodeEmulationBackend.run_bytes_constant`.
        """
        start = int(start_address)
        stop = int(stop_address)
        if start > stop:
            return b""
        backend = self._pcode_backend()
        if require_constant:
            return backend.run_bytes_constant(start, stop)
        return backend.run_bytes(start, stop)
