"""Pure-python re-implementation of Binary Refinery's ``carve printable``.

Only needed by the built-in PCode backend; the refinery backend uses the real
unit.  ``carve printable -n N`` yields every run of printable bytes at least N
bytes long.
"""

_PRINTABLE = frozenset(list(range(0x20, 0x7F)) + [0x09, 0x0A, 0x0D])


def carve_printable(data, min_len=8):
    """Return every printable run in *data* of at least *min_len* bytes."""
    runs = []
    current = bytearray()
    for byte in bytearray(data):
        if byte in _PRINTABLE:
            current.append(byte)
            continue
        if len(current) >= min_len:
            runs.append(bytes(current))
        del current[:]
    if len(current) >= min_len:
        runs.append(bytes(current))
    return runs


def best_printable(data, min_len=8):
    """Longest printable run in *data*, or ``""`` when nothing qualifies.

    Refinery's pipeline concatenates every carved chunk; for the PCode backend
    the emulated stack window contains a lot of unrelated slack, so returning
    the single longest run gives a far cleaner result.
    """
    runs = carve_printable(data, min_len)
    if not runs:
        return ""
    return max(runs, key=len).decode("ascii", "replace")
