"""Ghidra API differences the plugin has to straddle.

Ghidra replaced the integer comment constants on ``CodeUnit``
(``CodeUnit.EOL_COMMENT``) with a ``CommentType`` enum.  Every call site used to
carry its own ``try``/``except`` for that -- except :mod:`ungarble.symbols`,
which imported the enum unguarded and so died with an ``ImportError`` on the
older API, taking the whole of *Recover Function Names* with it.  Resolving it
in one place is what stops the four call sites from drifting apart again.

``setComment`` takes whichever type the running Ghidra understands, so callers
pass a plain string kind (``"EOL"``, ``"PRE"``, ``"PLATE"``) and get the right
object back.
"""

_LEGACY = {
    "EOL": "EOL_COMMENT",
    "PRE": "PRE_COMMENT",
    "POST": "POST_COMMENT",
    "PLATE": "PLATE_COMMENT",
    "REPEATABLE": "REPEATABLE_COMMENT",
}

_CACHE = {}


def _resolve(kind):
    try:
        from ghidra.program.model.listing import CommentType

        return getattr(CommentType, kind)
    except Exception:
        from ghidra.program.model.listing import CodeUnit

        return getattr(CodeUnit, _LEGACY[kind])


def comment_type(kind):
    """The comment-type value this Ghidra's ``setComment`` expects."""
    key = str(kind).upper()
    if key not in _CACHE:
        _CACHE[key] = _resolve(key)
    return _CACHE[key]


def set_comment(listing, address, kind, text):
    """``listing.setComment`` with the comment type resolved per Ghidra version."""
    listing.setComment(address, comment_type(kind), text)
