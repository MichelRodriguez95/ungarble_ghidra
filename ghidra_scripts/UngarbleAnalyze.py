# One-shot Ungarble: find, emulate and annotate garble strings without the GUI.
# @author Invoke RE (original Binary Ninja plugin); Ghidra port
# @category Golang
# @menupath Tools.Ungarble (analyze in place)
# @runtime PyGhidra

import os
import sys


def _package_root():
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        here = str(getSourceFile().getParentFile().getAbsolutePath())
    return os.path.dirname(here)


def _read_original(program):
    path = program.getExecutablePath()
    if not path:
        return None
    candidate = str(path)
    if not os.path.exists(candidate):
        candidate = candidate.lstrip("/")
        if not os.path.exists(candidate):
            return None
    with open(candidate, "rb") as handle:
        return handle.read()


def _apply(program, results):
    from ghidra.program.model.listing import BookmarkType

    from ungarble.compat import comment_type

    eol, pre = comment_type("EOL"), comment_type("PRE")

    listing = program.getListing()
    bookmarks = program.getBookmarkManager()
    tx = program.startTransaction("Ungarble: annotate strings")
    applied = 0
    try:
        for start, end, text in results:
            if not text:
                continue
            addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(end)
            listing.setComment(addr, eol, "ungarbled: %s" % text)
            listing.setComment(addr, pre, 'ungarbled: "%s"' % text)
            bookmarks.setBookmark(addr, BookmarkType.ANALYSIS, "Ungarble", text)
            applied += 1
    finally:
        program.endTransaction(tx, True)
    return applied


def main():
    root = _package_root()
    if root not in sys.path:
        sys.path.insert(0, root)

    from ungarble.engine import UngarbleEngine
    from ungarble.finder import UngarbleFinder

    program = currentProgram
    task_monitor = monitor

    targets = UngarbleFinder(program, task_monitor).find_targets()
    print("[Ungarble] %d target location(s)" % len(targets))
    if not targets:
        return

    engine = UngarbleEngine(program, _read_original(program), task_monitor)
    results = []
    for start, end in targets:
        if task_monitor.isCancelled():
            break
        text = engine.run(int(start.getOffset()), int(end.getOffset()), batch=True)
        results.append((int(start.getOffset()), int(end.getOffset()), text))

    print("[Ungarble] annotated %d string(s)" % _apply(program, results))

    try:
        from ungarble.symbols import recover_and_apply

        summary = recover_and_apply(program, program.getExecutablePath(),
                                    None, task_monitor, graph=False)
        print("[Ungarble] names: %d renamed, %d labeled (source: %s)"
              % (summary["renamed"], summary["labeled"], summary.get("source", "?")))
    except Exception as exc:
        print("[Ungarble] name recovery skipped: %s" % exc)


main()
