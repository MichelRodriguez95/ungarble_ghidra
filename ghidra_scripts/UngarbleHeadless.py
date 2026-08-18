# Headless Ungarble: recover Golang garble-obfuscated strings without the GUI.
# @author Invoke RE (original Binary Ninja plugin); Ghidra port
# @category Golang
# @runtime PyGhidra

import json
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
    transaction = program.startTransaction("Ungarble: apply recovered strings")
    applied = 0
    try:
        for entry in results:
            if not entry["string"]:
                continue
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(
                entry["end"]
            )
            listing.setComment(address, eol, "ungarbled: %s" % entry["string"])
            listing.setComment(address, pre, 'ungarbled: "%s"' % entry["string"])
            bookmarks.setBookmark(
                address, BookmarkType.ANALYSIS, "Ungarble", entry["string"]
            )
            applied += 1
    finally:
        program.endTransaction(transaction, True)
    return applied


def main():
    root = _package_root()
    if root not in sys.path:
        sys.path.insert(0, root)

    from ungarble.engine import UngarbleEngine
    from ungarble.finder import UngarbleFinder

    program = currentProgram
    task_monitor = monitor

    finder = UngarbleFinder(program, task_monitor)
    targets = finder.find_targets()
    print("[Ungarble] %d target location(s)" % len(targets))
    if not targets:
        return

    engine = UngarbleEngine(program, _read_original(program), task_monitor)

    results = []
    for index, (start, end) in enumerate(targets):
        if task_monitor.isCancelled():
            break
        start_offset = int(start.getOffset())
        end_offset = int(end.getOffset())
        text = engine.run(start_offset, end_offset, batch=True)
        print(
            "[Ungarble] %d/%d 0x%x -> %s"
            % (index + 1, len(targets), start_offset, text)
        )
        results.append(
            {"start": start_offset, "end": end_offset, "string": text}
        )

    print("[Ungarble] applied %d comment(s)/bookmark(s)" % _apply(program, results))

    args = [str(a) for a in getScriptArgs()]

    if "--names" in args:
        args.remove("--names")
        graph = "--graph" in args
        if graph:
            args.remove("--graph")
        report = None
        if "--report" in args:
            ridx = args.index("--report")
            if ridx + 1 < len(args):
                report = args[ridx + 1]
                del args[ridx:ridx + 2]
        from ungarble.symbols import recover_and_apply

        sample = program.getExecutablePath()
        summary = recover_and_apply(program, sample, report, task_monitor, graph=graph)
        print("[Ungarble] names: %d renamed, %d labeled, %d skipped (source: %s)"
              % (summary["renamed"], summary["labeled"], summary["skipped"],
                 summary.get("source", "?")))

    strict = "--loose-patch" not in args
    if not strict:
        args.remove("--loose-patch")
    if "--patch" in args:
        idx = args.index("--patch")
        if idx + 1 >= len(args):
            print("[Ungarble] --patch requires an output path")
        else:
            out_path = args[idx + 1]
            del args[idx:idx + 2]
            original = _read_original(program)
            if original is None:
                print("[Ungarble] cannot patch: original binary not found on disk")
            else:
                from ungarble.patcher import write_patched_binary

                summary = write_patched_binary(program, original, targets,
                                               engine, out_path, strict=strict)
                print("[Ungarble] patched %d, skipped %d -> %s"
                      % (len(summary["patched"]), len(summary["skipped"]), out_path))
                for entry in summary["skipped"]:
                    print("[Ungarble]   skip 0x%x: %s" % (entry["start"], entry["reason"]))

    json_args = [a for a in args if not a.startswith("--")]
    if json_args:
        destination = json_args[0]
        with open(destination, "w") as handle:
            json.dump(results, handle, indent=2)
        print("[Ungarble] wrote %s" % destination)


main()
