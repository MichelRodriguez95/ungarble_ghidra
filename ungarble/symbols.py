"""Recover Go function names and apply them to the program (feature 8).

Design (per the plugin's dependency policy):

* **GoResolver, when available, is invoked as a console command found on PATH**
  -- never a hard-coded path, and never imported in-process. Running it as a
  subprocess also means it executes in its *own* environment, side-stepping the
  ``lief`` version clash it would otherwise cause inside PyGhidra.
    - ``goresolver resolve -x`` extracts the gopclntab names (fast).
    - ``goresolver resolve -g`` additionally recovers the *hashed* names by
      control-flow-graph similarity (slow: it builds reference Go binaries).
* **When GoResolver is not on PATH, a self-contained parser is used instead**
  (:mod:`ungarble.gopclntab`), which reads the table straight from Ghidra's
  memory with no external dependency.
* A **pre-generated GoResolver report** can always be imported directly
  (``report.json``); its graph-matched names take precedence over the gopclntab
  baseline.

garble hashes the author's own names (``main.checkPassword`` -> ``main.fwKj4nfcNL25``)
but leaves the standard-library names intact in the gopclntab, so even the
dependency-free path recovers most of the call graph's context.
"""

import json
import os
import shutil
import subprocess
import tempfile

from . import gopclntab
from .log import log_error, log_info

GORESOLVER_CMD = "goresolver"


def goresolver_path():
    """Location of the goresolver console tool on PATH, or ``None``."""
    return shutil.which(GORESOLVER_CMD)


def goresolver_available():
    return goresolver_path() is not None


def run_goresolver(sample_path, graph=False, go_versions=None, timeout=None):
    """Run the goresolver console tool and return ``{address: name}``.

    *graph* selects control-flow-graph recovery (``-g``, slow) over plain
    extraction (``-x``). Returns ``{}`` on any failure so callers can fall back.
    """
    exe = goresolver_path()
    if exe is None:
        return {}
    if not sample_path or not os.path.exists(str(sample_path)):
        log_error("goresolver: sample file not found on disk (%s)" % sample_path)
        return {}

    handle = tempfile.NamedTemporaryFile(
        suffix=".ungarble.goresolver.json", delete=False)
    handle.close()
    out = handle.name
    cmd = [exe, "-q", "resolve", "-g" if graph else "-x", "-o", out]
    if graph and go_versions:
        cmd += ["-v", ",".join(go_versions)]
    cmd.append(str(sample_path))
    log_info("running: %s" % " ".join(cmd))
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=timeout)
        mapping = load_goresolver_report(out)
    except subprocess.TimeoutExpired:
        log_error("goresolver timed out")
        return {}
    except subprocess.CalledProcessError as exc:
        log_error("goresolver exited with %s" % exc.returncode)
        return {}
    except Exception as exc:
        log_error("goresolver failed: %s" % exc)
        return {}
    finally:
        try:
            os.remove(out)
        except OSError:
            pass
    return mapping


def load_goresolver_report(report_path):
    """Return ``{address: name}`` from a GoResolver ``resolve`` JSON report.

    The report's ``Symbols`` field maps ``"0x...."`` entry addresses to a node
    carrying the resolved ``Name``.
    """
    with open(str(report_path), "r") as handle:
        data = json.load(handle)
    symbols = data.get("Symbols", data)
    mapping = {}
    for key, node in symbols.items():
        try:
            addr = int(key, 16) if isinstance(key, str) else int(key)
        except (TypeError, ValueError):
            continue
        name = node.get("Name") if isinstance(node, dict) else node
        if name:
            mapping[addr] = str(name)
    return mapping


def recover_names(program, sample_path=None, report_path=None,
                  run_console=True, graph=False, go_versions=None):
    """Gather ``{address: name}`` from the best available source.

    Order:
      1. explicit ``report_path`` (a pre-generated GoResolver report), merged
         with a gopclntab baseline;
      2. else the GoResolver console tool on PATH (``-x`` or ``-g``);
      3. else the built-in parser.

    Returns ``(mapping, source_label)``.
    """
    baseline = {}
    source = None

    if run_console and goresolver_available() and sample_path:
        baseline = run_goresolver(sample_path, graph=graph, go_versions=go_versions)
        if baseline:
            source = "goresolver console (%s)" % ("graph" if graph else "extract")

    if not baseline:
        baseline = gopclntab.parse(program)
        if baseline:
            source = "built-in gopclntab parser"

    if report_path:
        report = load_goresolver_report(report_path)
        for addr, name in report.items():
            baseline[addr] = name
        source = (source + " + report") if source else "GoResolver report"

    return baseline, (source or "none")


_BAD_CHARS = str.maketrans({" ": "_", "\t": "_", "\n": "_", ";": "_"})


def _sanitize(name):
    return name.translate(_BAD_CHARS)


def apply_symbols(program, mapping, monitor=None, only_default=True, add_comment=True):
    """Apply ``{address: name}`` to the program. Returns a summary dict."""
    from ghidra.program.model.symbol import SourceType

    from .compat import set_comment

    factory = program.getAddressFactory().getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    symbol_table = program.getSymbolTable()
    listing = program.getListing()

    renamed = labeled = skipped = 0
    tx = program.startTransaction("Ungarble: apply recovered names")
    try:
        for addr_value, raw_name in mapping.items():
            if monitor is not None and monitor.isCancelled():
                break
            name = _sanitize(str(raw_name))
            if not name:
                continue
            address = factory.getAddress(int(addr_value))
            func = func_mgr.getFunctionAt(address)
            if func is not None:
                current = func.getName()
                if only_default and not (
                    current.startswith("FUN_") or current.startswith("SUB_")
                ):
                    skipped += 1
                else:
                    try:
                        func.setName(name, SourceType.ANALYSIS)
                        renamed += 1
                    except Exception as exc:
                        log_error("rename 0x%x -> %s failed: %s"
                                  % (int(addr_value), name, exc))
                        skipped += 1
            else:
                try:
                    symbol_table.createLabel(address, name, SourceType.ANALYSIS)
                    labeled += 1
                except Exception:
                    skipped += 1
            if add_comment:
                try:
                    set_comment(listing, address, "PLATE", "go: %s" % raw_name)
                except Exception:
                    pass
    finally:
        program.endTransaction(tx, True)

    summary = {"renamed": renamed, "labeled": labeled, "skipped": skipped,
               "total": len(mapping)}
    log_info("names applied: %(renamed)d renamed, %(labeled)d labeled, "
             "%(skipped)d skipped (of %(total)d)" % summary)
    return summary


def recover_and_apply(program, sample_path=None, report_path=None, monitor=None,
                      run_console=True, graph=False, only_default=True,
                      add_comment=True):
    """Convenience: gather names from the best source and apply them."""
    mapping, source = recover_names(
        program, sample_path, report_path,
        run_console=run_console, graph=graph,
    )
    log_info("name source: %s (%d names)" % (source, len(mapping)))
    if not mapping:
        return {"renamed": 0, "labeled": 0, "skipped": 0, "total": 0,
                "source": source}
    summary = apply_symbols(program, mapping, monitor,
                            only_default=only_default, add_comment=add_comment)
    summary["source"] = source
    return summary
