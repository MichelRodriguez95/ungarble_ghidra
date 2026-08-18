"""Swing UI -- the port of ``ui/main_widget.py``.

Binary Ninja's ``UngarblePaneWidget`` was a Qt ``QWidget`` hosted in a
``WidgetPane``.  Ghidra's dockable equivalent, ``ComponentProvider``, is an
abstract Java class and JPype cannot extend Java classes from python, so this
uses a plain Swing ``JFrame`` parented to the Ghidra tool instead.  It picks up
Ghidra's look and feel automatically (same JVM) and navigates the listing
through ``GoToService``, so it behaves like a native Ghidra window.
"""

import os
import traceback

from java.awt import BorderLayout, Dimension, FlowLayout, Toolkit
from java.awt.datatransfer import StringSelection
from java.io import File as java_file
from java.awt.event import ActionListener, MouseListener
from java.lang import Object as JavaObject
from javax.swing import (
    BorderFactory,
    JButton,
    JComboBox,
    JFileChooser,
    JFrame,
    JLabel,
    JMenuItem,
    JOptionPane,
    JPanel,
    JPopupMenu,
    JScrollPane,
    JTable,
    ListSelectionModel,
    WindowConstants,
)
from javax.swing.table import DefaultTableModel
from jpype import JArray, JImplements, JOverride, JString

from .engine import PCODE, REFINERY, UngarbleEngine
from .finder import UngarbleFinder
from .log import log_error, log_info
from .tasks import BackgroundJob, make_monitor, on_edt

COLUMNS = ["Start Address", "End Address", "Ungarbled String"]

COL_START = 0
COL_END = 1
COL_STRING = 2


def _action_listener(function):
    @JImplements(ActionListener)
    class _Listener(object):
        @JOverride
        def actionPerformed(self, event):
            try:
                function()
            except Exception:
                log_error(traceback.format_exc())

    return _Listener()


def _mouse_listener(on_click=None, on_popup=None):
    @JImplements(MouseListener)
    class _Listener(object):
        @JOverride
        def mouseClicked(self, event):
            if on_click is not None and not event.isPopupTrigger():
                try:
                    on_click(event)
                except Exception:
                    log_error(traceback.format_exc())

        @JOverride
        def mousePressed(self, event):
            self._maybe_popup(event)

        @JOverride
        def mouseReleased(self, event):
            self._maybe_popup(event)

        @JOverride
        def mouseEntered(self, event):
            pass

        @JOverride
        def mouseExited(self, event):
            pass

        def _maybe_popup(self, event):
            if on_popup is not None and event.isPopupTrigger():
                try:
                    on_popup(event)
                except Exception:
                    log_error(traceback.format_exc())

    return _Listener()


def _row_array(values):
    """Build a java String[] -- avoids the addRow(Vector) overload."""
    return JArray(JString)([JString(v) for v in values])


class UngarbleWindow(object):
    def __init__(self, program, tool=None):
        self.program = program
        self.tool = tool
        self.engine = None
        self.file_data = None
        self.file_data_loaded = False
        self.job = None
        self.items = []
        self._build()


    def _build(self):
        self.frame = JFrame("Ungarble - %s" % self.program.getName())
        self.frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
        self.frame.setSize(Dimension(1100, 620))

        self.model = DefaultTableModel()
        for name in COLUMNS:
            self.model.addColumn(name)

        self.table = JTable(self.model)
        self.table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.setRowSelectionAllowed(True)
        try:
            self.table.setDefaultEditor(JavaObject.class_, None)
        except Exception:
            pass
        columns = self.table.getColumnModel()
        columns.getColumn(COL_START).setPreferredWidth(150)
        columns.getColumn(COL_END).setPreferredWidth(150)
        columns.getColumn(COL_STRING).setPreferredWidth(760)
        self.table.addMouseListener(
            _mouse_listener(self._on_table_click, self._on_table_popup)
        )

        scroll = JScrollPane(self.table)
        scroll.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        self.frame.getContentPane().setLayout(BorderLayout())
        self.frame.getContentPane().add(scroll, BorderLayout.CENTER)
        self.frame.getContentPane().add(self._build_controls(), BorderLayout.SOUTH)

        if self.tool is not None:
            try:
                self.frame.setLocationRelativeTo(self.tool.getToolFrame())
            except Exception:
                pass

    def _build_controls(self):
        panel = JPanel(BorderLayout())

        buttons = JPanel(FlowLayout(FlowLayout.LEFT))

        self.find_button = JButton("Get Target Locations")
        self.find_button.addActionListener(_action_listener(self.get_target_locations))
        buttons.add(self.find_button)

        self.ungarble_button = JButton("Ungarble Locations")
        self.ungarble_button.addActionListener(_action_listener(self.ungarble_locations))
        buttons.add(self.ungarble_button)

        self.cancel_button = JButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.addActionListener(_action_listener(self.cancel_job))
        buttons.add(self.cancel_button)

        self.apply_button = JButton("Apply to Program")
        self.apply_button.setToolTipText(
            "Add recovered strings as EOL comments and bookmarks at the "
            "slicebytetostring callsites"
        )
        self.apply_button.addActionListener(_action_listener(self.apply_to_program))
        buttons.add(self.apply_button)

        self.export_button = JButton("Write Deobfuscated Binary")
        self.export_button.setToolTipText(
            "Write a runnable copy of the binary with the string sequences "
            "patched in place so the plaintext is inline (amd64/arm64)"
        )
        self.export_button.addActionListener(_action_listener(self.write_deobfuscated))
        buttons.add(self.export_button)

        self.names_button = JButton("Recover Function Names")
        self.names_button.setToolTipText(
            "Recover Go function names from the gopclntab and, optionally, a "
            "GoResolver resolve report, and apply them to the program"
        )
        self.names_button.addActionListener(_action_listener(self.recover_names))
        buttons.add(self.names_button)

        self.export_table_button = JButton("Export Table…")
        self.export_table_button.setToolTipText("Export the results as JSON or CSV")
        self.export_table_button.addActionListener(_action_listener(self.export_table))
        buttons.add(self.export_table_button)

        self.copy_all_button = JButton("Copy All")
        self.copy_all_button.setToolTipText("Copy the whole table to the clipboard (TSV)")
        self.copy_all_button.addActionListener(_action_listener(self.copy_all))
        buttons.add(self.copy_all_button)

        buttons.add(JLabel("   Backend:"))
        self.backend_combo = JComboBox(
            _row_array(["auto", REFINERY, PCODE])
        )
        self.backend_combo.setToolTipText(
            "auto: binary-refinery when available, otherwise Ghidra's PCode emulator"
        )
        self.backend_combo.addActionListener(_action_listener(self._on_backend_changed))
        buttons.add(self.backend_combo)

        self.status = JLabel(" Ready.")
        self.status.setBorder(BorderFactory.createEmptyBorder(2, 8, 6, 8))

        panel.add(buttons, BorderLayout.CENTER)
        panel.add(self.status, BorderLayout.SOUTH)
        return panel

    def show(self):
        self.frame.setVisible(True)
        return self


    def _set_status(self, text):
        self.status.setText(" %s" % text)

    def _address(self, offset):
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(
            int(offset)
        )

    def _cell(self, row, column):
        value = self.model.getValueAt(row, column)
        return "" if value is None else str(value)

    def _row_offset(self, row, column):
        text = self._cell(row, column)
        return int(text, 16) if text else None

    def _job_running(self):
        if self.job is not None and self.job.is_running():
            self._set_status("A job is already running.")
            return True
        return False

    def _start_job(self, name, body):
        def finished():
            self.cancel_button.setEnabled(False)
            self.find_button.setEnabled(True)
            self.ungarble_button.setEnabled(True)

        self.job = BackgroundJob(name, body, on_done=finished)
        self.cancel_button.setEnabled(True)
        self.find_button.setEnabled(False)
        self.ungarble_button.setEnabled(False)
        self.job.start()
        return self.job

    def cancel_job(self):
        if self.job is not None:
            self.job.cancel()
            self._set_status("Cancelling...")


    @staticmethod
    def _read_file(path):
        if not path:
            return None
        candidate = str(path)
        if not os.path.exists(candidate):
            stripped = candidate.lstrip("/")
            if os.path.exists(stripped):
                candidate = stripped
            else:
                return None
        try:
            with open(candidate, "rb") as handle:
                data = handle.read()
        except Exception as exc:
            log_error("Could not read %s: %s" % (candidate, exc))
            return None
        log_info("Loaded %d bytes from %s" % (len(data), candidate))
        return data

    def _load_file_data(self):
        """Original bytes of the garbled binary, needed by the refinery backend.

        Mirrors the Binary Ninja plugin, which read the file behind the
        BNDB and prompted for a path when that failed.
        """
        data = self._read_file(self.program.getExecutablePath())
        if data is not None:
            return data

        chooser = JFileChooser()
        chooser.setDialogTitle("Select the original garbled binary")
        if chooser.showOpenDialog(self.frame) != JFileChooser.APPROVE_OPTION:
            JOptionPane.showMessageDialog(
                self.frame,
                "Path to the original garbled binary is needed for the "
                "binary-refinery backend.\nFalling back to Ghidra's PCode "
                "emulator.",
                "Not Found",
                JOptionPane.WARNING_MESSAGE,
            )
            return None
        picked = str(chooser.getSelectedFile().getAbsolutePath())
        data = self._read_file(picked)
        if data is None:
            JOptionPane.showMessageDialog(
                self.frame,
                "Could not read %s" % picked,
                "Not Found",
                JOptionPane.ERROR_MESSAGE,
            )
        return data

    def _preference(self):
        selected = str(self.backend_combo.getSelectedItem())
        return None if selected == "auto" else selected

    def _ensure_engine(self, monitor=None):
        if self.engine is None:
            if not self.file_data_loaded:
                self.file_data = self._load_file_data()
                self.file_data_loaded = True
            self.engine = UngarbleEngine(
                self.program, self.file_data, monitor, prefer=self._preference()
            )
            on_edt(lambda: self._set_status("Backend: %s" % self.engine.describe()))
        else:
            self.engine.monitor = monitor
        return self.engine

    def _on_backend_changed(self):
        self.engine = None
        self._set_status("Backend preference: %s" % self.backend_combo.getSelectedItem())


    def get_target_locations(self):
        """Port of ``getTargetLocations``."""
        if self._job_running():
            return
        log_info("[ + ] Getting target locations")
        self.items = []
        self.model.setRowCount(0)
        self._set_status("Finding slicebytetostring...")

        def body(job):
            monitor = make_monitor(job)
            finder = UngarbleFinder(self.program, monitor)

            def on_result(start, end):
                entry = {
                    "start": int(start.getOffset()),
                    "end": int(end.getOffset()),
                }
                self.items.append(entry)
                on_edt(lambda: self._add_row(entry["start"], entry["end"], ""))

            def on_progress(index, total):
                text = "%d/%d callsites checked" % (index, total)
                job.progress = text
                on_edt(lambda: self._set_status(text))

            finder.find_targets(on_result, on_progress)
            count = len(self.items)
            on_edt(
                lambda: self._set_status(
                    "%d target location(s) found." % count
                    if count
                    else "No garble string sequences found."
                )
            )

        self._start_job("Ungarble: finding locations", body)

    def ungarble_locations(self):
        """Port of ``ungarbleLocations`` -- emulate every unsolved row."""
        if self._job_running():
            return
        log_info("[ + ] Ungarbling all locations")

        locations = []
        for row in range(self.model.getRowCount()):
            start = self._row_offset(row, COL_START)
            end = self._row_offset(row, COL_END)
            if start is None or end is None:
                continue
            locations.append(
                {
                    "start": start,
                    "end": end,
                    "current": self._cell(row, COL_STRING),
                    "row": row,
                }
            )

        if not locations:
            self._set_status("Nothing to ungarble -- run 'Get Target Locations' first.")
            return

        def body(job):
            engine = self._ensure_engine(make_monitor(job))
            total = len(locations)
            for index, location in enumerate(locations):
                if job.cancelled:
                    break
                if not location["current"]:
                    log_info("Emulating 0x%x" % location["start"])
                    result = engine.run(location["start"], location["end"], batch=True)
                    log_info(
                        "Emulation result 0x%x // result: %s"
                        % (location["start"], result)
                    )
                    self._set_row_result(location["row"], result)
                text = "%d/%d target ranges emulated" % (index + 1, total)
                job.progress = text
                on_edt(lambda t=text: self._set_status(t))

        self._start_job("Ungarble: emulating locations", body)

    def ungarble_row(self, row):
        """Port of the ``Ungarble String`` context-menu action."""
        if self._job_running():
            return
        start = self._row_offset(row, COL_START)
        end = self._row_offset(row, COL_END)
        if start is None or end is None:
            return
        self._set_status("Emulating 0x%x -> 0x%x ..." % (start, end))

        def body(job):
            log_info("Emulating from: 0x%x to 0x%x" % (start, end))
            engine = self._ensure_engine(make_monitor(job))
            result = engine.run(start, end, batch=False)
            log_info("Found string: %s" % result)
            self._set_row_result(row, result)
            on_edt(lambda: self._set_status("Done: %s" % result))

        self._start_job("Ungarble: emulating 0x%x" % start, body)

    def apply_to_program(self):
        """Ghidra-native extra: persist results into the program database.

        Recovered strings become EOL comments plus bookmarks at the
        slicebytetostring callsite, so they survive outside this window.
        """
        from ghidra.program.model.listing import BookmarkType

        rows = []
        for row in range(self.model.getRowCount()):
            text = self._cell(row, COL_STRING).strip()
            end = self._row_offset(row, COL_END)
            if text and end is not None:
                rows.append((end, text))

        if not rows:
            self._set_status("No recovered strings to apply.")
            return

        transaction = self.program.startTransaction("Ungarble: apply recovered strings")
        applied = 0
        try:
            bookmarks = self.program.getBookmarkManager()
            for offset, text in rows:
                address = self._address(offset)
                self._set_comment(address, "EOL", "ungarbled: %s" % text)
                self._set_comment(address, "PRE", 'ungarbled: "%s"' % text)
                bookmarks.setBookmark(
                    address, BookmarkType.ANALYSIS, "Ungarble", text
                )
                applied += 1
        except Exception:
            log_error(traceback.format_exc())
        finally:
            self.program.endTransaction(transaction, True)
        self._set_status("Applied %d string(s) as comments and bookmarks." % applied)

    def write_deobfuscated(self):
        """Write a runnable copy with string sequences patched in place."""
        if self._job_running():
            return

        pairs = []
        for row in range(self.model.getRowCount()):
            start = self._row_offset(row, COL_START)
            end = self._row_offset(row, COL_END)
            if start is not None and end is not None:
                pairs.append((self._address(start), self._address(end)))
        if not pairs:
            self._set_status("No target locations -- run 'Get Target Locations' first.")
            return

        from ghidra.program.model.listing import Program

        from .patcher import Patcher

        if not Patcher(self.program).supported:
            processor = str(self.program.getLanguage().getProcessor())
            JOptionPane.showMessageDialog(
                self.frame,
                "In-place patching supports amd64 and arm64 only.\n"
                "This program is %s / %d-bit."
                % (processor, self.program.getDefaultPointerSize() * 8),
                "Unsupported architecture",
                JOptionPane.WARNING_MESSAGE,
            )
            return

        if not self.file_data_loaded:
            self.file_data = self._load_file_data()
            self.file_data_loaded = True
        if not self.file_data:
            self._set_status("Original binary is required to write a patched copy.")
            return

        chooser = JFileChooser()
        chooser.setDialogTitle("Write deobfuscated binary as")
        default = str(self.program.getName()) + ".deobf"
        chooser.setSelectedFile(java_file(default))
        if chooser.showSaveDialog(self.frame) != JFileChooser.APPROVE_OPTION:
            return
        out_path = str(chooser.getSelectedFile().getAbsolutePath())

        def body(job):
            from .patcher import write_patched_binary

            engine = self._ensure_engine(make_monitor(job))

            def on_progress(index, total):
                text = "%d/%d sequences patched" % (index, total)
                job.progress = text
                on_edt(lambda: self._set_status(text))

            summary = write_patched_binary(
                self.program, self.file_data, pairs, engine, out_path,
                on_progress=on_progress,
            )
            patched = len(summary["patched"])
            skipped = len(summary["skipped"])
            on_edt(lambda: self._report_patch_summary(out_path, patched, skipped, summary))

        self._start_job("Ungarble: writing deobfuscated binary", body)

    def _report_patch_summary(self, out_path, patched, skipped, summary):
        self._set_status(
            "Wrote %s -- %d patched, %d skipped." % (out_path, patched, skipped)
        )
        lines = ["Wrote %s" % out_path,
                 "",
                 "Patched: %d" % patched,
                 "Skipped: %d" % skipped]
        if summary["skipped"]:
            lines.append("")
            lines.append("Skipped locations:")
            for entry in summary["skipped"][:20]:
                lines.append("  0x%x -- %s" % (entry["start"], entry["reason"]))
            if len(summary["skipped"]) > 20:
                lines.append("  ... and %d more" % (len(summary["skipped"]) - 20))
        JOptionPane.showMessageDialog(
            self.frame, "\n".join(lines), "Deobfuscated binary written",
            JOptionPane.INFORMATION_MESSAGE,
        )


    def _table_rows(self):
        rows = []
        for row in range(self.model.getRowCount()):
            rows.append({
                "start": self._cell(row, COL_START),
                "end": self._cell(row, COL_END),
                "string": self._cell(row, COL_STRING),
            })
        return rows

    def export_table(self):
        rows = self._table_rows()
        if not rows:
            self._set_status("Nothing to export.")
            return
        chooser = JFileChooser()
        chooser.setDialogTitle("Export results")
        chooser.setSelectedFile(java_file(str(self.program.getName()) + "_ungarble.json"))
        if chooser.showSaveDialog(self.frame) != JFileChooser.APPROVE_OPTION:
            return
        path = str(chooser.getSelectedFile().getAbsolutePath())
        try:
            if path.lower().endswith(".csv"):
                self._write_csv(path, rows)
            else:
                self._write_json(path, rows)
        except Exception:
            log_error(traceback.format_exc())
            self._set_status("Export failed -- see log.")
            return
        self._set_status("Exported %d row(s) to %s" % (len(rows), path))

    @staticmethod
    def _write_json(path, rows):
        import json

        with open(path, "w") as handle:
            json.dump(rows, handle, indent=2)

    @staticmethod
    def _write_csv(path, rows):
        import csv

        with open(path, "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["start", "end", "string"])
            for r in rows:
                writer.writerow([r["start"], r["end"], r["string"]])

    def copy_all(self):
        rows = self._table_rows()
        if not rows:
            self._set_status("Nothing to copy.")
            return
        lines = ["start\tend\tstring"]
        for r in rows:
            lines.append("%s\t%s\t%s" % (r["start"], r["end"], r["string"]))
        self._copy("\n".join(lines))
        self._set_status("Copied %d row(s) to the clipboard." % len(rows))


    def recover_names(self):
        if self._job_running():
            return

        from javax.swing import JOptionPane as _JOP
        from .symbols import goresolver_available

        report_path = [None]
        graph = [False]

        if goresolver_available():
            choice = _JOP.showConfirmDialog(
                self.frame,
                "GoResolver was found on PATH.\n\n"
                "Run control-flow-graph matching to also de-hash the author's\n"
                "own function names?  This is slower (it builds reference Go\n"
                "binaries) but recovers names garble hashed.\n\n"
                "Yes: graph (-g, slow).  No: fast extract (-x).  Cancel: abort.",
                "Recover Function Names", _JOP.YES_NO_CANCEL_OPTION,
            )
            if choice == _JOP.CANCEL_OPTION:
                return
            graph[0] = (choice == _JOP.YES_OPTION)
        else:
            choice = _JOP.showConfirmDialog(
                self.frame,
                "GoResolver is not on PATH; the built-in gopclntab parser will\n"
                "be used (standard-library names; garble-hashed names stay hashed).\n\n"
                "Import a pre-generated GoResolver report as well?\n"
                "Yes: pick a report.  No: parser only.  Cancel: abort.",
                "Recover Function Names", _JOP.YES_NO_CANCEL_OPTION,
            )
            if choice == _JOP.CANCEL_OPTION:
                return
            if choice == _JOP.YES_OPTION:
                chooser = JFileChooser()
                chooser.setDialogTitle("Select GoResolver resolve report (JSON)")
                if chooser.showOpenDialog(self.frame) == JFileChooser.APPROVE_OPTION:
                    report_path[0] = str(chooser.getSelectedFile().getAbsolutePath())

        sample_path = self.program.getExecutablePath()
        self._set_status("Recovering function names...")

        def body(job):
            from .symbols import recover_and_apply

            summary = recover_and_apply(
                self.program, sample_path, report_path[0], make_monitor(job),
                graph=graph[0],
            )
            on_edt(lambda: self._report_names_summary(summary))

        self._start_job("Ungarble: recovering names", body)

    def _report_names_summary(self, summary):
        self._set_status(
            "Names: %d renamed, %d labeled, %d skipped (source: %s)."
            % (summary["renamed"], summary["labeled"], summary["skipped"],
               summary.get("source", "?"))
        )
        if summary["total"] == 0:
            JOptionPane.showMessageDialog(
                self.frame,
                "No names recovered.\n\nEither the binary has no gopclntab, or "
                "it is an unusual Go version. If GoResolver is installed, make "
                "sure `goresolver` is on PATH.",
                "Recover Function Names", JOptionPane.WARNING_MESSAGE,
            )

    def _set_comment(self, address, kind, text):
        """Set an EOL or PRE comment, tolerant of the Ghidra enum rename."""
        from .compat import set_comment

        set_comment(self.program.getListing(), address, kind, text)


    def _add_row(self, start, end, text):
        self.model.addRow(_row_array(["0x%x" % start, "0x%x" % end, text]))

    def _set_row_result(self, row, result):
        def update():
            if row < self.model.getRowCount():
                self.model.setValueAt(result, row, COL_STRING)

        on_edt(update)

    def _on_table_click(self, event):
        """Clicking an address column navigates the listing."""
        row = self.table.rowAtPoint(event.getPoint())
        column = self.table.columnAtPoint(event.getPoint())
        if row < 0 or column not in (COL_START, COL_END):
            return
        offset = self._row_offset(row, column)
        if offset is not None:
            self.goto(offset)

    def goto(self, offset):
        address = self._address(offset)
        service = self._goto_service()
        if service is None:
            log_error("GoToService unavailable; cannot navigate to 0x%x" % offset)
            return
        service.goTo(address)

    def _goto_service(self):
        if self.tool is None:
            return None
        from ghidra.app.services import GoToService

        for candidate in (GoToService, getattr(GoToService, "class_", None)):
            if candidate is None:
                continue
            try:
                service = self.tool.getService(candidate)
                if service is not None:
                    return service
            except Exception:
                continue
        return None

    def _on_table_popup(self, event):
        row = self.table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        self.table.setRowSelectionInterval(row, row)

        menu = JPopupMenu()

        ungarble_item = JMenuItem("Ungarble String")
        ungarble_item.addActionListener(_action_listener(lambda: self.ungarble_row(row)))
        menu.add(ungarble_item)

        copy_item = JMenuItem("Copy String")
        copy_item.addActionListener(
            _action_listener(lambda: self._copy(self._cell(row, COL_STRING)))
        )
        menu.add(copy_item)

        menu.addSeparator()

        goto_start = JMenuItem("Go To Start Address")
        goto_start.addActionListener(
            _action_listener(lambda: self.goto(self._row_offset(row, COL_START)))
        )
        menu.add(goto_start)

        goto_end = JMenuItem("Go To End Address")
        goto_end.addActionListener(
            _action_listener(lambda: self.goto(self._row_offset(row, COL_END)))
        )
        menu.add(goto_end)

        menu.show(event.getComponent(), event.getX(), event.getY())

    @staticmethod
    def _copy(text):
        if not text:
            return
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)
