"""Background-work helpers.

The Binary Ninja plugin used ``BackgroundTaskThread`` plus Qt signals to keep
the UI responsive and marshal results back to the table.  The Ghidra equivalent
is a Java thread plus ``SwingUtilities.invokeLater``.

Real Java threads are used rather than Python ``threading.Thread`` so the work
runs on a thread the JVM already knows about, and Ghidra's own ``Task`` class is
avoided because JPype can only implement Java *interfaces* from Python, not
extend Java classes.  ``TaskMonitor`` *is* an interface, so cancellation can be
propagated into Ghidra API calls -- see :func:`make_monitor`.
"""

import traceback

from java.lang import Runnable
from java.lang import Thread as JavaThread
from javax.swing import SwingUtilities
from jpype import JImplements, JOverride

from .log import log_error


def as_runnable(function):
    """Wrap a zero-argument python callable as a java.lang.Runnable."""

    @JImplements(Runnable)
    class _Runnable(object):
        @JOverride
        def run(self):
            try:
                function()
            except Exception:
                log_error(traceback.format_exc())

    return _Runnable()


def on_edt(function):
    """Schedule *function* on the Swing event dispatch thread."""
    SwingUtilities.invokeLater(as_runnable(function))


class BackgroundJob(object):
    """Cancellable worker, the stand-in for ``BackgroundTaskThread``.

    The job body receives this object so it can poll ``cancelled`` -- the same
    pattern the original plugin used with ``self.cancelled``.
    """

    def __init__(self, name, body, on_done=None):
        self.name = name
        self.body = body
        self.on_done = on_done
        self.cancelled = False
        self.done = False
        self.progress = ""
        self._thread = None

    def _wrapped(self):
        try:
            self.body(self)
        except Exception:
            log_error("%s failed:\n%s" % (self.name, traceback.format_exc()))
        finally:
            self.done = True
            if self.on_done is not None:
                on_edt(self.on_done)

    def start(self):
        self._thread = JavaThread(as_runnable(self._wrapped), self.name)
        self._thread.setDaemon(True)
        self._thread.start()
        return self

    def cancel(self):
        self.cancelled = True

    def is_running(self):
        return self._thread is not None and self._thread.isAlive()


def make_monitor(job):
    """A TaskMonitor whose cancelled state is backed by *job*.

    Falls back to ``TaskMonitor.DUMMY`` if the JPype proxy cannot be built, in
    which case cancellation is still honoured by our own loops (exactly as the
    Binary Ninja plugin behaved) -- just not inside Ghidra's own iterators.
    """
    from ghidra.util.task import TaskMonitor

    try:
        return _JobTaskMonitor(job)
    except Exception as exc:
        log_error("TaskMonitor proxy unavailable (%s); using DUMMY" % exc)
        return TaskMonitor.DUMMY


@JImplements("ghidra.util.task.TaskMonitor")
class _JobTaskMonitor(object):
    """Adapts a :class:`BackgroundJob` to Ghidra's TaskMonitor interface.

    Java overloads that share a name (``initialize``, ``incrementProgress``,
    ``increment``) collapse into one python method with a default argument,
    since a python class cannot declare the same name twice.
    """

    def __init__(self, job):
        self._job = job
        self._message = ""
        self._maximum = 0
        self._progress = 0
        self._indeterminate = False
        self._cancel_enabled = True
        self._listeners = []


    @JOverride
    def isCancelled(self):
        return bool(self._job.cancelled)

    @JOverride
    def cancel(self):
        self._job.cancel()

    def _check(self):
        if self._job.cancelled:
            from ghidra.util.exception import CancelledException

            raise CancelledException()

    @JOverride
    def checkCanceled(self):
        self._check()

    @JOverride
    def checkCancelled(self):
        self._check()

    @JOverride
    def clearCanceled(self):
        self._job.cancelled = False

    @JOverride
    def clearCancelled(self):
        self._job.cancelled = False

    @JOverride
    def isCancelEnabled(self):
        return self._cancel_enabled

    @JOverride
    def setCancelEnabled(self, enabled):
        self._cancel_enabled = bool(enabled)

    @JOverride
    def addCancelledListener(self, listener):
        self._listeners.append(listener)

    @JOverride
    def removeCancelledListener(self, listener):
        if listener in self._listeners:
            self._listeners.remove(listener)


    @JOverride
    def setMessage(self, message):
        self._message = str(message)
        self._job.progress = self._message

    @JOverride
    def getMessage(self):
        return self._message

    @JOverride
    def setProgress(self, value):
        self._progress = int(value)

    @JOverride
    def getProgress(self):
        return self._progress

    @JOverride
    def incrementProgress(self, amount=1):
        self._progress += int(amount)

    @JOverride
    def increment(self, amount=1):
        self._check()
        self._progress += int(amount)

    @JOverride
    def initialize(self, maximum, message=None):
        self._maximum = int(maximum)
        self._progress = 0
        if message is not None:
            self.setMessage(message)

    @JOverride
    def setMaximum(self, maximum):
        self._maximum = int(maximum)

    @JOverride
    def getMaximum(self):
        return self._maximum

    @JOverride
    def setIndeterminate(self, indeterminate):
        self._indeterminate = bool(indeterminate)

    @JOverride
    def isIndeterminate(self):
        return self._indeterminate

    @JOverride
    def setShowProgressValue(self, show):
        pass
