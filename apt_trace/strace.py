from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
                             ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.syscall import (SYSCALL_NAMES, SYSCALL_PROTOTYPES,
                            FILENAME_ARGUMENTS, SOCKET_SYSCALL_NAMES)
from ptrace.func_call import FunctionCallOptions
from sys import stderr, exit
from optparse import OptionParser
import os
from logging import getLogger, error
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.ctypes_tools import formatAddress
from ptrace.tools import signal_to_exitcode
import sys
import re
from typing import Optional


logger = getLogger(__name__)


class SyscallTracer(Application):
    def __init__(self):
        self.debugger: Optional[PtraceDebugger] = None
        Application.__init__(self)
        # Parse self.options
        self.parseOptions()
        # Setup output (log)
        self.setupLog()
        self.cache = {}

    def setupLog(self):
        self._output = None
        self._setupLog(stderr)

    def parseOptions(self):
        parser = OptionParser(
            usage="%prog [options] -- program [arg1 arg2 ...]")
        self.createCommonOptions(parser)
        self.createLogOptions(parser)
        parser.add_option("--auto", "-a",
                          help="Do not prompt for whether to install dependencies; automatically try all options "
                               "(this is the default if not run from a TTY)",
                          action="store_true", default=not sys.stdin.isatty() or not sys.stdout.isatty())
        parser.add_option("--auto-install-single", "-s",
                          help="If there is a single APT package that satisfies a missing file, install it "
                               "automatically, but if there are multiple possibilities then prompt the user",
                          action="store_true")
        self.options, self.program = parser.parse_args()

        # Create "only" filter
        only = set()
        for syscall, format in SYSCALL_PROTOTYPES.items():
            restype, arguments = format
            if any(argname in FILENAME_ARGUMENTS for argtype, argname in arguments):
                only.add(syscall)
        self.only = only

        self.options.fork = True
        self.options.show_pid = True
        self.options.show_ip = True
        self.processOptions()

    def ignoreSyscall(self, syscall):
        name = syscall.name
        if self.only and (name not in self.only):
            return True
        return False

    def syscallTrace(self, process):
        # First query to break at next syscall
        self.prepareProcess(process)
        exitcode = 0
        while True:
            # No more process? Exit
            if not self.debugger:
                break

            # Wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
            except ProcessExit as event:
                self.processExited(event)
                if event.exitcode is not None:
                    exitcode = event.exitcode
                continue
            except ProcessSignal as event:
                event.display(log=logger.debug)
                event.process.syscall(event.signum)
                exitcode = signal_to_exitcode(event.signum)
                continue
            except NewProcessEvent as event:
                self.newProcess(event)
                continue
            except ProcessExecution as event:
                self.processExecution(event)
                continue

            # Process syscall enter or exit
            self.syscall(event.process)
        return exitcode

    def handle_missing_file(self, path: str):
        pass

    def syscall(self, process):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall:
            if syscall.result is None:
                for argument in syscall.arguments:
                    if argument.name not in FILENAME_ARGUMENTS:
                        continue
                    try:
                        data, truncated = argument.function.process.readCString(argument.value, 1024)
                    except:
                        data = ""
                    filename = os.path.abspath(os.fsdecode(data))
                    if filename.startswith("/") and not (
                            os.path.exists(filename) or
                            filename.startswith("/home") or
                            filename.startswith("/usr/local") or
                            filename.startswith("/tmp")
                    ):
                        self.handle_missing_file(filename)

        # Break at next syscall
        process.syscall()

    def processExited(self, event):
        # Display syscall which has not exited
        state = event.process.syscall_state
        if (state.next_event == "exit") \
                and state.syscall:
            self.displaySyscall(state.syscall)

    def prepareProcess(self, process):
        process.syscall()
        process.syscall_state.ignore_callback = self.ignoreSyscall

    def newProcess(self, event):
        process = event.process
        self.prepareProcess(process)
        process.parent.syscall()

    def processExecution(self, event):
        process = event.process
        process.syscall()

    def runDebugger(self):
        # Create debugger and traced process
        self.setupDebugger()
        process = self.createProcess()
        if not process:
            return

        self.syscall_options = FunctionCallOptions(
            write_types=False,
            write_argname=False,
            string_max_length=3000,
            replace_socketcall=False,
            write_address=True,
            max_array_count=200,
        )
        self.syscall_options.instr_pointer = False

        return self.syscallTrace(process)

    def main(self) -> int:
        self.debugger = PtraceDebugger()
        exitcode = 0
        try:
            exitcode = self.runDebugger()
        except ProcessExit as event:
            self.processExited(event)
            if event.exitcode is not None:
                exitcode = event.exitcode
        except PtraceError as err:
            error("ptrace() error: %s" % err)
            if err.errno is not None:
                exitcode = err.errno
        except KeyboardInterrupt:
            error("Interrupted.")
            exitcode = 1
        except PTRACE_ERRORS as err:
            writeError(logger, err, "Debugger error")
            exitcode = 1
        self.debugger.quit()
        return exitcode

    def createChild(self, program):
        return Application.createChild(self, program)
