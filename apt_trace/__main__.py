import subprocess
from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
                             ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.syscall import (SYSCALL_NAMES, SYSCALL_PROTOTYPES,
                            FILENAME_ARGUMENTS, SOCKET_SYSCALL_NAMES)
from ptrace.func_call import FunctionCallOptions
from sys import stderr
from optparse import OptionParser
from logging import getLogger, error
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.tools import signal_to_exitcode
import logging
import os
import functools
from typing import Optional, Dict
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@functools.cache
def apt_install(package):
    subprocess.run(["sudo", "apt", "-y", "install", package], stderr=subprocess.DEVNULL)
    return True

def apt_isinstalled(package):
    return 'installed' in subprocess.run(["apt", "-qq", "list", package], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE).stdout.decode("utf8")

@functools.cache
def file_to_packages(filename: str, arch: str = "amd64") -> str:
    if arch not in ("amd64", "i386"):
        raise ValueError("Only amd64 and i386 supported")
    logger.debug(f'Running [{" ".join(["apt-file", "search", "-F", filename])}]')
    contents = subprocess.run(["apt-file", "search", "-F", filename],
                              stdout=subprocess.PIPE).stdout.decode("utf8")
    db: Dict[str, str] = {}
    selected = None
    for line in contents.split("\n"):
        if not line:
            continue
        package_i, filename_i = line.split(": ")
        db[filename_i] = package_i
    return frozenset(db.values())


def cached_file_to_packages(filename: str, file_to_package_cache: Optional[Dict[str, tuple[str]]] = None) -> str:
    # file_to_package_cache contains all the files that are provided be previous
    # dependencies. If a file pattern is already sastified by current files
    # use the package already included as a dependency
    if file_to_package_cache is not None:
        if filename in file_to_package_cache:
            return file_to_package_cache[filename]

    packages = file_to_packages(filename)

    # a new package is chosen add all the files it provides to our cache
    # uses `apt-file` command line tool
    if file_to_package_cache is not None:
        for package in packages:
            contents = subprocess.run(["apt-file", "list", package],
                                      stdout=subprocess.PIPE).stdout.decode("utf8")
            for line in contents.split("\n"):
                if ":" not in line:
                    break
                package_i, filename_i = line.split(": ")
                file_to_package_cache[filename_i] = file_to_package_cache.get(filename_i, ()) + (package_i,)

    return packages


class SyscallTracer(Application):

    def __init__(self):
        Application.__init__(self)
        # Parse self.options
        self.parseOptions()
        # Setup output (log)
        self.setupLog()
        self.cache={}

    def setupLog(self):
        self._output = None
        self._setupLog(stderr)

    def parseOptions(self):
        parser = OptionParser(
            usage="%prog [options] -- program [arg1 arg2 ...]")
        self.createCommonOptions(parser)
        self.createLogOptions(parser)
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
                event.display()
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

    def syscall(self, process):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall:
            if syscall.result is None:
                for argument in syscall.arguments:
                    if argument.name not in FILENAME_ARGUMENTS:
                        continue
                    try:
                        data, truncated = argument.function.process.readCString(
                            argument.value, 1024)
                    except:
                        data = ""
                    filename = os.path.abspath(os.fsdecode(data))
                    if not filename.startswith("/home") and \
                        not filename.startswith("/usr/local") and \
                        not filename.startswith("/tmp") and \
                        filename.startswith("/") and \
                        not os.path.exists(filename):
                        packages = file_to_packages(filename)
                        #packages = () #cached_file_to_packages(filename, self.cache)
                        packages = [pkg for pkg in packages if pkg not in done_packages]
                        if packages:
                            Shell(filename=filename, packages=packages).cmdloop()

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

    def main(self):
        sys.exit(self._main())

    def _main(self):
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
            writeError(getLogger(), err, "Debugger error")
            exitcode = 1
        self.debugger.quit()
        return exitcode

    def createChild(self, program):
        return Application.createChild(self, program)

import cmd, sys

done_packages = set()
class Shell(cmd.Cmd):
    prompt = '(apt-trace) '
    file = None

    def __init__(self, *args, filename=None, packages=(), **kwargs):
        if filename is None:
            raise ValueError("Shell needs a filename")
        self.filename = filename
        self.packages = packages
        self.intro = f'Found {len(self.packages)} packages for filename {self.filename}. What do I do?\n'\
                     f'Type help or ? to list commands.\n'
        if len(self.packages) < 20:
            self.do_list()

        super().__init__(*args, **kwargs)

    def do_list(self, arg=None):
        'List all potentials'
        for i, package in enumerate(self.packages):
            print (f"{i:3d}: {package}")

    def do_filename(self, arg):
        'List current filename'
        print (self.filename)

    def do_install(self, arg):
        'Install a package: INSTALL gdb #(or the package number in the list)'
        try:
            arg = self.packages[int(arg.strip())]
        except:
            pass
        apt_install(arg)
        #remove recently installed package from potential list
        self.packages = [pkg for pkg in packages if pkg != arg.strip()]
        return not self.packages #if not more packages continue

    def do_isinstalled(self, arg):
        'Check if a package is installed: ISINSTALLED gdb'
        print (apt_isinstalled(arg) and "YES" or "NO" )

    def do_continue(self, arg):
        'Continue Execution of inferior'
        global done_packages
        done_packages = done_packages.union(self.packages)
        return True

    def _complete_with_potentials(self, text, line, begidx, endidx):
        return tuple((pkg for pkg in self.packages if pkg.strip().startswith(text)))

    complete_isinstalled = _complete_with_potentials
    complete_install = _complete_with_potentials

    def default(self, line):
        if line == "EOF" or len(line) == 0:
            return True
        self.stdout.write('[-] Unknown command: %r\n' % (line,))

main = SyscallTracer().main