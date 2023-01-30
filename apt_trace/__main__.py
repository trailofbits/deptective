import cmd
import logging

from .apt import apt_install, apt_isinstalled
from .dependencies import SBOMGenerator


logger = logging.getLogger(__name__)

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
        self.packages = [pkg for pkg in self.packages if pkg != arg.strip()]
        return not self.packages #if not more packages continue

    def do_isinstalled(self, arg):
        'Check if a package is installed: ISINSTALLED gdb'
        print(apt_isinstalled(arg) and "YES" or "NO")

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


def main():
    exit(SBOMGenerator().main())


if __name__ == "__main__":
    main()
