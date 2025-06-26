# Deptective
[![PyPI version](https://badge.fury.io/py/deptective.svg)](https://badge.fury.io/py/deptective)
[![Tests](https://github.com/trailofbits/deptective/workflows/tests/badge.svg)](https://github.com/trailofbits/deptective/actions)
[![Slack Status](https://slack.empirehacking.nyc/badge.svg)](https://slack.empirehacking.nyc)

**What?** Deptective automatically determines the native dependencies required to run any arbitrary program or command.

**How?** Deptective runs the command, observing which nonexistent files it attempts to open. If the command fails,
Deptective attempts to install the dependencies that provide the nonexistent files, and runs the command again.
If installing a dependency does not change the observable behavior of the command, then Deptective backtracks and tries 
a different dependency. This process continues until either the command succeeds or there are no more dependencies that 
could provide a missing file.

## Quickstart 🚀
```commandline
$ pip3 install deptective
```

### Running it 🏃
You simply point `deptective` to any executable, script, or shell command:
```console
$ deptective cat /usr/bin/transmission-gtk
[10:10:44] INFO     Copying source files to the container...                      dependencies.py:546
           INFO     Updating apt sources...                                       dependencies.py:553
[10:10:58] INFO     Installing coreutils into de790cc40abe...                     dependencies.py:575
[10:11:10] INFO     Installing transmission-gtk into 0b26c0931f9f...              dependencies.py:575
🔎 cat                       ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━              0%   -:--:--   0/2
1 💾 transmission-gtk        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                             0/?
[10:12:11] INFO     Satisfying dependencies: 💾 transmission-gtk                           cli.py:304
                    Install with: apt-get install transmission-gtk
```

Say you download some source code that you need to build with GNU autotools. Simply run
```console
$ deptective ./configure
```
and Deptective will automatically determine all of the requirements necessary to build the code!

If you know the specific file you are missing and you want to see all of the packages that provide that file, you
can use the `-s` option:
```console
$ deptective -s /usr/bin/transmission-gtk
[10:13:02] INFO     Packages providing /usr/bin/transmission-gtk: transmission-gtk         cli.py:276
```

By default, Deptective returns the first satisfying set of dependencies it discovers. This is not guaranteed to be the 
smallest satisfying set of dependencies (*i.e.*, it may include unnecessary dependencies). Deptective can enumerate an 
arbitrary number of results with the `-n` argument.

### Prerequisites 🧩

Depective uses Docker to snapshot installation state, avoid polluting the host system with unnecessary dependencies, and
investigate dependencies across different distributions.

If running from Linux, Deptective defaults to checking for dependencies on the host's distribution, architecture, and 
package manager, if possible. If running from a different operating system, Deptective defaults to searching for 
dependencies on the latest version of Ubuntu using `apt`. Package managers, operating systems, releases, and 
architectures can be specified through command line arguments (see `deptective --help`). 

A list of all supported operating systems, releases, and architectures can be enumerated with the `deptective --list` 
command.

## Caveats and Troubleshooting ⚠️

### Log Directory for Debugging 📊
Deptective can save logs and runtime artifacts to a specified directory using the `--log-dir` option. This is especially useful for debugging failed dependency resolution attempts, as it will preserve information about partial results and command outputs.

```console
$ deptective --log-dir ./debug-logs ./configure
```

If the log directory already exists, you can use the `--force` option to overwrite it:

```console
$ deptective --log-dir ./debug-logs --force ./configure
```

If no log directory is specified, Deptective will create a temporary directory and report its location when errors occur.

### Host System Paths 📂
As mentioned above, Deptective does its analysis within Docker containers. Deptective will automatically copy 
its current working directory on the host system into `/workdir/` inside the container.
This means that if the command being inspected references files with absolute paths and/or files that are not in the 
directory subtree rooted at `$PWD`, the command will likely fail. There are plans to address this in a later version of 
Deptective.

### Package Index Cache 📇
Deptective builds a package index cache mapping file paths to packages that provide them the first time it is run.
However, package databases like `apt` are constantly changing, with vulnerable packages being yanked and new packages 
added. You can force a rebuild of the package index cache by running `deptective --rebuild`.

### Path Testing Latency ⏳
Deptective uses the Docker API to test the existence of files accessed by the target command. On certain Docker 
configurations—particularly when macOS is the host OS—, this can be very slow. A different, faster mechanism for testing
files will be added in a future release.

## Contact 💬

If you'd like to file a bug report or feature request, please use our
[issues](https://github.com/trailofbits/deptective/issues) page.
Feel free to contact us or reach out in
[Empire Hacking](https://slack.empirehacking.nyc/) for help using or extending Deptective.

## License 📝

This utility was developed by [Trail of Bits](https://www.trailofbits.com/).
It is licensed under the [GNU Lesser General Public License v3.0](LICENSE).
[Contact us](mailto:opensource@trailofbits.com) if you're looking for an
exception to the terms.

© 2025, Trail of Bits.
