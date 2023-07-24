![](https://gist.githubusercontent.com/feliam/f837ff5af70b4786eb39bda2b829eacd/raw/7f3a3af57e0040e574673742d41938661a8cb88e/jdi.svg?sanitize=1)

# APT-trace
`apt-trace` will install dependencies of an arbitrary program on the fly. 
`apt-trace` catches every file access before it can even fail and prints a list packages that provide that file. 
`apt-trace` builds its own database to match filenames with packages using the system provided apt sources; the more sources there are configured bigger the universe of packages.

## Quickstart 🚀
```commandline
$ python setup.py install
```

### Running it 🏃
You simply point `apt-trace` it to your executable/binary/script:
```console
$ apt-trace  cat /usr/bin/transmission-gtk
Found 1 packages providing /usr/bin/transmission-gtk. What do I do?
Type help or ? to list commands.
Packages:
    0: transmission-gtk
(apt-trace) continue
/usr/bin/cat: /usr/bin/transmission-gtk: No such file or directory
Dependencies:
  ubuntu:locales
  ubuntu:transmission-gtk
  ubuntu:libc6
```

### apt-trace depends on.. 🎭
Some python packages: python-ptrace, appdirs, lz4 
Some ubuntu packages: sudo

```commandline
$ apt install python3
$ apt install python3-setuptools
$ apt install sudo
$ apt update
```

## Development 👷
```commandline
$ git clone https://github.com/trailofbits/apt-trace
$ cd apt-trace
$ python3 -m venv venv  # Optional virtualenv
$ ./venv/bin/activate   # Optional virtualenv
$ python setup.py develop
```
