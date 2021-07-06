![](https://gist.githubusercontent.com/feliam/f837ff5af70b4786eb39bda2b829eacd/raw/7f3a3af57e0040e574673742d41938661a8cb88e/jdi.svg?sanitize=1)

# APT-trace
`apt-trace` let you install dependencies of an arbitrary binary on the fly. 

## Quickstart 🚀
```commandline
$ python setup.py install
```

### Running it 🏃
You simply point it to your executable:
```console
$ apt-trace $yourexe
```

### apt-trace depends on.. 🎭
A python package: python-ptrace and a some ubuntu packages: sudo, apt-file
```commandline
$ apt install python3
$ apt install python3-setuptools
$ apt install apt-file
$ apt install sudo
$ apt-file update
```

## Development 👷
```commandline
$ git clone https://github.com/trailofbits/apt-trace
$ cd apt-trace
$ python3 -m venv venv  # Optional virtualenv
$ ./venv/bin/activate   # Optional virtualenv
$ python setup.py develop
```
