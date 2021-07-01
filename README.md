![](https://gist.githubusercontent.com/feliam/f837ff5af70b4786eb39bda2b829eacd/raw/7f3a3af57e0040e574673742d41938661a8cb88e/jdi.svg?sanitize=1)

# APT-trace
`apt-trace` let you install dependencies of an arbitrary binary on the fly. 

## Quickstart 🚀

```commandline
$ python setup.py install
```

### Running it 🏃
You simply point it to a repository:
```console
$ apt-trace $yourbinary
```

### apt-trace depends on.. 🎭
python-ptrace

## Development 👷
```commandline
$ git clone https://github.com/trailofbits/apt-trace
$ cd apt-trace
$ python3 -m venv venv  # Optional virtualenv
$ ./venv/bin/activate   # Optional virtualenv
$ python setup.py develop
```
