import functools
import glob
import logging
import lz4.frame
import os
from pathlib import Path
import atexit
import shutil
import subprocess
from typing import Dict, List, Set, Union, Tuple
from appdirs import AppDirs


logger = logging.getLogger(__name__)
APP_DIRS = AppDirs("apt-trace", "Trail of Bits")
CACHE_DIR = Path(APP_DIRS.user_cache_dir)
if not CACHE_DIR.exists():
    CACHE_DIR.mkdir(parents=True)

is_root = os.getuid() == 0
def run_as_root(command: List[str]) -> subprocess.CompletedProcess:
    if not is_root:
        if shutil.which("sudo") is None:
            raise ValueError("this command must either be run as root or `sudo` must be installed and in the PATH")
        sudo_prefix = ["sudo"]
    else:
        sudo_prefix = []
    return subprocess.run(sudo_prefix + command, stderr=subprocess.DEVNULL)


@functools.lru_cache
def apt_install(package):
    return run_as_root(["apt", "-y", "install", package]).returncode == 0


def apt_isinstalled(package):
    return 'installed' in subprocess.run(
        ["apt", "-qq", "list", package], stderr=subprocess.DEVNULL, stdout=subprocess.PIPE
    ).stdout.decode("utf8")


import sqlite3
PACKAGES_DB = CACHE_DIR / "packages.sqlite"
db_connection = None

@functools.lru_cache(maxsize=128)
def file_to_packages(filename: Union[str, bytes, Path], arch: str = "amd64") -> Tuple[str, ...]:
    """
    Downloads and uses apt-file database directly
    # http://security.ubuntu.com/ubuntu/dists/focal-security/Contents-amd64.gz
    # http://security.ubuntu.com/ubuntu/dists/focal-security/Contents-i386.gz
    """
    if arch not in ("amd64", "i386"):
        raise ValueError("Only amd64 and i386 supported")
    logger.debug(f"searching for packages associated with {filename!r}")
    # ensure that the filename is a byte string:
    try:
        if isinstance(filename, str):
            filename = filename.encode("utf-8")
        elif isinstance(filename, Path):
            filename = str(filename).encode("utf-8")
    except UnicodeEncodeError:
        logger.warning(f"File {filename!r} cannot be encoded in UTF-8; skipping")
        return ()

    global db_connection
    if db_connection is None:
        # low level simple sqlite usage follows
        db_connection = sqlite3.connect(PACKAGES_DB)
        if db_connection is None:
            logger.info(f"Failed to connect to sqlite file {PACKAGES_DB}")
            return ()

        #register to close the singleton connection at exit
        atexit.register(lambda: db_connection.close()) # type: ignore

        # walk the apt sources files just once every apt-trace run
        # fixme remove and/or explain the CASTs
        cur = db_connection.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS contents (filename TEXT, package TEXT)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS loaded (dbfile TEXT)''')
        for dbfile in glob.glob(f'/var/lib/apt/lists/*Contents-{arch}.lz4'):
            cur = db_connection.cursor()
            cur.execute("SELECT 1 FROM loaded WHERE dbfile=CAST(? as TEXT) limit 1", (dbfile,))
            if cur.fetchone() is not None:
                continue
            logger.info(f"Rebuilding contents db {dbfile}")
            # FIXME bytes/string/TEXT/BLOB/encoding mini nightmare
            with lz4.frame.open(dbfile, mode='r') as contents:
                for line in contents.readlines():
                    size = len(line.split()[-1])
                    packages_i_lst = line[-size-1:]
                    filename_i = b'/'+line[:-size-1].strip()
                    packages_i = (pkg.split(b"/")[-1].decode("utf-8").strip() for pkg in packages_i_lst.split(b","))
                    for package_j in packages_i:
                        db_connection.cursor().execute("INSERT INTO contents VALUES (CAST(? as TEXT), CAST(? AS TEXT))", (filename_i, package_j))
            db_connection.cursor().execute("INSERT INTO loaded VALUES (CAST(? AS TEXT))", (dbfile,))

        #loaded apt sources are counted only the first time
        cur = db_connection.cursor()
        cur.execute("SELECT count() FROM loaded")
        if not cur.fetchone():
            logger.info("You need the contents file here: /var/lib/apt/lists/*Contents*.lz4. Try installing apt-file and doing apt update.")

        #single commit for all the updates
        db_connection.commit()

    cur = db_connection.cursor()
    cur.execute("SELECT DISTINCT(package) FROM contents WHERE filename like '%' || CAST(? AS TEXT)", (filename,))

    result = tuple(cur.fetchall())
    logger.info(f"File {filename!r} is associated with packages {result!r}")
    return result
