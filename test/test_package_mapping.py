import unittest

from apt_trace.apt import Apt
from apt_trace.cache import SQLCache
from apt_trace.package_manager import PackagingConfig


class PackageMapping(unittest.TestCase):
    def test_mapping(self):
        cache = SQLCache.from_disk(
            Apt(PackagingConfig(os="ubuntu", os_version="noble", arch="amd64"))
        )
        self.assertEqual({"gcc", "pentium-builder"}, cache["/usr/bin/gcc"])
