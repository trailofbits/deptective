import unittest

from apt_trace.apt import file_to_packages


class PackageMapping(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(file_to_packages("/usr/bin/gcc"), ("gcc",))
