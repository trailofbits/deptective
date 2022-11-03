import unittest

from apt_trace.apt import file_to_packages


class PackageMapping(unittest.TestCase):
    def test_mapping(self):
        print(file_to_packages("/testing"))
