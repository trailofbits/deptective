from unittest import TestCase

import docker

from apt_trace.containers import Container


class ContainerTests(TestCase):
    def test_run(self):
        with Container(parent="ubuntu:22.10") as container:
            self.assertTrue(
                any(
                    b"base64" in line
                    for line in container.run(["-la", "/usr/bin"], entrypoint="/bin/ls")
                )
            )
