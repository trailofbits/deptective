from subprocess import CalledProcessError, check_call, DEVNULL
from unittest import TestCase

from deptective.containers import Container


class ContainerTests(TestCase):
    def test_run(self):
        # the following Container command doesn't download the ubuntu image if it's missing,
        # so we need to do that manually:
        try:
            check_call(["docker", "run", "--entrypoint", "id", "--rm", "ubuntu:22.10"], stdout=DEVNULL,
                       stderr=DEVNULL)
        except CalledProcessError:
            self.skipTest("Requires docker")
        with Container(parent="ubuntu:22.10") as container:
            self.assertTrue(
                any(
                    b"base64" in line
                    for line in container.run(["-la", "/usr/bin"], entrypoint="/bin/ls")
                    .logs()
                    .split(b"\n")
                )
            )
